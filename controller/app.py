import os
import json
import logging
import datetime
import threading
import re
from flask import Flask, request, jsonify
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

app = Flask(__name__)

try:
    config.load_incluster_config()
    log.info("Loaded in-cluster kubeconfig")
except Exception:
    config.load_kube_config()
    log.info("Loaded local kubeconfig")

v1 = client.CoreV1Api()
net_v1 = client.NetworkingV1Api()

SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")
QUARANTINE_PRIORITIES = {"CRITICAL", "EMERGENCY", "ALERT"}

SYSTEM_NAMESPACES = {
    "kube-system", "cilium-spire",
    "monitoring", "falco", "security"
}

HIGH_CONFIDENCE_RULES = {
    "T1059.004",  # Shell Spawned in Container
    "T1003.008",  # Sensitive File Read
    "T1611",      # Ptrace/Mount Syscall
    "T1036",      # Defense Evasion (Binary from Tmp, Base64 Decode)
    "T1105",      # Download Tool
    "T1095",      # Reverse Shell
    "T1071",      # curl
}

MITRE_MAP = {
    "bash": ("T1059.004", "Execution", "Unix Shell"),
    "/bin/sh": ("T1059.004", "Execution", "Unix Shell"),
    "shell": ("T1059.004", "Execution", "Unix Shell"),
    "shadow": ("T1003.008", "Credential Access", "Shadow File"),
    "passwd": ("T1003.008", "Credential Access", "Passwd File"),
    "ptrace": ("T1611", "Privilege Escalation", "Container Escape"),
    "mount": ("T1611", "Privilege Escalation", "Mount Namespace"),
    "wget": ("T1071", "Command and Control", "Web Protocol"),
    "curl": ("T1071", "Command and Control", "Web Protocol"),
    "nmap": ("T1046", "Discovery", "Network Scan"),
    "netcat": ("T1095", "Command and Control", "Reverse Shell"),
    "reverse": ("T1071", "Command and Control", "Reverse Shell"),
}

def get_mitre(text: str):
    text_l = text.lower()
    for kw, info in MITRE_MAP.items():
        if kw in text_l:
            return info
    return ("T1059", "Execution", "Unknown Technique")

def extract_pod_info(output: str, output_fields: dict):
    """
    Extract pod_name and namespace from either:
    1. Falco text output (format: "pod=%pod_name ns=%namespace")
    2. output_fields JSON (fallback)
    """
    pod_name = None
    namespace = "default"

    if output:
        pod_match = re.search(r'pod=([^\s]+)', output)
        if pod_match:
            pod_name = pod_match.group(1)
            if pod_name == "<NA>":
                pod_name = None
        ns_match = re.search(r'ns=([^\s]+)', output)
        if ns_match and ns_match.group(1) != "<NA>":
            namespace = ns_match.group(1)

    if not pod_name and output_fields:
        pod_name = output_fields.get("k8s.pod.name") or output_fields.get("k8s_pod_name")
        if pod_name == "<NA>":
            pod_name = None
        namespace = output_fields.get("k8s.ns.name") or output_fields.get("k8s_ns_name") or namespace

    return pod_name, namespace

def is_rule_whitelisted(rule: str) -> bool:
    """Check if rule is whitelisted by MITRE ID or partial name."""
    rule_lower = rule.lower()
    for whitelisted_id in HIGH_CONFIDENCE_RULES:
        if whitelisted_id.lower() in rule_lower:
            return True
    return False

def apply_quarantine_network_policy(namespace: str, pod_name: str, pod_labels: dict) -> bool:
    """Apply deny-all NetworkPolicy to the specific pod."""
    policy_name = f"quarantine-{pod_name}"
    selector = {k: v for k, v in pod_labels.items()
                if not k.startswith("security.io")}
    
    body = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": policy_name,
            "namespace": namespace,
            "labels": {"security.io/quarantined": "true",
                      "security.io/target-pod": pod_name}
        },
        "spec": {
            "podSelector": {"matchLabels": selector},
            "policyTypes": ["Ingress", "Egress"]
        }
    }
    try:
        net_v1.create_namespaced_network_policy(namespace, body)
        log.info(f"✓ Quarantine policy applied: {pod_name}/{namespace}")
        return True
    except ApiException as e:
        if e.status == 409:
            log.info(f"Pod {pod_name} already quarantined")
            return True
        log.error(f"Failed to apply quarantine policy: {e}")
        return False

def annotate_quarantined_pod(namespace: str, pod_name: str, reason: str, mitre_id: str, mitre_name: str):
    """Label and annotate the pod."""
    now = datetime.datetime.utcnow().isoformat() + "Z"
    patch = {
        "metadata": {
            "labels": {"security.io/quarantined": "true"},
            "annotations": {
                "security.io/quarantine-reason": reason[:500],
                "security.io/quarantine-timestamp": now,
                "security.io/mitre-technique-id": mitre_id,
                "security.io/mitre-technique-name": mitre_name,
                "security.io/remediation": "Investigate pod logs. Delete if confirmed malicious."
            }
        }
    }
    try:
        v1.patch_namespaced_pod(pod_name, namespace, patch)
        log.info(f"Pod annotated: {pod_name}/{namespace}")
    except ApiException as e:
        log.error(f"Failed to annotate pod: {e}")

def create_audit_event(namespace: str, pod_name: str, reason: str, mitre_id: str):
    """Create a Kubernetes Event for audit trail."""
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    name = f"security-incident-{pod_name}-{int(datetime.datetime.utcnow().timestamp())}"
    body = {
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": {"name": name, "namespace": namespace},
        "involvedObject": {"kind": "Pod", "name": pod_name, "namespace": namespace},
        "reason": "SecurityIncident",
        "message": f"[{mitre_id}] Pod quarantined — {reason[:200]}",
        "type": "Warning",
        "firstTimestamp": now,
        "lastTimestamp": now,
        "count": 1,
        "source": {"component": "security-ir-controller"},
        "action": "Quarantine",
        "reportingComponent": "security-ir-controller"
    }
    try:
        v1.create_namespaced_event(namespace, body)
        log.info(f"Audit event created for {pod_name}/{namespace}")
    except ApiException as e:
        log.error(f"Failed to create audit event: {e}")

def send_slack_alert(pod_name: str, namespace: str, rule: str, mitre_id: str, mitre_tactic: str, mitre_name: str, node_name: str):
    """Send Slack notification."""
    if not SLACK_WEBHOOK:
        return
    payload = {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "🚨 Security Incident — Pod Auto-Quarantined"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Pod*\n`{pod_name}`"},
                {"type": "mrkdwn", "text": f"*Namespace*\n`{namespace}`"},
                {"type": "mrkdwn", "text": f"*Node*\n`{node_name}`"},
                {"type": "mrkdwn", "text": f"*MITRE*\n`{mitre_id}` — {mitre_name}"},
                {"type": "mrkdwn", "text": f"*Tactic*\n{mitre_tactic}"},
                {"type": "mrkdwn", "text": f"*Rule*\n{rule}"},
            ]},
        ]
    }
    try:
        requests.post(SLACK_WEBHOOK, json=payload, timeout=5)
        log.info(f"Slack alert sent")
    except Exception as e:
        log.error(f"Slack notification failed: {e}")

@app.route("/webhook", methods=["POST"])
def falco_webhook():
    """Receives Falco alerts from falco-sidekick."""
    data = request.get_json(force=True, silent=True) or {}
    priority = data.get("priority", "").upper()
    rule = data.get("rule", "unknown rule")
    output = data.get("output", "")
    output_fields = data.get("output_fields", {})

    log.info(f"Alert received: [{priority}] {rule}")

    if not is_rule_whitelisted(rule):
        log.info(f"Rule NOT whitelisted ({rule}) — skipping quarantine")
        return jsonify({"status": "ignored", "reason": "rule_not_whitelisted"}), 200

    if priority not in QUARANTINE_PRIORITIES:
        log.info(f"Priority {priority} below threshold — skipping")
        return jsonify({"status": "ignored", "priority": priority}), 200

    pod_name, namespace = extract_pod_info(output, output_fields)

    if not pod_name:
        log.warning(f"No pod name in alert — skipping")
        return jsonify({"status": "no_pod"}), 200

    if namespace in SYSTEM_NAMESPACES:
        log.info(f"System namespace {namespace} — skipping")
        return jsonify({"status": "system_ns_skipped"}), 200

    mitre_id, mitre_tactic, mitre_name = get_mitre(output + " " + rule)

    try:
        pod = v1.read_namespaced_pod(pod_name, namespace)
        pod_labels = pod.metadata.labels or {}
        node_name = pod.spec.node_name or "unknown"
    except ApiException as e:
        log.error(f"Pod not found {pod_name}/{namespace}: {e}")
        return jsonify({"status": "pod_not_found"}), 200

    log.warning(f"QUARANTINING: {pod_name}/{namespace} — Rule: {rule} [{mitre_id}]")

    threads = [
        threading.Thread(target=apply_quarantine_network_policy, args=(namespace, pod_name, pod_labels)),
        threading.Thread(target=annotate_quarantined_pod, args=(namespace, pod_name, output, mitre_id, mitre_name)),
        threading.Thread(target=create_audit_event, args=(namespace, pod_name, output, mitre_id)),
        threading.Thread(target=send_slack_alert, args=(pod_name, namespace, rule, mitre_id, mitre_tactic, mitre_name, node_name)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    log.info(f"Incident response complete for {pod_name}/{namespace}")
    return jsonify({"status": "quarantined", "pod": pod_name, "namespace": namespace, "mitre": mitre_id}), 200

@app.route("/api/incidents")
def list_incidents():
    """List all currently quarantined pods."""
    pods = v1.list_pod_for_all_namespaces(label_selector="security.io/quarantined=true")
    incidents = [
        {
            "pod": p.metadata.name,
            "namespace": p.metadata.namespace,
            "reason": (p.metadata.annotations or {}).get("security.io/quarantine-reason", "")[:120],
            "timestamp": (p.metadata.annotations or {}).get("security.io/quarantine-timestamp", ""),
            "mitre": (p.metadata.annotations or {}).get("security.io/mitre-technique-id", ""),
        }
        for p in pods.items
    ]
    return jsonify({"total": len(incidents), "incidents": incidents}), 200

@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    log.info("Security IR Controller starting on :8080")
    app.run(host="0.0.0.0", port=8080, debug=False)