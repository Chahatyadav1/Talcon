import re
import logging
from flask import Flask, request, jsonify
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
v1 = client.CoreV1Api()
net_v1 = client.NetworkingV1Api()

QUARANTINE_PRIORITIES = {"CRITICAL", "EMERGENCY", "ALERT"}  
SYSTEM_NAMESPACES = {"kube-system", "monitoring", "falco", "security"} 
DANGEROUS_RULES = ["T1059.004", "T1003.008"]                


def get_pod_and_namespace(output: str):
    pod = re.search(r"pod=(\S+)", output)
    ns = re.search(r"ns=(\S+)", output)
    pod = pod.group(1) if pod else None
    ns = ns.group(1) if ns else "default"
    return (None if pod == "<NA>" else pod), ns


def quarantine(pod_name: str, namespace: str):
    v1.patch_namespaced_pod(
        pod_name, namespace,
        {"metadata": {"labels": {"security.io/quarantined": "true"}}},
    )
    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "quarantine-deny-all", "namespace": namespace},
        "spec": {
            "podSelector": {"matchLabels": {"security.io/quarantined": "true"}},
            "policyTypes": ["Ingress", "Egress"],
        },
    }


@app.route("/webhook", methods=["POST"])
def webhook():
    alert = request.get_json(force=True, silent=True) or {}
    rule = alert.get("rule", "")
    priority = alert.get("priority", "").upper()
    output = alert.get("output", "")

    if not any(r in rule for r in DANGEROUS_RULES):
        return jsonify({"status": "ignored", "reason": "rule"}), 200

    if priority not in QUARANTINE_PRIORITIES:
        return jsonify({"status": "ignored", "reason": "priority"}), 200

    pod_name, namespace = get_pod_and_namespace(output)
    if not pod_name or namespace in SYSTEM_NAMESPACES:
        return jsonify({"status": "ignored", "reason": "pod_or_namespace"}), 200


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
