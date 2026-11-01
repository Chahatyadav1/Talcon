import re
from flask import Flask, request
from kubernetes import client, config

config.load_incluster_config()
v1, net = client.CoreV1Api(), client.NetworkingV1Api()
app = Flask(__name__)

MITRE = {"T1059.004": "Execution", "T1003.008": "Credential Access"}   
SYSTEM = {"kube-system", "monitoring", "falco", "security"}


@app.route("/webhook", methods=["POST"])
def webhook():
    alert = request.get_json(force=True)

    technique = alert["rule"].split()[0]
    if technique not in MITRE:
        return "ignored"

    pod = re.search(r"pod=(\S+)", alert["output"])[1]
    ns = re.search(r"ns=(\S+)", alert["output"])[1]
    if pod == "<NA>" or ns in SYSTEM:
        return "ignored"

    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "quarantine"},
        "spec": {
            "podSelector": {"matchLabels": {"quarantined": "true"}},
            "policyTypes": ["Ingress", "Egress"],
        },
    }
    if "quarantine" not in [p.metadata.name for p in net.list_namespaced_network_policy(ns).items]:
        net.create_namespaced_network_policy(ns, policy)

    v1.patch_namespaced_pod(pod, ns, {"metadata": {
        "labels": {"quarantined": "true"},
        "annotations": {"mitre": f"{technique} {MITRE[technique]}"}}})
    return "quarantined"
