import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_phase_10_threat_graph():
    print("--- STARTING PHASE 10 THREAT RELATIONSHIP GRAPH VERIFICATION ---")

    # 1. Login user
    email = "phase10_tester@example.com"
    password = "SafePassword99!"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_res = client.post("/api/v1/auth/login", data={"username": email, "password": password})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Submit high-correlation multi-entity scam message
    scam_msg = (
        "URGENT: PayPal security alert! Your account access is restricted. "
        "Visit http://paypal-verify-auth.xyz/security-checkpoint immediately or call +1-800-555-0199."
    )
    res_scam = client.post("/api/v1/analyses/text", json={"text": scam_msg}, headers=headers)
    assert res_scam.status_code == 200
    data = res_scam.json()
    analysis_id = data["analysis_id"]
    print(f"Submitted Analysis -> ID: {analysis_id}")

    # 3. Retrieve Node-Link Threat Graph for this analysis
    graph_res = client.get(f"/api/v1/analyses/{analysis_id}/graph", headers=headers)
    assert graph_res.status_code == 200, f"Graph retrieval failed: {graph_res.text}"
    graph_data = graph_res.json()
    
    print(f"Graph Data -> Total Nodes: {graph_data['total_nodes']}, Total Edges: {graph_data['total_edges']}")
    assert graph_data["total_nodes"] >= 4
    assert graph_data["total_edges"] >= 3

    node_types = set(n["type"] for n in graph_data["nodes"])
    node_labels = [n["label"] for n in graph_data["nodes"]]
    print(f"Node Types Present: {node_types}")
    print(f"Node Labels: {node_labels}")

    # Check key threat entities extracted into graph
    assert "ANALYSIS" in node_types
    assert "BRAND" in node_types
    assert "URL" in node_types
    assert "DOMAIN" in node_types
    assert any("PayPal" in l for l in node_labels)
    assert any("paypal-verify-auth.xyz" in l for l in node_labels)

    edge_labels = [e["label"] for e in graph_data["edges"]]
    print(f"Edge Relationship Types: {edge_labels}")
    assert "CLAIMS_BRAND_IDENTITY" in edge_labels
    assert "CONTAINS_URL" in edge_labels
    assert "HOSTED_ON_DOMAIN" in edge_labels
    print("Graph node and edge relational connectivity OK.")

    # 4. Check Global Threat Network Aggregation
    network_res = client.get("/api/v1/analyses/graph/network", headers=headers)
    assert network_res.status_code == 200
    network_data = network_res.json()
    print(f"Global Threat Network -> Nodes: {network_data['total_nodes']}, Edges: {network_data['total_edges']}")
    assert network_data["total_nodes"] >= graph_data["total_nodes"]
    assert network_data["total_edges"] >= graph_data["total_edges"]
    print("Global threat network graph aggregation OK.")

    print("--- ALL PHASE 10 TESTS PASSED SUCCESSFULLY ---")

if __name__ == "__main__":
    test_phase_10_threat_graph()
