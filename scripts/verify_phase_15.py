import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_phase_15_production_readiness():
    print("--- STARTING PHASE 15 PRODUCTION OPTIMIZATION VERIFICATION ---")

    # 1. Test Registration and Session Authentication
    email = "phase15_prod_tester@protectpro.sec"
    password = "ProdReadyPassword2026!"
    reg_res = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    if reg_res.status_code != 200:
        assert reg_res.status_code == 400 # Already registered
    
    login_res = client.post("/api/v1/auth/login", data={"username": email, "password": password})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("Auth session & JWT issuance verified.")

    # 2. Test Paginated History Endpoint & Aggregations
    hist_res = client.get("/api/v1/history/?skip=0&limit=5", headers=headers)
    assert hist_res.status_code == 200, f"History fetch failed: {hist_res.text}"
    hist_data = hist_res.json()
    print(f"History Metrics -> Total: {hist_data['total_count']}, High Risk: {hist_data['high_risk_count']}, Safe: {hist_data['safe_count']}, Avg: {hist_data['average_risk']}")
    assert "total_count" in hist_data
    assert "average_risk" in hist_data
    assert "analyses" in hist_data
    assert hist_data["page_size"] == 5
    print("Paginated history & KPI aggregation OK.")

    # 3. Create a New Analysis to Verify End-to-End Pipeline
    text_payload = (
        "URGENT FRAUD ALERT: Your bank account will be closed within 12 hours. "
        "Enter your password and security code immediately at http://secure-portal-auth.xyz/login"
    )
    analysis_res = client.post("/api/v1/analyses/text", json={"text": text_payload}, headers=headers)
    assert analysis_res.status_code == 200
    res_data = analysis_res.json()
    new_id = res_data["analysis_id"]
    print(f"Created Analysis #{new_id} -> Score: {res_data['risk_score']}, Severity: {res_data['risk_level']}")
    assert res_data["risk_score"] >= 55
    assert len(res_data["indicators"]) >= 3
    assert res_data["ai_investigation_report"] is not None
    print("End-to-end analysis creation & AI report verification OK.")

    # 4. Verify Single Analysis Retrieval by ID with Tenant Isolation
    get_res = client.get(f"/api/v1/analyses/{new_id}", headers=headers)
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert get_data["analysis_id"] == new_id
    assert get_data["risk_score"] == res_data["risk_score"]
    print("Single analysis retrieval by ID OK.")

    # 5. Verify Cross-Tenant Access Rejection (Data Isolation)
    # Register a second distinct tenant
    email2 = "tenant2_observer@agency.sec"
    client.post("/api/v1/auth/register", json={"email": email2, "password": password})
    login_res2 = client.post("/api/v1/auth/login", data={"username": email2, "password": password})
    token2 = login_res2.json()["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # Tenant 2 attempts to query Tenant 1's analysis
    cross_res = client.get(f"/api/v1/analyses/{new_id}", headers=headers2)
    assert cross_res.status_code == 404, "Tenant isolation breach: cross-tenant access allowed!"
    print("Cross-tenant access correctly rejected with 404 Not Found.")

    # 6. Verify Unauthenticated Endpoint Rejection
    unauth_res = client.get(f"/api/v1/analyses/{new_id}")
    assert unauth_res.status_code == 401
    print("Unauthenticated access correctly rejected with 401 Unauthorized.")

    # 7. Verify Threat Graph & Defensive Guidance Endpoints
    graph_res = client.get(f"/api/v1/analyses/{new_id}/graph", headers=headers)
    assert graph_res.status_code == 200
    guidance_res = client.get(f"/api/v1/analyses/{new_id}/guidance", headers=headers)
    assert guidance_res.status_code == 200
    print("Threat graph and defensive guidance endpoints verified.")

    # 8. Verify Campaigns and Live Evaluation APIs
    camp_res = client.get("/api/v1/campaigns/", headers=headers)
    assert camp_res.status_code == 200
    eval_res = client.get("/api/v1/evaluation/metrics", headers=headers)
    assert eval_res.status_code == 200
    print("Campaign intelligence and evaluation metric APIs operational.")

    print("--- ALL PHASE 15 PRODUCTION READINESS TESTS PASSED SUCCESSFULLY ---")

if __name__ == "__main__":
    test_phase_15_production_readiness()
