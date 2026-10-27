import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_phase_11_rag_knowledge_base():
    print("--- STARTING PHASE 11 RAG KNOWLEDGE BASE VERIFICATION ---")

    # 1. Login user
    email = "phase11_tester@example.com"
    password = "SafePassword99!"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_res = client.post("/api/v1/auth/login", data={"username": email, "password": password})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Submit scam text specifically targeting Credential Phishing & Brand Spoofing
    phishing_msg = (
        "URGENT: PayPal account alert! Your profile will be blocked immediately due to unauthorized login. "
        "Enter your password and OTP token at http://paypal-auth-verify.xyz/login within 24 hours."
    )
    res = client.post("/api/v1/analyses/text", json={"text": phishing_msg}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    analysis_id = data["analysis_id"]
    guidance = data.get("defensive_guidance", [])
    print(f"Analysis #{analysis_id} -> Embedded Guidance Articles Count: {len(guidance)}")
    
    assert len(guidance) >= 1
    doc_ids = [g["doc_id"] for g in guidance]
    print(f"Retrieved Document IDs in Analysis: {doc_ids}")
    assert any(d in ["KB-CRED-001", "KB-BRAND-002"] for d in doc_ids)
    
    first_item = guidance[0]
    print(f"Top Matched Title: {first_item['title']} (Score: {first_item['relevance_score']})")
    assert "recommended_mitigation" in first_item
    assert len(first_item["recommended_mitigation"]) > 20
    print("Embedded RAG defensive guidance OK.")

    # 3. Query RAG Guidance Endpoint GET /analyses/{id}/guidance
    guidance_res = client.get(f"/api/v1/analyses/{analysis_id}/guidance", headers=headers)
    assert guidance_res.status_code == 200, f"Guidance query failed: {guidance_res.text}"
    items = guidance_res.json()
    print(f"Queried Guidance Articles via API: {len(items)}")
    assert len(items) >= 1
    assert items[0]["doc_id"] in ["KB-CRED-001", "KB-BRAND-002"]
    print("RAG API Endpoint verification OK.")

    # 4. Verify Delivery Smishing RAG Retrieval
    delivery_msg = "USPS: Package delivery failed due to unpaid customs fee of $1.95. Update details at http://usps-reschedule-fee.top"
    res_del = client.post("/api/v1/analyses/text", json={"text": delivery_msg}, headers=headers)
    assert res_del.status_code == 200
    del_guidance = res_del.json().get("defensive_guidance", [])
    del_doc_ids = [g["doc_id"] for g in del_guidance]
    print(f"Delivery Scam Retrieved Documents: {del_doc_ids}")
    assert "KB-DELV-004" in del_doc_ids
    print("Accurate RAG taxonomic classification and guidance retrieval OK.")

    print("--- ALL PHASE 11 TESTS PASSED SUCCESSFULLY ---")

if __name__ == "__main__":
    test_phase_11_rag_knowledge_base()
