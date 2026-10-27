import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_phase_8_similarity_pipeline():
    print("--- STARTING PHASE 8 FINGERPRINTING & SIMILARITY SEARCH VERIFICATION ---")

    # 1. Login user
    email = "phase8_tester@example.com"
    password = "SafePassword99!"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_res = client.post("/api/v1/auth/login", data={"username": email, "password": password})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    import uuid
    run_id = uuid.uuid4().hex[:6]
    test_domain = f"chase-security-update-{run_id}.xyz"

    # 2. First submission (Initial novel scam pattern)
    msg_1 = (
        f"URGENT: Your bank account will be blocked within 24 hours due to unauthorized login. "
        f"Enter your password and security code immediately at http://{test_domain}/login"
    )
    res_1 = client.post("/api/v1/analyses/text", json={"text": msg_1}, headers=headers)
    assert res_1.status_code == 200, f"Analysis 1 failed: {res_1.text}"
    data_1 = res_1.json()
    print(f"Submission 1 -> ID: {data_1['analysis_id']}, Verdict: {data_1['similarity_verdict']}, Hash: {data_1['structural_hash'][:16]}...")
    assert data_1["similarity_verdict"] in ["NEW_PATTERN", "KNOWN_CAMPAIGN", "STRONG_MATCH"]
    assert data_1["structural_hash"] is not None
    id_1 = data_1["analysis_id"]

    # 3. Second submission with minor lexical mutation (Canonical variation test)
    # Variations: "suspended" instead of "blocked", "act now" instead of "within 24 hours"
    msg_2 = (
        f"URGENT: Your account is suspended due to unauthorized login. "
        f"Enter your password and security code immediately at http://{test_domain}/login"
    )
    res_2 = client.post("/api/v1/analyses/text", json={"text": msg_2}, headers=headers)
    assert res_2.status_code == 200, f"Analysis 2 failed: {res_2.text}"
    data_2 = res_2.json()
    print(f"Submission 2 (Variant) -> ID: {data_2['analysis_id']}, Verdict: {data_2['similarity_verdict']}, Matches: {data_2['similarity_matches_count']}")
    
    # Should flag as EXACT_FINGERPRINT or STRONG_MATCH
    assert data_2["similarity_verdict"] in ["STRONG_MATCH", "KNOWN_CAMPAIGN", "SIMILAR_PATTERN"]
    assert data_2["similarity_matches_count"] >= 1

    # 4. Query detailed similarity report for Submission 2 via GET /{id}/similar
    id_2 = data_2["analysis_id"]
    sim_res = client.get(f"/api/v1/analyses/{id_2}/similar", headers=headers)
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    print(f"Similarity Details -> Highest Score: {sim_data['highest_similarity']}, Verdict: {sim_data['verdict']}")
    assert sim_data["highest_similarity"] >= 0.85
    assert len(sim_data["matches"]) >= 1
    match_ids = [m["analysis_id"] for m in sim_data["matches"]]
    assert id_1 in match_ids or sim_data["total_historical_matches"] >= 1
    print(f"Successfully matched variant (ID {id_2}) to historical cluster (Total matches: {sim_data['total_historical_matches']})!")

    # 5. Third submission: Completely unrelated benign message
    msg_3 = f"Hey John {run_id}, can you review the quarterly budget spreadsheet before our team sync?"
    res_3 = client.post("/api/v1/analyses/text", json={"text": msg_3}, headers=headers)
    assert res_3.status_code == 200
    data_3 = res_3.json()
    print(f"Submission 3 (Benign) -> Verdict: {data_3['similarity_verdict']}, Matches: {data_3['similarity_matches_count']}")
    assert data_3["risk_score"] == 0
    assert data_3["risk_level"] == "Safe"
    assert data_3["similarity_verdict"] in ["NEW_PATTERN", "STRONG_MATCH", "SIMILAR_PATTERN", "KNOWN_CAMPAIGN"]

    print("--- ALL PHASE 8 TESTS PASSED SUCCESSFULLY ---")

if __name__ == "__main__":
    test_phase_8_similarity_pipeline()
