import os
import sys

# Ensure backend directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_phase_4_pipeline():
    print("--- STARTING PHASE 4 VERIFICATION ---")

    # 1. Register & login a test user
    email = "phase4_tester@example.com"
    password = "SafePassword99!"
    reg_res = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    if reg_res.status_code == 400:
        # User already registered
        pass
    else:
        assert reg_res.status_code == 200, f"Register failed: {reg_res.text}"

    login_res = client.post("/api/v1/auth/login", data={"username": email, "password": password})
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("Authentication established.")

    # 2. Test Legitimate / Benign Text
    safe_text = "Hi Sarah, are we still meeting tomorrow at 2 PM at the coffee shop? Let me know."
    res_safe = client.post("/api/v1/analyses/text", json={"text": safe_text}, headers=headers)
    assert res_safe.status_code == 200, f"Safe text analysis failed: {res_safe.text}"
    data_safe = res_safe.json()
    print(f"Safe text result -> Score: {data_safe['risk_score']}, Level: {data_safe['risk_level']}")
    assert data_safe["risk_score"] == 0
    assert data_safe["risk_level"] == "Safe"
    assert len(data_safe["indicators"]) == 0
    print("Benign text verified (Score 0, Safe).")

    # 3. Test High-Urgency Credential Phishing Text
    phishing_text = (
        "URGENT: Your bank account suspended immediately due to suspicious activity. "
        "Enter your password and share your OTP at http://secure-verify-auth.xyz/login within 12 hours!"
    )
    res_scam = client.post("/api/v1/analyses/text", json={"text": phishing_text}, headers=headers)
    assert res_scam.status_code == 200, f"Scam text analysis failed: {res_scam.text}"
    data_scam = res_scam.json()
    print(f"Scam text result -> Score: {data_scam['risk_score']}, Level: {data_scam['risk_level']}")
    assert data_scam["risk_score"] >= 70, f"Expected high score, got {data_scam['risk_score']}"
    assert data_scam["risk_level"] in ["High", "Critical"]
    assert len(data_scam["indicators"]) >= 3
    assert len(data_scam["extraction"]["extracted_urls"]) == 1
    assert "http://secure-verify-auth.xyz/login" in data_scam["extraction"]["extracted_urls"]
    print(f"Phishing detection verified with {len(data_scam['indicators'])} indicators.")

    # 4. Test Adversarial Obfuscation (Zero-Width Space & Homoglyph)
    # Using Cyrillic 'а' in 'account' and zero-width spaces in 'suspended'
    obfuscated_text = "Final notice: Your \u200Bаccount\u200B is suspended! Act now within 24 hours."
    res_obf = client.post("/api/v1/analyses/text", json={"text": obfuscated_text}, headers=headers)
    assert res_obf.status_code == 200
    data_obf = res_obf.json()
    types = [i["indicator_type"] for i in data_obf["indicators"]]
    print(f"Obfuscated text result -> Score: {data_obf['risk_score']}, Indicators: {types}")
    assert "Adversarial Text Obfuscation" in types
    print("Adversarial normalization and detection verified.")

    # 5. Test Retrieval by ID
    analysis_id = data_scam["analysis_id"]
    get_res = client.get(f"/api/v1/analyses/{analysis_id}", headers=headers)
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert get_data["analysis_id"] == analysis_id
    assert get_data["risk_score"] == data_scam["risk_score"]
    print("Database persistence and retrieval by ID verified.")

    # 6. Test Tenant Isolation (Unauthenticated or other user)
    unauth_res = client.get(f"/api/v1/analyses/{analysis_id}")
    assert unauth_res.status_code == 401
    print("Tenant security verified on analysis endpoints.")

    print("--- ALL PHASE 4 TESTS PASSED SUCCESSFULLY ---")

if __name__ == "__main__":
    test_phase_4_pipeline()
