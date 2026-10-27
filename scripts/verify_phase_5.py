import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_phase_5_url_pipeline():
    print("--- STARTING PHASE 5 URL DNA & BRAND IMPERSONATION VERIFICATION ---")

    # 1. Login user
    email = "phase5_tester@example.com"
    password = "SafePassword99!"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_res = client.post("/api/v1/auth/login", data={"username": email, "password": password})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Test Legitimate Domain (PayPal official)
    legit_url = "https://www.paypal.com/signin"
    res_legit = client.post("/api/v1/analyses/url", json={"url": legit_url}, headers=headers)
    assert res_legit.status_code == 200, f"Failed legit URL: {res_legit.text}"
    data_legit = res_legit.json()
    print(f"Legit PayPal URL -> Score: {data_legit['risk_score']}, Level: {data_legit['risk_level']}")
    # Legitimate domains should score very low / safe
    assert data_legit["risk_score"] < 25
    assert data_legit["domain"] == "paypal.com"
    print("Legitimate domain verification OK.")

    # 3. Test Brand Spoofing / Impersonation (paypal-security-login.xyz)
    spoof_url = "http://paypal-security-verification.xyz/login/verify"
    res_spoof = client.post("/api/v1/analyses/url", json={"url": spoof_url}, headers=headers)
    assert res_spoof.status_code == 200
    data_spoof = res_spoof.json()
    print(f"Spoofed URL -> Score: {data_spoof['risk_score']}, Level: {data_spoof['risk_level']}")
    assert data_spoof["risk_score"] >= 70, f"Expected critical/high score, got {data_spoof['risk_score']}"
    indicator_types = [i["indicator_type"] for i in data_spoof["indicators"]]
    print(f"Detected Indicators: {indicator_types}")
    assert "Brand Domain Impersonation (Spoofing)" in indicator_types
    assert "High-Risk Top-Level Domain (TLD)" in indicator_types
    assert "Insecure Protocol (HTTP)" in indicator_types
    print("Brand Impersonation & Risky TLD detection OK.")

    # 4. Test Brand Mismatch with Context (Text claims Apple, link is strange)
    mismatch_url = "https://update-account-verification-service.com/auth"
    context = "Your Apple ID has been locked due to unauthorized logins. Click below to verify."
    res_mismatch = client.post("/api/v1/analyses/url", json={"url": mismatch_url, "context_text": context}, headers=headers)
    assert res_mismatch.status_code == 200
    data_mismatch = res_mismatch.json()
    print(f"Brand Mismatch -> Score: {data_mismatch['risk_score']}, Level: {data_mismatch['risk_level']}")
    mismatch_types = [i["indicator_type"] for i in data_mismatch["indicators"]]
    print(f"Detected Indicators: {mismatch_types}")
    assert "Brand / Destination Domain Mismatch" in mismatch_types
    print("Contextual Brand/Domain Mismatch OK.")

    # 5. Test Raw IP Address & Suspicious Encoding
    ip_url = "http://192.168.1.100/signin@user:pass"
    res_ip = client.post("/api/v1/analyses/url", json={"url": ip_url}, headers=headers)
    assert res_ip.status_code == 200
    data_ip = res_ip.json()
    print(f"IP URL -> Score: {data_ip['risk_score']}, Indicators: {[i['indicator_type'] for i in data_ip['indicators']]}")
    ip_types = [i["indicator_type"] for i in data_ip["indicators"]]
    assert "Direct IP Address Hostname" in ip_types
    print("Direct IP address detection OK.")

    print("--- ALL PHASE 5 TESTS PASSED SUCCESSFULLY ---")

if __name__ == "__main__":
    test_phase_5_url_pipeline()
