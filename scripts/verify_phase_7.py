import io
import os
import sys
import qrcode

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def generate_qr_image_bytes(data: str) -> bytes:
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def test_phase_7_qr_pipeline():
    print("--- STARTING PHASE 7 QR ANALYSIS & DECODING VERIFICATION ---")

    # 1. Login user
    email = "phase7_tester@example.com"
    password = "SafePassword99!"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_res = client.post("/api/v1/auth/login", data={"username": email, "password": password})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Test Safe Benign URL in QR
    safe_qr_bytes = generate_qr_image_bytes("https://www.paypal.com/signin")
    files_safe = {"file": ("safe_qr.png", safe_qr_bytes, "image/png")}
    res_safe = client.post("/api/v1/analyses/qr", files=files_safe, headers=headers)
    assert res_safe.status_code == 200, f"QR decode failed: {res_safe.text}"
    data_safe = res_safe.json()
    print(f"Safe QR -> Payload: {data_safe['decoded_payload']}, Score: {data_safe['risk_score']}")
    assert data_safe["payload_type"] == "url"
    assert "paypal.com" in data_safe["decoded_payload"]
    assert data_safe["risk_score"] < 25
    print("Benign QR decoding OK.")

    # 3. Test Quishing / Malicious Spoofed URL in QR
    scam_url = "http://paypal-security-verification.xyz/login/verify"
    scam_qr_bytes = generate_qr_image_bytes(scam_url)
    files_scam = {"file": ("scam_qr.png", scam_qr_bytes, "image/png")}
    res_scam = client.post("/api/v1/analyses/qr", files=files_scam, headers=headers)
    assert res_scam.status_code == 200
    data_scam = res_scam.json()
    print(f"Phishing QR -> Score: {data_scam['risk_score']}, Indicators: {[i['indicator_type'] for i in data_scam['indicators']]}")
    assert data_scam["risk_score"] >= 70
    scam_types = [i["indicator_type"] for i in data_scam["indicators"]]
    assert "Brand Domain Impersonation (Spoofing)" in scam_types
    print("Quishing (QR Phishing) detection OK.")

    # 4. Test Direct Cryptocurrency Transfer Payload in QR
    crypto_payload = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.5"
    crypto_qr_bytes = generate_qr_image_bytes(crypto_payload)
    files_crypto = {"file": ("crypto_qr.png", crypto_qr_bytes, "image/png")}
    res_crypto = client.post("/api/v1/analyses/qr", files=files_crypto, headers=headers)
    assert res_crypto.status_code == 200
    data_crypto = res_crypto.json()
    print(f"Crypto QR -> Score: {data_crypto['risk_score']}, Type: {data_crypto['payload_type']}")
    assert data_crypto["payload_type"] == "payment"
    crypto_types = [i["indicator_type"] for i in data_crypto["indicators"]]
    assert "Direct Financial / Payment QR Payload" in crypto_types
    print("Direct Payment QR pattern detection OK.")

    # 5. Test Non-QR Image Handling
    dummy_img = io.BytesIO()
    from PIL import Image
    Image.new('RGB', (100, 100), color=(128, 128, 128)).save(dummy_img, format='PNG')
    files_empty = {"file": ("empty.png", dummy_img.getvalue(), "image/png")}
    res_empty = client.post("/api/v1/analyses/qr", files=files_empty, headers=headers)
    assert res_empty.status_code == 200
    data_empty = res_empty.json()
    assert data_empty["decoded_payload"] is None
    assert data_empty["payload_type"] == "empty"
    print("Non-QR image handled gracefully without false crash.")

    print("--- ALL PHASE 7 TESTS PASSED SUCCESSFULLY ---")

if __name__ == "__main__":
    test_phase_7_qr_pipeline()
