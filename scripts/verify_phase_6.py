import io
import os
import sys
from PIL import Image, ImageDraw

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def create_synthetic_screenshot(text: str) -> bytes:
    """Generates an in-memory PNG image with text rendered onto it."""
    img = Image.new('RGB', (600, 200), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 50), text, fill=(0, 0, 0))
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return buffer.getvalue()

def test_phase_6_screenshot_pipeline():
    print("--- STARTING PHASE 6 SCREENSHOT OCR & FORENSICS VERIFICATION ---")

    # 1. Login user
    email = "phase6_tester@example.com"
    password = "SafePassword99!"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_res = client.post("/api/v1/auth/login", data={"username": email, "password": password})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Test Benign / Blank Screenshot
    blank_bytes = create_synthetic_screenshot("Hello, this is a normal business memo.")
    files = {"file": ("screenshot.png", blank_bytes, "image/png")}
    res_blank = client.post("/api/v1/analyses/screenshot", files=files, headers=headers)
    assert res_blank.status_code == 200, f"Screenshot request failed: {res_blank.text}"
    data_blank = res_blank.json()
    print(f"Blank/Benign Screenshot -> Engine: {data_blank['ocr_engine']}, Score: {data_blank['risk_score']}")
    assert data_blank["forensics"]["width"] == 600
    assert data_blank["forensics"]["height"] == 200
    assert data_blank["forensics"]["format"] == "PNG"
    print("Forensics & safe upload validation OK.")

    # 3. Test Invalid File Extension / MIME Rejection
    bad_files = {"file": ("malicious.exe", b"MZ\x90\x00\x03\x00\x00\x00", "application/octet-stream")}
    res_bad = client.post("/api/v1/analyses/screenshot", files=bad_files, headers=headers)
    assert res_bad.status_code == 400
    print("Unsafe non-image payload rejected successfully (400 Bad Request).")

    # 4. Test File Size Limit Exceeded (> 5MB)
    huge_payload = b"0" * (6 * 1024 * 1024)
    huge_files = {"file": ("huge.png", huge_payload, "image/png")}
    res_huge = client.post("/api/v1/analyses/screenshot", files=huge_files, headers=headers)
    assert res_huge.status_code == 400
    print("Excessive file size (>5MB) rejected successfully (400 Bad Request).")

    print("--- ALL PHASE 6 TESTS PASSED SUCCESSFULLY ---")

if __name__ == "__main__":
    test_phase_6_screenshot_pipeline()
