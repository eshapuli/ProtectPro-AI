import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_phase_9_campaign_pipeline():
    print("--- STARTING PHASE 9 CAMPAIGN DETECTION & THREAT TIMELINE VERIFICATION ---")

    # 1. Login user
    email = "phase9_tester@example.com"
    password = "SafePassword99!"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_res = client.post("/api/v1/auth/login", data={"username": email, "password": password})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Submit initial wave of a coordinated scam campaign
    wave_1 = (
        "URGENT ALERT: Your Chase account will be locked immediately. "
        "Enter your password and security pin at http://chase-urgent-verify.xyz/login within 12 hours!"
    )
    res_1 = client.post("/api/v1/analyses/text", json={"text": wave_1}, headers=headers)
    assert res_1.status_code == 200
    data_1 = res_1.json()
    id_1 = data_1["analysis_id"]
    print(f"Wave 1 Submission -> ID: {id_1}, Initial Campaign: {data_1.get('campaign_id')}")

    # 3. Submit secondary mutated wave sharing the same threat infrastructure and patterns
    wave_2 = (
        "URGENT ALERT: Your Chase account is suspended. "
        "Enter your password and security pin at http://chase-urgent-verify.xyz/login immediately!"
    )
    res_2 = client.post("/api/v1/analyses/text", json={"text": wave_2}, headers=headers)
    assert res_2.status_code == 200
    data_2 = res_2.json()
    id_2 = data_2["analysis_id"]
    campaign_id = data_2.get("campaign_id")
    print(f"Wave 2 Submission -> ID: {id_2}, Detected Campaign ID: {campaign_id}")
    
    assert campaign_id is not None
    assert campaign_id.startswith("CP-2026-")
    print("Automated Campaign Clustering OK.")

    # 4. Submit third mutation to test campaign member accumulation
    wave_3 = (
        "URGENT NOTICE: Your Chase account access is restricted. "
        "Enter your credentials and passcode at http://chase-urgent-verify.xyz/login now!"
    )
    res_3 = client.post("/api/v1/analyses/text", json={"text": wave_3}, headers=headers)
    assert res_3.status_code == 200
    data_3 = res_3.json()
    print(f"Wave 3 Submission -> ID: {data_3['analysis_id']}, Campaign ID: {data_3.get('campaign_id')}")
    assert data_3.get("campaign_id") == campaign_id
    print("Multi-submission campaign membership aggregation OK.")

    # 5. Verify Threat Timeline Endpoint GET /campaigns/{campaign_id}
    timeline_res = client.get(f"/api/v1/campaigns/{campaign_id}", headers=headers)
    assert timeline_res.status_code == 200, f"Timeline fetch failed: {timeline_res.text}"
    timeline_data = timeline_res.json()
    print(f"Campaign Report -> Name: {timeline_data['name']}, Submissions: {timeline_data['total_submissions']}")
    assert timeline_data["total_submissions"] >= 3
    assert len(timeline_data["timeline"]) >= 3
    
    # Check timeline events
    event_types = [e["event_type"] for e in timeline_data["timeline"]]
    print(f"Timeline Events: {event_types}")
    assert "FIRST_OBSERVED" in event_types
    assert "LATEST_OBSERVATION" in event_types
    print("Chronological Threat Timeline verification OK.")

    # 6. Verify List Campaigns GET /campaigns
    list_res = client.get("/api/v1/campaigns/", headers=headers)
    assert list_res.status_code == 200
    all_campaigns = list_res.json()
    assert len(all_campaigns) >= 1
    found_camp = any(c["campaign_id"] == campaign_id for c in all_campaigns)
    assert found_camp is True
    print("Campaign list query OK.")

    print("--- ALL PHASE 9 TESTS PASSED SUCCESSFULLY ---")

if __name__ == "__main__":
    test_phase_9_campaign_pipeline()
