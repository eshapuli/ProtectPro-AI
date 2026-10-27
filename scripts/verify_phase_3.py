import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from app.main import app
from app.db.database import SessionLocal
from app.models.user import User, Analysis
from app.core.config import settings

client = TestClient(app)

def run_verifications():
    print("--- STARTING VERIFICATION ---")

    # 1. Test Registration
    print("Testing Registration...")
    import uuid
    run_id = uuid.uuid4().hex[:8]
    email1 = f"user1_{run_id}@example.com"
    email2 = f"user2_{run_id}@example.com"
    password = "password123"

    res1 = client.post("/api/v1/auth/register", json={"email": email1, "password": password})
    assert res1.status_code == 200, f"Failed to register user 1: {res1.text}"
    user1_id = res1.json()["id"]

    res2 = client.post("/api/v1/auth/register", json={"email": email2, "password": password})
    assert res2.status_code == 200, f"Failed to register user 2: {res2.text}"
    user2_id = res2.json()["id"]
    print("Registration OK")

    # 2. Test Login & JWT
    print("Testing Login...")
    login_res = client.post("/api/v1/auth/login", data={"username": email1, "password": password})
    assert login_res.status_code == 200, "Login failed"
    token = login_res.json()["access_token"]
    assert token is not None
    print("Login and JWT generation OK")

    # 3. Test Protected Endpoints & Authorization
    print("Testing Protected Endpoints...")
    headers = {"Authorization": f"Bearer {token}"}
    me_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == email1
    print("Authorized access OK")

    # 4. Test Unauthenticated Access
    print("Testing Unauthenticated Access Rejection...")
    fail_res = client.get("/api/v1/auth/me")
    assert fail_res.status_code == 401
    print("Unauthenticated access rejected OK")

    # 5. Verify Database Tables and Password Hashing
    print("Testing Database constraints and Hashing...")
    db = SessionLocal()
    db_user = db.query(User).filter(User.email == email1).first()
    assert db_user is not None
    assert db_user.hashed_password != password, "Password was stored in plaintext!"
    assert db_user.hashed_password.startswith("$2b$") # bcrypt prefix
    
    # Verify User Isolation
    # Create mock analyses manually for user 1 and user 2
    a1 = Analysis(user_id=user1_id, input_type="text", risk_score=50, risk_level="Medium")
    a2 = Analysis(user_id=user2_id, input_type="url", risk_score=90, risk_level="Critical")
    db.add(a1)
    db.add(a2)
    db.commit()

    # User 1 fetches history
    hist_res = client.get("/api/v1/history/", headers=headers)
    assert hist_res.status_code == 200
    hist_data = hist_res.json()["analyses"]
    assert len(hist_data) == 1
    assert hist_data[0]["id"] == a1.id
    assert hist_data[0]["input_type"] == "text"
    print("User Isolation OK")

    # 6. Verify Config and Secrets
    print("Testing Configuration...")
    assert "sqlite" in settings.SQLALCHEMY_DATABASE_URI
    assert settings.SECRET_KEY != ""
    print("Configuration OK")

    print("--- ALL VERIFICATIONS PASSED ---")

if __name__ == "__main__":
    run_verifications()
