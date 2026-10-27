import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_phase_14_evaluation():
    print("--- STARTING PHASE 14 EVALUATION FRAMEWORK VERIFICATION ---")

    # 1. Login user
    email = "phase14_tester@example.com"
    password = "SafePassword99!"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_res = client.post("/api/v1/auth/login", data={"username": email, "password": password})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Invoke Evaluation Benchmark via API
    res = client.get("/api/v1/evaluation/metrics", headers=headers)
    assert res.status_code == 200, f"Evaluation benchmark failed: {res.text}"
    metrics = res.json()

    print(f"Total Samples Evaluated: {metrics['total_samples']}")
    print(f"Accuracy: {metrics['accuracy'] * 100:.1f}%")
    print(f"Precision: {metrics['precision'] * 100:.1f}%")
    print(f"Recall: {metrics['recall'] * 100:.1f}%")
    print(f"F1 Score: {metrics['f1_score'] * 100:.1f}%")
    print(f"False Positive Rate (FPR): {metrics['false_positive_rate'] * 100:.1f}%")
    print(f"False Negative Rate (FNR): {metrics['false_negative_rate'] * 100:.1f}%")
    print(f"Confusion Matrix: {metrics['confusion_matrix']}")

    # Verification assertions:
    # Deterministic pipeline must achieve high precision and zero false positives on benign samples
    assert metrics["total_samples"] == 12
    assert metrics["false_positives"] == 0, "Zero false positives expected on benign baseline."
    assert metrics["true_positives"] >= 6, "At least 6 out of 7 scam vectors must be detected."
    assert metrics["precision"] == 1.0, "Precision must be 100% (no benign messages misclassified)."
    assert metrics["recall"] >= 0.85, "Recall must be >= 85%."
    assert metrics["f1_score"] >= 0.90, "F1 score must be >= 0.90."

    print("--- ALL PHASE 14 TESTS PASSED SUCCESSFULLY ---")

if __name__ == "__main__":
    test_phase_14_evaluation()
