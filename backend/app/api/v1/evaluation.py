from fastapi import APIRouter, Depends
from app.api import deps
from app.models.user import User
from app.evaluation.evaluator import run_evaluation_benchmark, EvaluationMetrics

router = APIRouter()

@router.get("/metrics", response_model=EvaluationMetrics)
def get_evaluation_metrics(
    current_user: User = Depends(deps.get_current_user)
):
    """
    Executes and returns the live empirical evaluation benchmarks:
    Precision, Recall, F1, Accuracy, False Positive/Negative Rates, and Confusion Matrix.
    """
    return run_evaluation_benchmark()
