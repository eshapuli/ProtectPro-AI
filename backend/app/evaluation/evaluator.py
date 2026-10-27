import json
import os
from typing import Dict, Any, List
from pydantic import BaseModel

from app.services.extractors.text_extractor import extract_entities_from_text
from app.services.analyzers.rule_engine import analyze_text_rules
from app.services.analyzers.url_dna_analyzer import analyze_url_dna
from app.services.risk.risk_engine import calculate_risk_score

class EvaluationMetrics(BaseModel):
    total_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    confusion_matrix: Dict[str, Dict[str, int]]
    sample_evaluations: List[Dict[str, Any]]

def run_evaluation_benchmark(dataset_path: str = None) -> EvaluationMetrics:
    """
    Evaluates the deterministic threat detection & risk engine against ground-truth benchmarks.
    Measures Precision, Recall, F1, Accuracy, FPR, and FNR without mocked data.
    """
    if not dataset_path:
        curr_dir = os.path.dirname(__file__)
        dataset_path = os.path.join(curr_dir, "dataset.json")

    with open(dataset_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    tp = 0
    fp = 0
    tn = 0
    fn = 0
    eval_details = []

    for item in samples:
        item_id = item["id"]
        item_type = item["type"]
        content = item["content"]
        ground_truth = item["ground_truth"] # "SCAM" or "BENIGN"

        indicators = []
        if item_type == "url":
            url_report = analyze_url_dna(content)
            indicators = url_report.indicators
        else: # text
            extraction = extract_entities_from_text(content)
            indicators = analyze_text_rules(extraction)
            for url in extraction.extracted_urls:
                url_rep = analyze_url_dna(url, context_text=content)
                indicators.extend(url_rep.indicators)

        risk_res = calculate_risk_score(indicators)
        # Decision boundary: risk score >= 30 is classified as Threat (SCAM)
        prediction = "SCAM" if risk_res.score >= 30 else "BENIGN"

        if ground_truth == "SCAM" and prediction == "SCAM":
            tp += 1
            outcome = "TP"
        elif ground_truth == "BENIGN" and prediction == "SCAM":
            fp += 1
            outcome = "FP"
        elif ground_truth == "BENIGN" and prediction == "BENIGN":
            tn += 1
            outcome = "TN"
        else:
            fn += 1
            outcome = "FN"

        eval_details.append({
            "id": item_id,
            "category": item.get("category"),
            "ground_truth": ground_truth,
            "prediction": prediction,
            "risk_score": risk_res.score,
            "risk_level": risk_res.risk_level,
            "outcome": outcome,
            "indicator_count": len(indicators)
        })

    total = len(samples)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return EvaluationMetrics(
        total_samples=total,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        accuracy=round(accuracy, 4),
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        false_negative_rate=round(fnr, 4),
        confusion_matrix={
            "actual_scam": {"predicted_scam": tp, "predicted_benign": fn},
            "actual_benign": {"predicted_scam": fp, "predicted_benign": tn}
        },
        sample_evaluations=eval_details
    )
