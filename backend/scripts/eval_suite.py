"""
VulnGuard AI — AI Evaluation Suite (Phase 4)

Runs the LangGraph scanner against a 20-sample benchmark dataset and
computes classification metrics:

  Accuracy  — how often the binary label (vulnerable / clean) is correct
  Precision — of findings reported, how many are genuine
  Recall    — of genuine vulns, how many did we catch
  F1        — harmonic mean of Precision and Recall
  Per-type breakdown — accuracy per vulnerability type

Usage:
    python backend/scripts/eval_suite.py
    python backend/scripts/eval_suite.py --benchmark backend/data/benchmark.json
    python backend/scripts/eval_suite.py --output results/eval_2026-05-12.json
"""

import argparse
import json
import os
import sys
import time
import tempfile
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

# Add project root so backend.agents imports work
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.agents.scanner import build_scanner_graph
from backend.agents.state import ScanState


# ─────────────────────────────────────────────────────────────────────────────
# Metric helpers
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ConfusionMatrix:
    tp: int = 0   # True Positive  — correctly flagged as vulnerable
    tn: int = 0   # True Negative  — correctly flagged as clean
    fp: int = 0   # False Positive — clean code flagged as vulnerable
    fn: int = 0   # False Negative — vulnerable code missed

    @property
    def accuracy(self) -> float:
        total = self.tp + self.tn + self.fp + self.fn
        return (self.tp + self.tn) / total if total else 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class SampleResult:
    sample_id: str
    language: str
    ground_truth_label: str        # "vulnerable" | "clean"
    predicted_label: str           # "vulnerable" | "clean"
    expected_vuln_types: list
    detected_vuln_types: list
    confirmed_count: int
    correct: bool
    elapsed_s: float
    error: Optional[str] = None


@dataclass
class EvalReport:
    timestamp: str
    benchmark_path: str
    total_samples: int
    correct: int
    cm: ConfusionMatrix
    per_type: dict
    sample_results: list[SampleResult]
    model_info: str
    elapsed_total_s: float


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

def _write_temp_code(code: str, language: str) -> str:
    """Write code snippet to a temp file and return its path."""
    ext_map = {"php": ".php", "python": ".py", "javascript": ".js"}
    ext = ext_map.get(language, ".txt")
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=ext, delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        return f.name


def _run_sample(graph, sample: dict) -> SampleResult:
    """Run the scanner graph on a single benchmark sample and return a SampleResult."""
    sample_id = sample["id"]
    code = sample["code"]
    language = sample.get("language", "unknown")
    ground_truth = sample["label"]           # "vulnerable" | "clean"
    expected_vulns = sample.get("expected_vulns", [])

    # Write code to a temp file (scanner reads from file paths)
    temp_path = _write_temp_code(code, language)

    initial_state: ScanState = {
        "file_path": temp_path,
        "file_content": "",
        "findings": [],
        "verified_indices": [],
        "patches": [],
        "logs": [],
        "current_node": "scan",
        "error": None,
    }

    start = time.perf_counter()
    error = None

    try:
        result = graph.invoke(initial_state)
    except Exception as e:
        error = str(e)
        result = {"findings": [], "verified_indices": [], "patches": [], "logs": []}
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass

    elapsed = time.perf_counter() - start

    findings = result.get("findings", [])
    verified_raw = result.get("verified_indices", [])

    # Safely coerce verified indices to ints
    verified_ints = []
    for idx in verified_raw:
        if isinstance(idx, int):
            verified_ints.append(idx)
        elif isinstance(idx, dict):
            verified_ints = list(range(len(findings)))
            break
        else:
            try:
                verified_ints.append(int(idx))
            except (TypeError, ValueError):
                pass

    confirmed_findings = [findings[i] for i in verified_ints if i < len(findings)]
    confirmed_count = len(confirmed_findings)

    # Binary prediction: "vulnerable" if any confirmed findings, else "clean"
    predicted_label = "vulnerable" if confirmed_count > 0 else "clean"
    correct = predicted_label == ground_truth

    detected_types = [f.get("vuln_type", "") for f in confirmed_findings]

    return SampleResult(
        sample_id=sample_id,
        language=language,
        ground_truth_label=ground_truth,
        predicted_label=predicted_label,
        expected_vuln_types=[v["vuln_type"] for v in expected_vulns],
        detected_vuln_types=detected_types,
        confirmed_count=confirmed_count,
        correct=correct,
        elapsed_s=round(elapsed, 2),
        error=error,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Report formatting
# ─────────────────────────────────────────────────────────────────────────────

def _bar(value: float, width: int = 30) -> str:
    """ASCII progress bar."""
    filled = round(value * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _print_report(report: EvalReport):
    """Print a formatted evaluation report to stdout."""
    W = 72
    sep = "=" * W
    thin = "-" * W

    print(f"\n{sep}")
    print(f"  VulnGuard AI -- Evaluation Suite Report")
    print(f"  Timestamp : {report.timestamp}")
    print(f"  Benchmark : {report.benchmark_path}")
    print(f"  Model     : {report.model_info}")
    print(f"  Samples   : {report.total_samples} total")
    print(f"  Duration  : {report.elapsed_total_s:.1f}s")
    print(f"{sep}")

    # ── Confusion matrix ─────────────────────────────────────────────────────
    cm = report.cm
    print(f"\n  Confusion Matrix")
    print(f"  {thin}")
    print(f"                     Predicted")
    print(f"                  Vuln      Clean")
    print(f"  Actual  Vuln  | TP={cm.tp:3d}  | FN={cm.fn:3d}  |")
    print(f"          Clean | FP={cm.fp:3d}  | TN={cm.tn:3d}  |")

    # ── Core metrics ─────────────────────────────────────────────────────────
    print(f"\n  Core Metrics")
    print(f"  {thin}")
    metrics = [
        ("Accuracy",  cm.accuracy,  "How often overall label is correct"),
        ("Precision", cm.precision, "Of reported vulns, % that are real"),
        ("Recall",    cm.recall,    "Of real vulns, % we caught"),
        ("F1 Score",  cm.f1,        "Harmonic mean of Precision & Recall"),
    ]
    for name, val, desc in metrics:
        bar = _bar(val)
        print(f"  {name:<10} {_pct(val):>6}  {bar}  {desc}")

    # ── Per-type breakdown ────────────────────────────────────────────────────
    if report.per_type:
        print(f"\n  Per-Vulnerability-Type Detection")
        print(f"  {thin}")
        print(f"  {'Type':<30} {'Expected':>8} {'Detected':>8} {'Hit Rate':>9}")
        print(f"  {'-'*30} {'-'*8} {'-'*8} {'-'*9}")
        for vtype, counts in sorted(report.per_type.items(), key=lambda x: -x[1]["expected"]):
            exp = counts["expected"]
            det = counts["detected"]
            rate = det / exp if exp else 0.0
            bar_small = "#" * round(rate * 10) + "-" * (10 - round(rate * 10))
            print(f"  {vtype:<30} {exp:>8} {det:>8}   [{bar_small}]")

    # ── Sample-by-sample table ────────────────────────────────────────────────
    print(f"\n  Sample Results")
    print(f"  {thin}")
    print(f"  {'ID':<5} {'Lang':<5} {'Truth':<10} {'Predicted':<10} {'OK?':<5} {'Time':>6}  Notes")
    print(f"  {'-'*5} {'-'*5} {'-'*10} {'-'*10} {'-'*5} {'-'*6}  {'-'*20}")
    for r in report.sample_results:
        ok = "[OK]" if r.correct else "[X]"
        note = ""
        if not r.correct:
            if r.ground_truth_label == "vulnerable" and r.predicted_label == "clean":
                note = f"Missed: {', '.join(r.expected_vuln_types[:2])}"
            else:
                note = f"FP: {', '.join(r.detected_vuln_types[:2])}"
        if r.error:
            note = f"ERROR: {r.error[:40]}"
        print(
            f"  {r.sample_id:<5} {r.language:<5} {r.ground_truth_label:<10} "
            f"{r.predicted_label:<10} {ok:<5} {r.elapsed_s:>5.1f}s  {note}"
        )

    # ── Final verdict ─────────────────────────────────────────────────────────
    print(f"\n{sep}")
    acc = cm.accuracy
    if acc >= 0.90:
        verdict = "[EXCELLENT]  Model performance is production-ready."
    elif acc >= 0.75:
        verdict = "[GOOD]       Solid performance, minor tuning recommended."
    elif acc >= 0.60:
        verdict = "[ACCEPTABLE] Performance is acceptable for a portfolio demo."
    else:
        verdict = "[NEEDS WORK] High miss/false-positive rate. Review prompts."
    print(f"\n  Verdict: {verdict}")
    print(f"  Correct: {report.correct}/{report.total_samples} | "
          f"Accuracy: {_pct(cm.accuracy)} | "
          f"Precision: {_pct(cm.precision)} | "
          f"Recall: {_pct(cm.recall)} | "
          f"F1: {_pct(cm.f1)}")
    print(f"\n{sep}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def run_eval(benchmark_path: str, output_path: Optional[str] = None) -> EvalReport:
    from datetime import datetime

    print(f"\n[*] Loading benchmark: {benchmark_path}")
    with open(benchmark_path, encoding="utf-8") as f:
        benchmark = json.load(f)

    samples = benchmark["samples"]
    print(f"[*] {len(samples)} samples loaded")
    print(f"[*] Building LangGraph scanner...")

    graph = build_scanner_graph()

    # Detect which LLM is active
    from backend.agents.llm_client import get_gemini_client, get_openai_client, get_anthropic_client
    g_client, g_model = get_gemini_client()
    o_client, o_model = get_openai_client()
    a_client, a_model = get_anthropic_client()
    if g_client:
        model_info = f"Gemini ({g_model})"
    elif o_client:
        model_info = f"OpenAI ({o_model})"
    elif a_client:
        model_info = f"Anthropic ({a_model})"
    else:
        model_info = "Mock (no API key — offline mode)"

    print(f"[*] LLM backend: {model_info}")
    print(f"[*] Starting evaluation...\n")

    results: list[SampleResult] = []
    cm = ConfusionMatrix()
    per_type: dict[str, dict] = {}

    total_start = time.perf_counter()

    for i, sample in enumerate(samples):
        sid = sample["id"]
        print(f"  [{i+1:02d}/{len(samples)}] {sid} ({sample['language']}, {sample['label']}) ...", end=" ", flush=True)

        r = _run_sample(graph, sample)
        results.append(r)

        # Update confusion matrix
        truth = sample["label"]
        if truth == "vulnerable":
            if r.predicted_label == "vulnerable":
                cm.tp += 1
            else:
                cm.fn += 1
        else:
            if r.predicted_label == "clean":
                cm.tn += 1
            else:
                cm.fp += 1

        # Update per-type hit rate tracking
        for ev in sample.get("expected_vulns", []):
            vt = ev["vuln_type"]
            if vt not in per_type:
                per_type[vt] = {"expected": 0, "detected": 0}
            per_type[vt]["expected"] += 1
            # Check if we detected this specific vuln type
            detected_types_lower = [d.lower() for d in r.detected_vuln_types]
            if any(vt.lower() in d or d in vt.lower() for d in detected_types_lower):
                per_type[vt]["detected"] += 1

        status = "OK" if r.correct else "X"
        print(f"{status}  ({r.elapsed_s:.1f}s)")

    elapsed_total = round(time.perf_counter() - total_start, 1)

    report = EvalReport(
        timestamp=datetime.now().isoformat(timespec="seconds"),
        benchmark_path=str(benchmark_path),
        total_samples=len(samples),
        correct=sum(1 for r in results if r.correct),
        cm=cm,
        per_type=per_type,
        sample_results=results,
        model_info=model_info,
        elapsed_total_s=elapsed_total,
    )

    _print_report(report)

    # Optionally save JSON report
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        def _convert(obj):
            if isinstance(obj, ConfusionMatrix):
                return {**asdict(obj), "accuracy": obj.accuracy, "precision": obj.precision,
                        "recall": obj.recall, "f1": obj.f1}
            if isinstance(obj, SampleResult):
                return asdict(obj)
            raise TypeError(type(obj))

        report_dict = {
            "timestamp": report.timestamp,
            "benchmark_path": report.benchmark_path,
            "total_samples": report.total_samples,
            "correct": report.correct,
            "model_info": report.model_info,
            "elapsed_total_s": report.elapsed_total_s,
            "metrics": {
                "accuracy":  cm.accuracy,
                "precision": cm.precision,
                "recall":    cm.recall,
                "f1":        cm.f1,
                "tp": cm.tp, "tn": cm.tn, "fp": cm.fp, "fn": cm.fn,
            },
            "per_type": report.per_type,
            "samples": [asdict(r) for r in results],
        }
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, default=str)
        print(f"[*] JSON report saved to: {out}")

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnGuard AI — Evaluation Suite")
    parser.add_argument(
        "--benchmark",
        default="backend/data/benchmark.json",
        help="Path to benchmark JSON file (default: backend/data/benchmark.json)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional path to save JSON evaluation report (e.g. results/eval.json)",
    )
    args = parser.parse_args()

    report = run_eval(args.benchmark, args.output)

    # Exit with non-zero if accuracy is terrible (useful for CI)
    if report.cm.accuracy < 0.50:
        sys.exit(1)
