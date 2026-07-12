"""
Runs the labeled benchmark corpus and reports real accuracy metrics:
precision, recall, F1 -- not just "did it find the obvious example."

Run:
    ./.venv/Scripts/python.exe benchmark/run_benchmark.py

Methodology:
    For each case, scan a temp folder containing ONLY that one file.
    - If expect_category=True:  category MUST appear -> else it's a False Negative (missed a real bug)
    - If expect_category=False: category MUST NOT appear -> else it's a False Positive (flagged safe code)
    True Positive  = vulnerable case, category correctly found
    True Negative  = safe case, category correctly absent

Precision = TP / (TP + FP)  -- of everything flagged, how much was real
Recall    = TP / (TP + FN)  -- of everything real, how much was caught
F1        = harmonic mean of the two

This is run per-category AND in aggregate. A category with high recall but
low precision means it's noisy (over-flags safe code). Low recall means it
misses real bugs. Both numbers matter; neither alone tells the full story.
"""

import sys
import tempfile
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from vibeshield.graph import run_graph
from cases import CASES


def run_case(case) -> set[str]:
    """Returns the set of categories found when scanning this one case."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / case.filename).write_text(case.content, encoding="utf-8")
        state = run_graph(str(root))
        return {v.category for v in state.vulnerabilities}


def main():
    results = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    failures = []

    for case in CASES:
        found_categories = run_case(case)
        category_found = case.category in found_categories

        if case.expect_category and category_found:
            results[case.category]["tp"] += 1
        elif case.expect_category and not category_found:
            results[case.category]["fn"] += 1
            failures.append(f"FALSE NEGATIVE: {case.category} ({case.filename}) -- vulnerable case, category not caught")
        elif not case.expect_category and category_found:
            results[case.category]["fp"] += 1
            failures.append(f"FALSE POSITIVE: {case.category} ({case.filename}) -- safe case, category incorrectly flagged")
        else:
            results[case.category]["tn"] += 1

    print(f"{'Category':<22} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}   {'Precision':>9} {'Recall':>7} {'F1':>6}")
    print("-" * 80)

    total_tp = total_fp = total_fn = total_tn = 0

    for category in sorted(results.keys()):
        r = results[category]
        tp, fp, fn, tn = r["tp"], r["fp"], r["fn"], r["tn"]
        total_tp += tp; total_fp += fp; total_fn += fn; total_tn += tn

        precision = tp / (tp + fp) if (tp + fp) else float("nan")
        recall = tp / (tp + fn) if (tp + fn) else float("nan")
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) and precision == precision and recall == recall and (precision + recall) > 0 else float("nan")

        def fmt(x):
            return "  n/a" if x != x else f"{x:.2f}"

        print(f"{category:<22} {tp:>3} {fp:>3} {fn:>3} {tn:>3}   {fmt(precision):>9} {fmt(recall):>7} {fmt(f1):>6}")

    print("-" * 80)
    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else float("nan")
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else float("nan")
    overall_f1 = (2 * overall_precision * overall_recall / (overall_precision + overall_recall)
                  if (overall_precision + overall_recall) > 0 else float("nan"))
    print(f"{'OVERALL':<22} {total_tp:>3} {total_fp:>3} {total_fn:>3} {total_tn:>3}   "
          f"{overall_precision:>9.2f} {overall_recall:>7.2f} {overall_f1:>6.2f}")
    print()

    if failures:
        print(f"{len(failures)} case(s) did not match expected ground truth:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All cases matched expected ground truth exactly.")


if __name__ == "__main__":
    main()