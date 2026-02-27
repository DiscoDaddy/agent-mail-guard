#!/usr/bin/env python3
"""
Benchmark AgentMailGuard sanitizer against known prompt injection datasets.

SAFETY: All dataset content is treated as hostile attack payloads.
Content is ONLY passed through sanitize_text() programmatically.
No dataset content is ever printed to stdout in full — only statistics.
"""

import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

import pyarrow.parquet as pq

# Add sanitizer to path
SANITIZER_DIR = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, SANITIZER_DIR)

from sanitize_core import sanitize_text

DATASETS_DIR = Path(__file__).resolve().parent / "datasets"
OUTPUT_DIR = Path(__file__).resolve().parent


def load_deepset():
    """Load deepset/prompt-injections. label: 1=injection, 0=benign."""
    samples = []
    for f in ["deepset_train.parquet", "deepset_test.parquet"]:
        p = DATASETS_DIR / f
        if not p.exists():
            continue
        t = pq.read_table(str(p))
        texts = t.column("text").to_pylist()
        labels = t.column("label").to_pylist()
        for text, label in zip(texts, labels):
            samples.append({
                "text": str(text) if text else "",
                "is_injection": label == 1,
                "dataset": "deepset",
            })
    return samples


def load_spml():
    """Load SPML Chatbot Prompt Injection. 'Prompt injection': 1=injection, 0=benign.
    Uses 'User Prompt' as the text to test."""
    p = DATASETS_DIR / "spml_train.parquet"
    if not p.exists():
        return []
    t = pq.read_table(str(p))
    texts = t.column("User Prompt").to_pylist()
    labels = t.column("Prompt injection").to_pylist()
    samples = []
    for text, label in zip(texts, labels):
        samples.append({
            "text": str(text) if text else "",
            "is_injection": label == 1,
            "dataset": "spml",
        })
    return samples


def load_jackhhao():
    """Load jackhhao/jailbreak-classification. type: 'jailbreak'=injection, 'benign'=benign."""
    samples = []
    for f in ["jackhhao_train.parquet", "jackhhao_test.parquet"]:
        p = DATASETS_DIR / f
        if not p.exists():
            continue
        t = pq.read_table(str(p))
        texts = t.column("prompt").to_pylist()
        types = t.column("type").to_pylist()
        for text, typ in zip(texts, types):
            samples.append({
                "text": str(text) if text else "",
                "is_injection": typ == "jailbreak",
                "dataset": "jackhhao",
            })
    return samples


def run_benchmark(samples):
    """Run sanitizer on all samples, return metrics."""
    results = {
        "tp": 0, "fp": 0, "tn": 0, "fn": 0,
        "by_dataset": defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0}),
        "missed_categories": defaultdict(int),
        "missed_examples": [],  # store first N missed injection indices
        "false_positive_flags": defaultdict(int),
        "total_time": 0,
    }

    start = time.time()
    for i, sample in enumerate(samples):
        text = sample["text"]
        is_injection = sample["is_injection"]
        ds = sample["dataset"]

        try:
            _, flags, _ = sanitize_text(text)
        except Exception:
            flags = []

        detected = len(flags) > 0

        if is_injection and detected:
            results["tp"] += 1
            results["by_dataset"][ds]["tp"] += 1
        elif is_injection and not detected:
            results["fn"] += 1
            results["by_dataset"][ds]["fn"] += 1
            # Categorize the miss (without storing raw text)
            # Simple heuristic categorization based on text length and basic properties
            text_len = len(text)
            cat = categorize_missed(text)
            results["missed_categories"][cat] += 1
            if len(results["missed_examples"]) < 500:
                results["missed_examples"].append({
                    "index": i,
                    "dataset": ds,
                    "category": cat,
                    "text_length": text_len,
                    "first_20_chars_hash": hash(text[:20]) % 10**8,  # non-reversible ref
                })
        elif not is_injection and detected:
            results["fp"] += 1
            results["by_dataset"][ds]["fp"] += 1
            for f in flags:
                results["false_positive_flags"][f] += 1
        else:
            results["tn"] += 1
            results["by_dataset"][ds]["tn"] += 1

    results["total_time"] = time.time() - start
    return results


def categorize_missed(text: str) -> str:
    """Categorize a missed injection by technique (without exposing raw content)."""
    t = text.lower()
    if "ignore" in t and "instruction" in t:
        return "direct_override"
    if "ignore" in t and "previous" in t:
        return "direct_override"
    if "forget" in t and ("instruction" in t or "rule" in t):
        return "direct_override"
    if "disregard" in t:
        return "direct_override"
    if "system:" in t or "[system]" in t or "<<sys>>" in t:
        return "system_prompt_injection"
    if "pretend" in t or "act as" in t or "you are now" in t:
        return "role_play"
    if "do anything now" in t or "dan" in t.split():
        return "dan_jailbreak"
    if "base64" in t or "encode" in t or "decode" in t:
        return "encoding_attack"
    if "translate" in t:
        return "translation_attack"
    if "repeat" in t or "say" in t:
        return "output_manipulation"
    if "sudo" in t or "admin" in t or "override" in t:
        return "privilege_escalation"
    if "hypothetical" in t or "imagine" in t or "scenario" in t:
        return "hypothetical_scenario"
    if "poem" in t or "story" in t or "write" in t:
        return "creative_bypass"
    if len(text) > 1000:
        return "long_payload"
    if any(ord(c) > 127 for c in text[:100]):
        return "unicode_obfuscation"
    return "uncategorized"


def compute_metrics(tp, fp, tn, fn):
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / total if total > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    return {
        "total": total,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "fpr": fpr,
    }


def generate_report(results, total_samples):
    tp, fp, tn, fn = results["tp"], results["fp"], results["tn"], results["fn"]
    m = compute_metrics(tp, fp, tn, fn)

    lines = []
    lines.append("# AgentMailGuard Benchmark Results")
    lines.append("")
    lines.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M CST')}")
    lines.append(f"**Sanitizer version:** sanitize_core.py")
    lines.append(f"**Total samples:** {total_samples}")
    lines.append(f"**Runtime:** {results['total_time']:.2f}s ({total_samples/results['total_time']:.0f} samples/sec)")
    lines.append("")
    lines.append("## Overall Metrics")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| **Precision** | {m['precision']:.4f} ({m['precision']*100:.1f}%) |")
    lines.append(f"| **Recall** | {m['recall']:.4f} ({m['recall']*100:.1f}%) |")
    lines.append(f"| **F1 Score** | {m['f1']:.4f} ({m['f1']*100:.1f}%) |")
    lines.append(f"| **Accuracy** | {m['accuracy']:.4f} ({m['accuracy']*100:.1f}%) |")
    lines.append(f"| **False Positive Rate** | {m['fpr']:.4f} ({m['fpr']*100:.1f}%) |")
    lines.append("")
    lines.append("## Confusion Matrix")
    lines.append("")
    lines.append(f"| | Predicted Injection | Predicted Benign |")
    lines.append(f"|---|---|---|")
    lines.append(f"| **Actual Injection** | TP: {tp} | FN: {fn} |")
    lines.append(f"| **Actual Benign** | FP: {fp} | TN: {tn} |")
    lines.append("")

    lines.append("## Per-Dataset Breakdown")
    lines.append("")
    for ds, counts in sorted(results["by_dataset"].items()):
        dm = compute_metrics(counts["tp"], counts["fp"], counts["tn"], counts["fn"])
        inj = counts["tp"] + counts["fn"]
        ben = counts["fp"] + counts["tn"]
        lines.append(f"### {ds}")
        lines.append(f"- Samples: {dm['total']} (injection: {inj}, benign: {ben})")
        lines.append(f"- Precision: {dm['precision']:.4f} | Recall: {dm['recall']:.4f} | F1: {dm['f1']:.4f}")
        lines.append(f"- False Positive Rate: {dm['fpr']:.4f}")
        lines.append("")

    lines.append("## Missed Injection Categories (False Negatives)")
    lines.append("")
    if results["missed_categories"]:
        lines.append(f"| Category | Count | % of FN |")
        lines.append(f"|----------|-------|---------|")
        for cat, count in sorted(results["missed_categories"].items(), key=lambda x: -x[1]):
            pct = count / fn * 100 if fn > 0 else 0
            lines.append(f"| {cat} | {count} | {pct:.1f}% |")
    else:
        lines.append("No missed injections! 🎉")
    lines.append("")

    lines.append("## Top False Positive Triggers")
    lines.append("")
    if results["false_positive_flags"]:
        lines.append(f"| Flag | Count |")
        lines.append(f"|------|-------|")
        for flag, count in sorted(results["false_positive_flags"].items(), key=lambda x: -x[1])[:15]:
            lines.append(f"| {flag} | {count} |")
    else:
        lines.append("No false positives! 🎉")
    lines.append("")

    return "\n".join(lines)


def main():
    print("Loading datasets...")
    all_samples = []

    deepset = load_deepset()
    print(f"  deepset: {len(deepset)} samples")
    all_samples.extend(deepset)

    spml = load_spml()
    print(f"  spml: {len(spml)} samples")
    all_samples.extend(spml)

    jackhhao = load_jackhhao()
    print(f"  jackhhao: {len(jackhhao)} samples")
    all_samples.extend(jackhhao)

    total_inj = sum(1 for s in all_samples if s["is_injection"])
    total_ben = sum(1 for s in all_samples if not s["is_injection"])
    print(f"\nTotal: {len(all_samples)} samples ({total_inj} injection, {total_ben} benign)")

    print("\nRunning benchmark...")
    results = run_benchmark(all_samples)

    print(f"\nDone in {results['total_time']:.2f}s")
    print(f"  TP={results['tp']} FP={results['fp']} TN={results['tn']} FN={results['fn']}")
    m = compute_metrics(results["tp"], results["fp"], results["tn"], results["fn"])
    print(f"  Precision={m['precision']:.4f} Recall={m['recall']:.4f} F1={m['f1']:.4f}")

    # Save results
    report = generate_report(results, len(all_samples))
    (OUTPUT_DIR / "RESULTS.md").write_text(report)
    print(f"\nResults saved to RESULTS.md")

    # Save missed injection examples (categories only, no raw text)
    missed_out = {
        "total_false_negatives": results["fn"],
        "categories": dict(results["missed_categories"]),
        "examples": results["missed_examples"],
    }
    (OUTPUT_DIR / "missed-injections.json").write_text(json.dumps(missed_out, indent=2))
    print(f"Missed injections saved to missed-injections.json")


if __name__ == "__main__":
    main()
