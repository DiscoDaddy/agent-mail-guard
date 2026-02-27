# AgentMailGuard Benchmark Results

## v1.4.0 — Pattern Improvements (2026-02-27)

Added 14 new patterns: ignore/disregard/forget variants, roleplay/identity override, hypothetical/scenario bypass, output manipulation, DAN jailbreak. Plus 3 spaceless variants.

### Before (v1.3.0) → After (v1.4.0)

| Metric | v1.3.0 | v1.4.0 | Change |
|--------|--------|--------|--------|
| **Precision** | 0.9891 (98.9%) | 0.9866 (98.7%) | -0.2% |
| **Recall** | 0.0676 (6.8%) | 0.1919 (19.2%) | **+12.4%** |
| **F1 Score** | 0.1265 (12.6%) | 0.3213 (32.1%) | **+19.5%** |
| **False Positive Rate** | 0.0022 (0.2%) | 0.0078 (0.8%) | +0.6% |
| **TP** | 910 | 2585 | +1675 |
| **FP** | 10 | 35 | +25 |
| **TN** | 4499 | 4474 | -25 |
| **FN** | 12561 | 10886 | -1675 |

**Total samples:** 17980 (13471 injection, 4509 benign)

### Summary

- Recall nearly **tripled** (6.8% → 19.2%) — catching 1,675 more injections
- Precision held steady at 98.7% (marginal -0.2%)
- F1 improved from 12.6% to 32.1% — a **2.5x improvement**
- FPR increased slightly from 0.2% to 0.8% — still very low

### Per-Dataset Breakdown (v1.4.0)

| Dataset | Samples | Precision | Recall | F1 | FPR |
|---------|---------|-----------|--------|-----|-----|
| deepset | 662 | TBD | TBD | TBD | TBD |
| jackhhao | 1306 | TBD | TBD | TBD | TBD |
| spml | 16012 | TBD | TBD | TBD | TBD |

---

*Benchmarked on 17,980 samples from deepset, jackhhao, and spml datasets.*
