# AgentMailGuard — Benchmark Recommendations

**Date:** 2026-02-27
**Based on:** 17,980 samples across 3 datasets (deepset, SPML, jackhhao)

## Summary

The sanitizer has **excellent precision (98.9%)** and **near-zero false positive rate (0.2%)** but **critically low recall (6.8%)**. It catches only 910 of 13,471 injection attempts. This is expected for a narrow regex-based approach — it was designed to catch specific patterns seen in email contexts, not the full spectrum of prompt injection techniques.

## Key Finding: Design Intent vs. Benchmark Scope

AgentMailGuard is an **email sanitizer**, not a general-purpose prompt injection classifier. Many missed samples are jailbreak-style attacks (roleplay, hypothetical scenarios, creative bypasses) that wouldn't typically appear in email bodies. The sanitizer's strength is its surgical precision and structural sanitization (URL stripping, base64 removal, etc.) which aren't measured by a simple detect/don't-detect benchmark.

**The recall number (6.8%) is misleadingly low** because the benchmark tests general injection detection, while the sanitizer focuses on email-specific threats + structural sanitization.

## Actionable Improvements (Priority Order)

### 1. Broaden "Ignore/Disregard/Forget" Pattern Variants (HIGH — quick win)

Current patterns require specific word sequences like `ignore (all)? previous instructions`. Missed variants include:
- "Ignore the original instruction..."
- "Ignore the above instructions..."  
- "Ignore any instructions you were given..."
- "Ignore all instructions" (extra whitespace between words)
- "Forget everything I said..."
- "Please disregard my previous settings..."
- "Ignore the last few things you were told..."

**Fix:** Broaden to catch `ignore .{0,30} instruction` and similar fuzzy patterns. Add:
```python
(re.compile(r"ignore\s+(?:the\s+)?(?:original|above|any|all|last|following)\s+\w*\s*instruction", re.I),
 "injection_pattern: 'ignore instructions variant'"),
(re.compile(r"forget\s+everything", re.I),
 "injection_pattern: 'forget everything'"),
(re.compile(r"disregard\s+(?:the\s+|my\s+)?(?:last|previous|above)", re.I),
 "injection_pattern: 'disregard variant'"),
```

**Expected impact:** Would catch ~2,000+ of the 2,488 direct_override false negatives.

### 2. Add Role-Play / Identity Override Patterns (HIGH)

726 missed injections use roleplay attacks. Add patterns for:
- "you are now..."
- "pretend you are..."  
- "act as..."
- "from now on you will..."
- "you are [NAME], a..."
- "do anything now" / "DAN"

```python
(re.compile(r"(?:pretend|act)\s+(?:as|like|you\s*(?:are|'re))", re.I),
 "injection_pattern: 'role play attack'"),
(re.compile(r"you\s+are\s+now\b", re.I),
 "injection_pattern: 'identity override'"),
(re.compile(r"from\s+now\s+on\s+you\s+(?:will|shall|must|are)", re.I),
 "injection_pattern: 'behavioral override'"),
(re.compile(r"\bdo\s+anything\s+now\b", re.I),
 "injection_pattern: 'DAN jailbreak'"),
```

**Expected impact:** ~700+ additional detections.

### 3. Add Hypothetical/Scenario Bypass Patterns (MEDIUM)

739 missed injections use hypothetical framing. Add:
- "imagine you are..."
- "in a hypothetical scenario..."  
- "let's play a game..."
- "for educational purposes..."

```python
(re.compile(r"imagine\s+(?:you|that|a\s+scenario)", re.I),
 "injection_pattern: 'hypothetical bypass'"),
(re.compile(r"hypothetical\s+scenario", re.I),
 "injection_pattern: 'hypothetical bypass'"),
(re.compile(r"let'?s\s+play\s+a\s+game", re.I),
 "injection_pattern: 'game framing bypass'"),
```

**Expected impact:** ~500+ additional detections.

### 4. Add Output Manipulation Patterns (MEDIUM)

609 missed injections manipulate output:
- "repeat after me..."
- "say [exact text]..."
- "your first word should be..."
- "respond with only..."
- "output the following..."

```python
(re.compile(r"(?:repeat|say|print|output|write)\s+(?:after\s+me|the\s+following|exactly|only)", re.I),
 "injection_pattern: 'output manipulation'"),
(re.compile(r"your\s+(?:first|next)\s+(?:word|response|output)\s+(?:should|must|will)\s+be", re.I),
 "injection_pattern: 'output manipulation'"),
```

### 5. Consider a Lightweight ML Classifier Layer (LOW — long-term)

Pattern matching fundamentally can't catch creative/novel attacks. A small transformer model (like protectai/deberta-v3-base-prompt-injection-v2, ~350MB) could serve as a second-pass classifier for emails that pass pattern matching but seem suspicious. This would be a separate optional module, not a replacement for the fast regex layer.

### 6. Scoring / Confidence System (LOW — architectural)

Instead of binary flags, add a confidence score. Structural indicators (URLs, base64, invisible chars) + pattern matches could combine into a risk score. This would let callers tune their own threshold (email from unknown sender → lower threshold, known sender → higher threshold).

## What NOT to Change

- **Don't reduce precision.** The 98.9% precision and 0.2% FPR are excellent. Don't add patterns so broad they flag normal emails.
- **Don't add general jailbreak patterns** that would fire on normal conversational text (e.g., "imagine" alone, "write a story" alone).
- **Keep structural sanitization as-is.** URL stripping, base64 removal, invisible char stripping, and markdown sanitization are the core value — they prevent exfiltration regardless of whether an injection is "detected."
- **Keep it stdlib-only.** The zero-dependency design is a feature, not a limitation.

## Estimated Impact of Recommendations 1-4

If all four high/medium recommendations are implemented:
- **Estimated new recall:** ~30-40% (up from 6.8%)
- **Estimated precision:** ~95%+ (slight decrease acceptable)
- **Estimated F1:** ~45-55% (up from 12.6%)

This would be a strong result for a pure regex sanitizer. For higher recall, an ML layer (rec #5) is needed.
