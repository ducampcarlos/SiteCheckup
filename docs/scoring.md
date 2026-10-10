# Scoring

The audit produces a score from 0 to 100 and a letter grade. The formula is intentionally simple so that anyone can recompute it by hand from the findings list.

## Formula

```
score = max(0, 100 - sum(penalty[severity] for each FAILED finding))
```

| Severity | Penalty per failed finding |
| --- | ---: |
| high | 15 |
| medium | 6 |
| low | 2 |
| info | 0 |

Only checks with status `fail` count. Passed, skipped ("not applicable") and errored checks never change the score. A check can fail with a severity different from its default (for example a certificate that expires in 20 days is `medium`, one that expires in 3 days is `high`); the severity reported on the finding is the one used.

## Grade

The score maps to a grade band:

| Score | Grade |
| ---: | :---: |
| 90-100 | A |
| 80-89 | B |
| 70-79 | C |
| 60-69 | D |
| 0-59 | F |

Then a **cap** applies, so a single serious issue cannot hide behind many passing checks:

| Worst failed severity | Best possible grade |
| --- | :---: |
| high | C |
| medium | B |
| low / info only | A |

## Worked examples

| Failed findings | Score | Grade | Why |
| --- | ---: | :---: | --- |
| none | 100 | A | |
| 3 low | 94 | A | 100 - 3x2 |
| 1 medium | 94 | B | band says A, medium caps at B |
| 6 medium | 64 | D | 100 - 6x6 |
| 1 high | 85 | C | band says B, high caps at C |
| 3 high, 5 medium, 4 low | 17 | F | 100 - 45 - 30 - 8 (the demo lab's legacy site) |

## Why these numbers

* **A transparent model beats a clever one.** A client or developer can see exactly why the score is what it is and which fix moves it most.
* **High is 2.5x medium and 7.5x low.** One exposed `.env` should hurt more than several missing optional headers.
* **Info is free.** Informational notes (for example "`wp-login.php` is reachable") are context, not defects.
* **The cap encodes the real-world rule of thumb** that a site with an exposed credential file is not a "B site", whatever else is right about it.

The score is a communication aid for trend and prioritisation. It is **not** a measure of how hard the site is to attack. See [ADR 0004](adr/0004-scoring.md).

Constants live in `src/sitecheckup/audit/scoring.py` and are covered by tests.
