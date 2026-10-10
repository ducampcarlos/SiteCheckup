# ADR 0004: A transparent additive score with a grade cap

* Status: accepted

## Context

Non-technical stakeholders want one number or letter; engineers want to know why. Weighted, normalised or "risk-model" scores look scientific but are impossible to explain in a status meeting, and they invite arguing about the model rather than fixing the findings.

## Decision

`score = max(0, 100 - sum(penalty))` over failed findings with penalties high 15, medium 6, low 2, info 0. Grades come from fixed bands, then a cap applies: any failed high-severity finding limits the grade to C, any medium to B. The formula and worked examples are in [docs/scoring.md](../scoring.md) and the constants are unit-tested.

## Consequences

* Anyone can recompute the score from the findings table.
* The cap prevents a pile of passing checks from hiding one serious problem.
* The score is relative to *this tool's checks*. It says nothing about how hard the site is to attack and must not be marketed as such.
* Changing constants changes historical comparability, so any change is a minor-version event in the changelog.
