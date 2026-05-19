# Model Explanation

VulnPriority uses a dual-model architecture.

The two models have different purposes and should not be described as the same type of model.

## Model 1 — Clean Leakage-Safe Model

### Purpose

The clean model is the stricter scientific confidence signal. It exists to show that the project considered data leakage and avoided direct shortcut features.

### What it avoids

The clean model excludes direct or shortcut signals such as:

- EPSS score
- EPSS percentile
- CVSS score
- CVSS vector
- CVSS subcomponents
- scanner severity
- exploit references
- source metadata
- known exploited flags used as direct labels

### Dashboard role

The clean model appears as:

Clean /100

It is a secondary confidence signal.

It should not be used as a hard gate to hide findings.

It can help upgrade a finding to Review Soon, but should not by itself force Review First.

### Correct interpretation

The clean model supports this claim:

A leakage-aware model can still learn useful vulnerability prioritization patterns from non-obvious metadata and engineered features.

## Model 2 — Operational EPSS Ranker

### Purpose

The operational EPSS ranker is the practical queue-sorting model.

It is used to order findings by likely exploitation relevance and to compare prioritization against CVSS-only sorting.

### Target

The operational ranker predicts an EPSS-based target.

For the current model, the label is based on:

EPSS score >= 0.10

### Leakage-hardening

The current operational ranker was hardened compared with the earlier operational version.

It removes:

- package_name
- raw cvss_vector
- feat_package_scope

These features were removed because they could memorise package-level or near-unique vulnerability patterns.

The current model also uses:

- temporal train/test split
- CWE-family bucketing
- label-shuffle sanity check
- permutation-importance reporting

### Dashboard role

The operational ranker appears as:

Rank /100

It is the primary sorting score in the dashboard.

The dashboard uses it for:

- Review Queue ordering
- Findings table ranking
- Scan History product-level status
- Review First filtering
- notification logic

### Correct interpretation

The correct claim is:

The operational ranker improves over CVSS-only prioritization by combining CVSS with additional vulnerability and advisory metadata.

The incorrect claim would be:

The operational ranker is the same as the clean leakage-safe model.

The operational ranker is leakage-hardened, but it is still the practical ranking model, while the clean model remains the stricter scientific confidence signal.

## Priority Labels

| Label | Rule | Explanation |
|---|---|---|
| Review First | Operational alert is true or Rank /100 is high enough for immediate attention | Highest review priority |
| Review Soon | Medium operational priority or strict clean-model confidence | Important but not the top queue |
| Severity Watch | Scanner severity High/Critical while operational priority is lower | Kept visible because scanner severity is high |
| Backlog | Lower-scoring findings | Lower operational priority |

## Scanner Severity vs AI Priority

Scanner severity and AI priority answer different questions.

Scanner severity answers:

How severe is the technical impact according to the scanner or CVSS?

AI priority answers:

Which findings should the analyst review first?

Therefore, a High scanner severity finding can still have a lower operational rank if the exploitation likelihood appears lower.

## Why Two Models Are Useful

The two-model setup balances academic defensibility and operational usefulness.

| Model | Strength | Limitation |
|---|---|---|
| Clean leakage-safe model | Stronger against leakage criticism | Less powerful as a ranking tool |
| Operational EPSS ranker | Better practical prioritization and CVSS comparison | Should be interpreted as a ranking model, not a strict yes/no classifier |

## Final Positioning for the Report

Use this wording:

The project uses two separate models for different purposes. The clean model is the stricter leakage-safe confidence signal. The operational EPSS ranker is the practical dashboard ordering model. The current ranker was hardened by removing high-cardinality and near-unique memorisation features, and it is evaluated as a ranking model against CVSS-only prioritization.