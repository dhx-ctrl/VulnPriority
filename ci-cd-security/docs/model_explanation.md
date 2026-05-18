# Model explanation

VulnPriority uses a dual-model architecture.

The two models have different purposes and should not be described as the same type of model.

## Model 1 — Clean leakage-safe model

### Purpose

The clean model is the scientifically defensible model. It is used as a strict confidence signal and as evidence that the project considered data leakage.

### What it avoids

The clean model excludes direct or shortcut signals such as:

- EPSS score;
- EPSS percentile;
- CVSS score;
- CVSS vector;
- CVSS subcomponents;
- scanner severity;
- raw advisory IDs;
- raw CVE/GHSA identifiers as direct labels;
- exploit references;
- source metadata;
- known exploited flags used as direct labels.

### Dashboard role

The clean model appears as:

```text
Clean /100
```

It is a secondary confidence signal.

It should not be used as a hard gate to hide findings.

It can help upgrade a finding to:

```text
Review Soon
```

but should not by itself force:

```text
Review First
```

### Correct interpretation

The clean model supports this claim:

> A leakage-aware model can still learn useful vulnerability prioritization patterns from non-obvious metadata and engineered features.

## Model 2 — Operational EPSS ranker

### Purpose

The operational ranker is the practical queue-sorting model.

It is used to order findings by likely exploitation relevance and to compare prioritization against CVSS-only sorting.

### Target

The operational ranker predicts an EPSS-based target, for example:

```text
EPSS >= 0.05
```

### Feature policy

The operational ranker may use CVSS and vulnerability metadata because its target is not CVSS.

This is not the same as predicting CVSS from CVSS.

However, this model is not presented as the strict leakage-safe model.

### Dashboard role

The operational ranker appears as:

```text
Rank /100
```

It is the primary sorting score in the dashboard.

The dashboard uses it for:

- Review Queue ordering;
- Findings table ranking;
- Scan History product-level status;
- Review First filtering;
- notification logic.

### Correct interpretation

The correct claim is:

> The operational ranker improves prioritization over CVSS alone by combining CVSS with additional vulnerability and package metadata.

The incorrect claim would be:

> The operational ranker is fully leakage-safe.

That should not be said.

## Priority labels

| Label | Rule | Explanation |
|---|---|---|
| Review First | Operational alert is true or Rank /100 >= 70 | Highest review priority |
| Review Soon | Rank /100 >= 30 or clean model flag is true | Important but not the top queue |
| Severity Watch | Scanner severity High/Critical while Rank /100 < 30 | Keep visible because scanner severity is high |
| Backlog | Lower-scoring findings | Lower operational priority |

## Scanner severity vs AI priority

Scanner severity and AI priority answer different questions.

Scanner severity answers:

```text
How severe is the technical impact according to the scanner or CVSS?
```

AI priority answers:

```text
Which findings should the analyst review first?
```

Therefore, a High scanner severity finding can still have a low operational rank if the exploitation likelihood appears lower.

## Why two models are useful

The two-model setup balances academic defensibility and operational usefulness.

| Model | Strength | Limitation |
|---|---|---|
| Clean leakage-safe model | Stronger against leakage criticism | Less powerful as a ranking tool |
| Operational EPSS ranker | Better practical prioritization and CVSS comparison | Not fully leakage-safe |

## Final positioning for the report

Use this wording:

> The project uses two separate models for different purposes. The clean minimal model is the leakage-safe scientific model and excludes direct label or severity shortcut features. The operational EPSS ranker is used for practical dashboard ordering. It is not presented as leakage-safe; instead, it is evaluated as a ranking model that combines CVSS with additional metadata to improve over CVSS-only prioritization.
