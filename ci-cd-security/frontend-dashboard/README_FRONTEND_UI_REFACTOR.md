# Frontend UI refactor patch

This patch moves generic UI components out of `DashboardPage.jsx` and into
`src/components/ui/`.

Created components:

- `GlassCard.jsx`
- `StatCard.jsx`
- `RiskPill.jsx`
- `ScannerPill.jsx`
- `PriorityPill.jsx`
- `SectionTitle.jsx`
- `EmptyPanel.jsx`

`DashboardPage.jsx` now imports these components instead of defining them inline.

Compatibility note:
`DashboardPage.jsx` still re-exports `GlassCard`, `StatCard`, and `SEV_COLORS`
so existing pages that import from `./DashboardPage.jsx` will not break immediately.
A later cleanup can update those imports directly to `../components/ui/GlassCard.jsx`.
