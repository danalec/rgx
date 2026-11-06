# EGM drift status

The gate reads this file, not the free-form drift reports. After an
`egm-drift-report` pass, update `date`, `report`, `unresolved` and
`decision` here; the dated reports in this directory are the audit trail
behind it. `decision` names the durable note where the finding was
resolved, and must exist. An `unresolved` count above zero fails the gate,
so a finding cannot be merged without a decision about the code. Use
`decision: pending` while findings are open; a clean status may not.

date: 2026-11-06
report: .egm/2026-11-06_DRIFT_REPORT.md
unresolved: 0
decision: AGENTS.md
