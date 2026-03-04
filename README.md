# Digital Product Engineering Test 3

## Rules-Driven Decision Engine + Release Gate Simulator

### How to Run

Navigate into the `engineering_test_3` folder first, then run the script:

```bash
cd "TEST 3/engineering_test_3"
node engine.js
```

No external dependencies. Pure Node.js (built-ins only). Outputs are written to
`healthcare_100/outputs/`.

---

## How Each Answer Was Derived

### Section 1 – Decision Validation (`decision_run_report.json`)

Each of the 100 requests in `requests.jsonl` was evaluated against `rules.csv` in
**strict priority order** (lowest priority number wins, first match exits):

| Rule | Priority | Condition                                                   | Decision           |
| ---- | -------- | ----------------------------------------------------------- | ------------------ |
| H1   | 1        | `acuity_score >= 95`                                      | `ED_NOW`         |
| H2   | 2        | `acuity_score >= 80`                                      | `URGENT_REVIEW`  |
| H3   | 3        | `visit_type = telehealth AND acuity_score < 60`           | `SELF_CARE`      |
| H4   | 4        | `location = RURAL AND acuity_score >= 60`                 | `CLINIC_REVIEW`  |
| H5   | 5        | `patient_group = immunocompromised AND acuity_score < 70` | `NURSE_CALL`     |
| H6   | 10       | `acuity_score < 60 AND symptom_severity = mild`           | `SELF_CARE`      |
| H7   | 999      | DEFAULT                                                     | `ROUTINE_REVIEW` |

Result: **100/100 decisions matched `expected_outputs.jsonl`** (0 mismatches).

---

### Section 2 – Security Gate Evaluation (`security_gate_evaluation.json`)

Policy sourced from `decision.yaml`:

- `fail_on_critical: true` → gate FAILs if `critical_vulns > 0`
- `fail_on_secrets: true` → gate FAILs if `secrets_found > 0`

`security_scan.json` reported 0 critical vulns and 0 secrets → **PASS**.

---

### Section 3 – Load Gate Evaluation (`load_gate_evaluation.json`)

Thresholds from `decision.yaml`:

- `p95_latency_max: 300 ms`
- `error_rate_max: 1.0%`

`load_test_results.json` reported `p95_ms=235` and `error_rate_pct=0.6` — both
under threshold → **PASS**.

---

### Section 4 – Blue/Green Promotion Simulation (`deploy_report.json`)

`deployment_state.json` shows `current_active=blue`, `inactive_version=green`.
`canary_metrics_pass.json` reported `p95_ms=265` (< 300) and `error_rate_pct=0.9`
(< 1.0) → canary gate **PASS** → promotion completed, rollback not triggered.

---

### Section 5 – Failure Scenario (Required for Principal Position) (`deploy_report_rollback.json`)

`canary_metrics_fail.json` reported `p95_ms=390` (> 300) and `error_rate_pct=1.4`
(> 1.0) → canary gate **FAIL** → promotion blocked, rollback triggered with reason
`performance_threshold_exceeded`.

---

### Section 6 – Release Policy Modeling (`release_policy_definition.json` + `release_policy_evaluation.json`)

The policy config is written to `release_policy_definition.json` (sourced from `decision.yaml`
defaults plus `min_canary_duration_minutes: 2`). Gate results are written separately to
`release_policy_evaluation.json`. All four gates (dataset, security, load, canary) passed
→ `promotion_allowed: true`, `overall_risk_level: LOW`.

Dataset mismatch tolerance = 1.0% (from `mismatch_tolerance_pct`); actual
mismatches = 0 → dataset gate **PASS**.

---

### Section 7 – Incident & Risk Analysis (`incident_analysis.json`)

Given the "canary error spike" scenario (`error_rate=2.3%`, `p95=390ms`,
`duration=3min`):

- **Classification**: `performance_regression` — both error rate and latency
  exceeded policy thresholds.
- **Blast radius**: `10_percent_traffic` — the canary slice was 10% (90/10 split).
- **Rollback required**: `true` — any gate violation mandates rollback per policy.
- **Risk level**: `HIGH` — error rate (2.3%) exceeded 2× the 1.0% threshold.
- **Estimated user impact**: `moderate` — limited to the 10% canary slice over 3
  minutes.

---

### Section 8 – Observability & Error Budget (`observability_plan.json` + `error_budget_calculation.json`)

SLO target: **99.9% availability** over 30 days.

```
monthly_error_budget_minutes = 30d × 24h × 60min × (1 − 0.999)
                              = 43,200 × 0.001
                              = 43.2 minutes
```

---

### Section 9 – Architecture & Governance (`architecture_assessment.json`)

Derived from the deployment model described across `decision.yaml`,
`deployment_state.json`, and the canary/promotion workflow:

| Field                 | Value                          | Rationale                                     |
| --------------------- | ------------------------------ | --------------------------------------------- |
| `deployment_model`  | `blue_green_with_canary`     | Active/inactive slots + canary split          |
| `control_plane`     | `policy_as_code`             | Rules and thresholds encoded in YAML/CSV      |
| `data_plane`        | `stateless_service`          | No session affinity required for routing      |
| `governance_model`  | `automated_gate_enforcement` | All gates evaluated programmatically          |
| `gitops_alignment`  | `true`                       | Policy files are version-controlled artifacts |
| `config_drift_risk` | `LOW`                        | Deterministic rules with no runtime mutation  |

---

## Output File Index

| File                               | Section | Description                                                    |
| ---------------------------------- | ------- | -------------------------------------------------------------- |
| `decision_run_report.json`       | 1       | Summary: total requests, matches, mismatch %, config hash      |
| `decision_mismatches.jsonl`      | 1       | Per-case mismatches — written only if mismatches exist        |
| `security_gate_evaluation.json`  | 2       | Vulnerability scan gate result + reason                        |
| `load_gate_evaluation.json`      | 3       | Performance load test gate result + violations                 |
| `deploy_report.json`             | 4       | Blue→Green promotion result (canary pass scenario)            |
| `deploy_report_rollback.json`    | 5       | Blue→Green promotion result (canary fail / rollback scenario) |
| `release_policy_definition.json` | 6       | Policy thresholds and configuration                            |
| `release_policy_evaluation.json` | 6       | Gate evaluation results + promotion_allowed + risk level       |
| `incident_analysis.json`         | 7       | Canary error spike classification and risk                     |
| `observability_plan.json`        | 8       | SLO definitions, alert thresholds, monitoring strategy         |
| `error_budget_calculation.json`  | 8       | Monthly error budget (43.2 min at 99.9% SLO)                   |
| `architecture_assessment.json`   | 9       | Deployment and governance model                                |
| `summary.txt`                    | Final   | Key=value summary for evaluator review                         |
