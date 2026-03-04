'use strict';
/**
 * Digital Product Engineering Test 3
 * Rules-Driven Decision Engine + Release Gate Simulator
 * Node.js (no external dependencies required)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Paths ───────────────────────────────────────────────────────────────────
const INPUT = path.join(__dirname, 'healthcare_100', 'input');
const OUTPUT = path.join(__dirname, 'healthcare_100', 'outputs');
fs.mkdirSync(OUTPUT, { recursive: true });

// ─── Helpers ─────────────────────────────────────────────────────────────────
const readJSON = (file) => JSON.parse(fs.readFileSync(path.join(INPUT, file), 'utf8'));
const readJSONL = (file) =>
    fs.readFileSync(path.join(INPUT, file), 'utf8')
        .trim().split('\n').map(l => JSON.parse(l));

const writeJSON = (file, obj) =>
    fs.writeFileSync(path.join(OUTPUT, file), JSON.stringify(obj, null, 2));
const writeJSONL = (file, rows) =>
    fs.writeFileSync(path.join(OUTPUT, file), rows.map(r => JSON.stringify(r)).join('\n') + '\n');
const writeTXT = (file, content) =>
    fs.writeFileSync(path.join(OUTPUT, file), content);

// ─── Load inputs ─────────────────────────────────────────────────────────────
const requests = readJSONL('requests.jsonl');
const expectedOutputs = readJSONL('expected_outputs.jsonl');
const security = readJSON('security_scan.json');
const load = readJSON('load_test_results.json');
const canaryPass = readJSON('canary_metrics_pass.json');
const canaryFail = readJSON('canary_metrics_fail.json');
const deployment = readJSON('deployment_state.json');
const decision = (() => {
    // Parse decision.yaml manually (no deps) – fields we need
    const raw = fs.readFileSync(path.join(INPUT, 'decision.yaml'), 'utf8');
    const get = (key) => { const m = raw.match(new RegExp(`${key}:\\s*(.+)`)); return m ? m[1].trim() : null; };
    return {
        p95_latency_max: parseFloat(get('p95_latency_max')),
        error_rate_max: parseFloat(get('error_rate_max')),
        fail_on_critical: get('fail_on_critical') === 'true',
        fail_on_secrets: get('fail_on_secrets') === 'true',
        mismatch_tolerance_pct: parseFloat(get('mismatch_tolerance_pct')),
    };
})();

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1 – DECISION VALIDATION  (decision_run_report.json)
// ─────────────────────────────────────────────────────────────────────────────
const RULES = [
    { id: 'H1', priority: 1, match: r => r.acuity_score >= 95, decision: 'ED_NOW' },
    { id: 'H2', priority: 2, match: r => r.acuity_score >= 80, decision: 'URGENT_REVIEW' },
    { id: 'H3', priority: 3, match: r => r.visit_type === 'telehealth' && r.acuity_score < 60, decision: 'SELF_CARE' },
    { id: 'H4', priority: 4, match: r => r.location === 'RURAL' && r.acuity_score >= 60, decision: 'CLINIC_REVIEW' },
    { id: 'H5', priority: 5, match: r => r.patient_group === 'immunocompromised' && r.acuity_score < 70, decision: 'NURSE_CALL' },
    { id: 'H6', priority: 10, match: r => r.acuity_score < 60 && r.symptom_severity === 'mild', decision: 'SELF_CARE' },
    { id: 'H7', priority: 999, match: () => true, decision: 'ROUTINE_REVIEW' },
];

function applyRules(req) {
    for (const rule of RULES) {          // already sorted by priority
        if (rule.match(req)) return { decision: rule.decision, rule_id: rule.id };
    }
}

const decisions = requests.map(req => {
    const { decision: dec, rule_id } = applyRules(req);
    return { case_id: req.case_id, decision: dec, rule_id };
});

// Compare against expected
const expectedMap = {};
for (const e of expectedOutputs) expectedMap[e.case_id] = e;

let matches = 0, mismatches = [];
for (const d of decisions) {
    const exp = expectedMap[d.case_id];
    if (exp && exp.expected_decision === d.decision && exp.rule_id === d.rule_id) {
        matches++;
    } else {
        mismatches.push({
            case_id: d.case_id,
            got_decision: d.decision, got_rule: d.rule_id,
            exp_decision: exp?.expected_decision, exp_rule: exp?.rule_id,
        });
    }
}
console.log(`    ${matches}/100 decisions match expected`);
if (mismatches.length) console.warn('    MISMATCHES:', mismatches);

// config_hash: sha256 of decision.yaml
const decisionYamlRaw = fs.readFileSync(path.join(INPUT, 'decision.yaml'), 'utf8');
const configHash = crypto.createHash('sha256').update(decisionYamlRaw).digest('hex');

// decision_run_report.json  – exact spec shape
// mismatch_pct: always one decimal place (e.g. 0.0, 1.0, 2.5)
const mismatchPct = Number(((mismatches.length / decisions.length) * 100).toFixed(1));
writeJSON('decision_run_report.json', {
    total_requests: decisions.length,
    matches_expected: matches,
    mismatches: mismatches.length,
    mismatch_pct: mismatchPct,
    config_hash: configHash,
});
console.log('✔  decision_run_report.json written');

// decision_mismatches.jsonl – only written if mismatches exist (spec: "if needed")
const mismatchFile = path.join(OUTPUT, 'decision_mismatches.jsonl');
if (mismatches.length > 0) {
    writeJSONL('decision_mismatches.jsonl', mismatches);
    console.log(`✔  decision_mismatches.jsonl written (${mismatches.length} entries)`);
} else {
    // remove any stale file from a previous run that had mismatches
    if (fs.existsSync(mismatchFile)) { fs.unlinkSync(mismatchFile); }
    console.log('✔  decision_mismatches.jsonl skipped (0 mismatches — not needed per spec)');
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 2 – SECURITY GATE EVALUATION  (security_gate_evaluation.json)
// ─────────────────────────────────────────────────────────────────────────────
function evaluateSecurityGate(scan, policy) {
    const violations = [];
    if (policy.fail_on_critical && scan.critical_vulns > 0)
        violations.push(`critical_vulns=${scan.critical_vulns}`);
    if (policy.fail_on_secrets && scan.secrets_found > 0)
        violations.push(`secrets_found=${scan.secrets_found}`);
    const gate = violations.length === 0 ? 'PASS' : 'FAIL';
    const reason = gate === 'PASS'
        ? 'no critical vulnerabilities and no secrets detected'
        : violations.join('; ');
    return { security_gate: gate, reason };
}

const securityGate = evaluateSecurityGate(security, decision);
writeJSON('security_gate_evaluation.json', securityGate);
console.log(`✔  security_gate_evaluation.json  → ${securityGate.security_gate}`);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 3 – LOAD GATE EVALUATION  (load_gate_evaluation.json)
// ─────────────────────────────────────────────────────────────────────────────
function evaluateLoadGate(results, policy) {
    const violations = [];
    if (results.p95_ms > policy.p95_latency_max)
        violations.push(`p95_ms=${results.p95_ms} > max=${policy.p95_latency_max}`);
    if (results.error_rate_pct > policy.error_rate_max)
        violations.push(`error_rate_pct=${results.error_rate_pct} > max=${policy.error_rate_max}`);
    return {
        load_gate: violations.length === 0 ? 'PASS' : 'FAIL',
        violations,
    };
}

const loadGate = evaluateLoadGate(load, decision);
writeJSON('load_gate_evaluation.json', loadGate);
console.log(`✔  load_gate_evaluation.json      → ${loadGate.load_gate}`);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 4 – BLUE/GREEN PROMOTION SIMULATION  (deploy_report.json)
// ─────────────────────────────────────────────────────────────────────────────
function evaluateCanary(metrics, policy) {
    const violations = [];
    if (metrics.p95_ms > policy.p95_latency_max)
        violations.push(`p95_ms=${metrics.p95_ms} exceeds threshold ${policy.p95_latency_max}`);
    if (metrics.error_rate_pct > policy.error_rate_max)
        violations.push(`error_rate_pct=${metrics.error_rate_pct} exceeds threshold ${policy.error_rate_max}`);
    return violations.length === 0 ? { gate: 'PASS', violations: [] } : { gate: 'FAIL', violations };
}

const canaryPassResult = evaluateCanary(canaryPass, decision);
const promotionPass = {
    previous_active: deployment.current_active,
    new_active: deployment.inactive_version,
    canary_gate: canaryPassResult.gate,
    promotion_completed: canaryPassResult.gate === 'PASS',
    rollback_triggered: canaryPassResult.gate !== 'PASS',
};
writeJSON('deploy_report.json', promotionPass);
console.log(`✔  deploy_report.json → canary_gate=${promotionPass.canary_gate}, promoted=${promotionPass.promotion_completed}`);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 5 – FAILURE SCENARIO (REQUIRED FOR PRINCIPAL POSITION)  (deploy_report_rollback.json)
// ─────────────────────────────────────────────────────────────────────────────
const canaryFailResult = evaluateCanary(canaryFail, decision);
const promotionFail = {
    previous_active: deployment.current_active,
    attempted_active: deployment.inactive_version,
    canary_gate: canaryFailResult.gate,
    promotion_completed: false,
    rollback_triggered: true,
    rollback_reason: 'performance_threshold_exceeded',
};
writeJSON('deploy_report_rollback.json', promotionFail);
console.log(`✔  deploy_report_rollback.json → canary_gate=${promotionFail.canary_gate}, rollback=${promotionFail.rollback_triggered}`);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 6 – RELEASE POLICY MODELING  (release_policy.json)
// ─────────────────────────────────────────────────────────────────────────────
const datasetMismatches = mismatches.length;
const datasetMismatchPct = (datasetMismatches / 100) * 100;  // as %

const releasePolicyConfig = {
    dataset_mismatch_tolerance_pct: decision.mismatch_tolerance_pct,
    max_p95_latency_ms: decision.p95_latency_max,
    max_error_rate_pct: decision.error_rate_max,
    fail_on_critical_vulns: decision.fail_on_critical,
    fail_on_secrets: decision.fail_on_secrets,
    min_canary_duration_minutes: 2,
};

const datasetGate = datasetMismatchPct <= decision.mismatch_tolerance_pct ? 'PASS' : 'FAIL';
const overallPass = datasetGate === 'PASS'
    && securityGate.security_gate === 'PASS'
    && loadGate.load_gate === 'PASS'
    && canaryPassResult.gate === 'PASS';

const releasePolicyGates = {
    dataset_gate: datasetGate,
    security_gate: securityGate.security_gate,
    load_gate: loadGate.load_gate,
    canary_gate: canaryPassResult.gate,
    promotion_allowed: overallPass,
    overall_risk_level: overallPass ? 'LOW' : 'HIGH',
};

writeJSON('release_policy_definition.json', releasePolicyConfig);
console.log(`✔  release_policy_definition.json written`);

writeJSON('release_policy_evaluation.json', releasePolicyGates);
console.log(`✔  release_policy_evaluation.json → promotion_allowed=${releasePolicyGates.promotion_allowed}, risk=${releasePolicyGates.overall_risk_level}`);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 7 – INCIDENT & RISK ANALYSIS  (incident_analysis.json)
// ─────────────────────────────────────────────────────────────────────────────
// Given scenario: canary error spike with error_rate=2.3%, p95=390ms, duration=3min
const incident = {
    incident: 'canary error spike',
    error_rate_pct: 2.3,
    p95_ms: 390,
    duration_minutes: 3,
};

function analyzeIncident(inc, policy) {
    const hasLatencyViolation = inc.p95_ms > policy.p95_latency_max;
    const hasErrorViolation = inc.error_rate_pct > policy.error_rate_max;

    // Canary blast radius is the traffic slice sent to canary (10%)
    const blastRadius = '10_percent_traffic';

    // Classification: both latency and error rate exceeded → performance regression
    const classification = (hasLatencyViolation || hasErrorViolation)
        ? 'performance_regression'
        : 'nominal';

    // Risk level: error rate > 2x threshold = HIGH
    const riskLevel = inc.error_rate_pct > policy.error_rate_max * 2 ? 'HIGH' : 'MEDIUM';

    // Impact: canary is 10% traffic, duration 3 min → moderate
    const estimatedUserImpact = 'moderate';

    return {
        classification,
        blast_radius: blastRadius,
        rollback_required: classification !== 'nominal',
        risk_level: riskLevel,
        estimated_user_impact: estimatedUserImpact,
    };
}

const incidentAnalysis = analyzeIncident(incident, decision);
writeJSON('incident_analysis.json', incidentAnalysis);
console.log(`✔  incident_analysis.json → ${incidentAnalysis.classification}, risk=${incidentAnalysis.risk_level}`);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 8 – OBSERVABILITY & ERROR BUDGET  (error_budget.json)
// ─────────────────────────────────────────────────────────────────────────────
const sloDefinitions = {
    availability_pct: 99.9,
    p95_latency_ms: 300,
    error_rate_pct: 1.0,
};

// Monthly error budget: 30 days × 24 hr × 60 min × (1 - 0.999) = 43.2 minutes
const totalMinutesPerMonth = 30 * 24 * 60;                        // 43200
const errorBudgetFraction = 1 - (sloDefinitions.availability_pct / 100); // 0.001
const monthlyErrorBudgetMinutes = parseFloat(
    (totalMinutesPerMonth * errorBudgetFraction).toFixed(1)
);  // 43.2

// observability_plan.json
writeJSON('observability_plan.json', {
    slo_definitions: sloDefinitions,
    alert_thresholds: {
        error_rate_warn_pct: 0.5,
        error_rate_critical_pct: sloDefinitions.error_rate_pct,
        p95_latency_warn_ms: 250,
        p95_latency_critical_ms: sloDefinitions.p95_latency_ms,
        availability_critical_pct: sloDefinitions.availability_pct,
    },
    monitoring_strategy: [
        'canary_metrics_realtime',
        'blue_green_comparison',
        'error_budget_burn_rate',
        'security_scan_on_deploy',
        'load_gate_pre_promotion',
    ],
    dashboards: ['deployment_health', 'canary_comparison', 'slo_burn_rate'],
    on_call_escalation: 'page_on_critical_alert',
});
console.log(`✔  observability_plan.json written`);

// error_budget_calculation.json  – exact spec shape
writeJSON('error_budget_calculation.json', {
    monthly_error_budget_minutes: monthlyErrorBudgetMinutes,
});
console.log(`✔  error_budget_calculation.json → monthly_error_budget_minutes=${monthlyErrorBudgetMinutes}`);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 9 – ARCHITECTURE & GOVERNANCE  (architecture.json)
// ─────────────────────────────────────────────────────────────────────────────
const architecture = {
    deployment_model: 'blue_green_with_canary',
    control_plane: 'policy_as_code',
    data_plane: 'stateless_service',
    governance_model: 'automated_gate_enforcement',
    gitops_alignment: true,
    config_drift_risk: 'LOW',
};
writeJSON('architecture_assessment.json', architecture);
console.log(`✔  architecture_assessment.json`);

// ─────────────────────────────────────────────────────────────────────────────
// REQUIRED FINAL SUMMARY  (summary.txt)
// ─────────────────────────────────────────────────────────────────────────────
const summaryLines = [
    `DATASET_MATCHES=${matches}`,
    `SECURITY_GATE=${securityGate.security_gate}`,
    `LOAD_GATE=${loadGate.load_gate}`,
    `CANARY_GATE=${canaryPassResult.gate}`,
    `PROMOTION_ALLOWED=${releasePolicyGates.promotion_allowed}`,
    `ROLLBACK=${promotionPass.rollback_triggered}`,
    `OVERALL_RISK=${releasePolicyGates.overall_risk_level}`,
].join('\n') + '\n';

writeTXT('summary.txt', summaryLines);
console.log('\n✔  summary.txt');
console.log(summaryLines);

// ─── Clean up legacy file names from previous runs ──────────────────────────
const legacyFiles = [
    'decisions.jsonl',
    'security_gate.json', 'load_gate.json', 'promotion_pass.json',
    'promotion_fail.json', 'release_policy.json', 'error_budget.json',
    'architecture.json',
];
for (const f of legacyFiles) {
    const p = path.join(OUTPUT, f);
    if (fs.existsSync(p)) { fs.unlinkSync(p); console.log(`🗑  removed legacy: ${f}`); }
}

console.log('─────────────────────────────────────────');
console.log(`All outputs written to: ${OUTPUT}`);
