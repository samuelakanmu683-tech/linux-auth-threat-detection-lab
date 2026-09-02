# Incident Investigation Report

## Case ID
`SOC-2026-001`

## Classification
**Simulated / Training Exercise**

## Executive Summary
The synthetic authentication dataset contains suspicious authentication patterns, including repeated failed SSH authentication from a single source, a successful authentication following repeated failures, multiple source addresses targeting an administrative account, and privileged-account activity.

The evidence supports opening an investigation. The dataset alone does not prove that an account was compromised.

## Key Findings

### Finding 1 — Repeated Authentication Failures
Source `203.0.113.50` generated repeated failures against the `admin` account.

**Assessment:** High-priority authentication anomaly.

### Finding 2 — Successful Authentication After Failures
The same source later successfully authenticated as `admin`.

**Assessment:** Correlated high-priority event requiring account and session validation.

### Finding 3 — Multiple Sources Targeting an Administrative Account
The `administrator` account received failed authentication attempts from multiple source addresses.

**Assessment:** Medium-priority distributed targeting pattern.

### Finding 4 — Privileged Authentication
Authentication activity involving `root` was observed.

**Assessment:** Medium-priority event requiring confirmation of authorized administrative activity.

## Recommended Response
1. Validate whether the affected accounts were expected targets of administrative activity.
2. Review authentication records around the alert timestamps.
3. Review successful sessions and commands for affected accounts.
4. Confirm source ownership and expected network location.
5. If compromise is confirmed, follow organizational containment and credential-reset procedures.
6. Improve monitoring for repeated failures and privileged authentication.

## Limitations
This investigation uses synthetic data and has no endpoint telemetry, process information, asset inventory, identity-provider context, or threat-intelligence enrichment.

## Analyst Conclusion
The observed patterns warrant investigation and demonstrate how authentication telemetry can be correlated into actionable SOC detections. A production conclusion would require additional evidence.
