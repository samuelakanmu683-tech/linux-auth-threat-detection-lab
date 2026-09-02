# Detection Rules

## AUTH-001 — SSH Brute Force
**Severity:** High  
Trigger: at least five failed authentication events from the same source within five minutes.

## AUTH-002 — Successful Login Following Repeated Failures
**Severity:** High  
Trigger: a successful authentication follows at least three failures for the same user and source within ten minutes.

This is a correlation signal, not proof of compromise.

## AUTH-003 — Multiple Sources Targeting One Account
**Severity:** Medium  
Trigger: at least three distinct source addresses generate failed authentication events for one account.

## AUTH-004 — Privileged Account Authentication
**Severity:** Medium  
Trigger: authentication involving `root`, `admin`, or `administrator`.

Context is required because legitimate administrative activity can generate this event.
