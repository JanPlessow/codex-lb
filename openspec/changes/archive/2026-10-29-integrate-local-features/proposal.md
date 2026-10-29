# Integrate local features into the shared main branch

## Why

The published local feature snapshot predates current main. Merge it without losing newer upstream authentication, database, refresh, or retry behavior.

## What Changes

Adapt account browsers, Orca terminal links, account-aware routing, native replay, pool protections, measured quotas, and the current dispatcher to current main. Preserve historical deployed migrations with an additive join and compatibility validation. Explicit permissions protect local host actions under the current dashboard roles.

## Impact

The personal fork gains the complete requested features. The running local service is not redeployed. Existing data must upgrade from both main and the prior local feature schema without losing accounts, browser ownership, or credentials.

## CI compatibility repairs

Cloud checks exposed inherited dependency advisories, legacy-schema bootstrap replay of the new browser branch, and stale probe test doubles. Repair these blockers without suppressing security checks or dropping supported compression. Verify fresh and legacy-ledger recovery, both database engines, the routing test contracts, and locked dependency security scans before merge.
