# Integrate local features into the shared main branch

## Why

The published local feature snapshot predates current main. Merge it without losing newer upstream authentication, database, refresh, or retry behavior.

## What Changes

Adapt account browsers, Orca terminal links, account-aware routing, native replay, pool protections, measured quotas, and the current dispatcher to current main. Preserve historical deployed migrations with an additive join and compatibility validation. Explicit permissions protect local host actions under the current dashboard roles.

## Impact

The personal fork gains the complete requested features. The running local service is not redeployed. Existing data must upgrade from both main and the prior local feature schema without losing accounts, browser ownership, or credentials.
