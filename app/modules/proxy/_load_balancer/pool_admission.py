"""Hard pool admission applies before every cached or fresh selection."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from app.core.pool_policy import pool_account_allowed, quota_admits

if TYPE_CHECKING:
    from app.modules.proxy.load_balancer import SelectionInputs


def apply_pool_policy(inputs: SelectionInputs, required_account_id: str | None) -> SelectionInputs:
    return replace(
        inputs,
        accounts=[
            account
            for account in inputs.accounts
            if pool_account_allowed(account)
            and quota_admits(
                inputs.latest_primary.get(account.id),
                inputs.latest_secondary.get(account.id),
                bound=account.id == required_account_id,
            )
        ],
        continuity_owner_candidates=[
            account for account in inputs.effective_continuity_owner_candidates if pool_account_allowed(account)
        ],
        sticky_mutation_authority_account_ids=(
            inputs.effective_sticky_mutation_authority_account_ids
            - frozenset(account.id for account in (inputs.runtime_accounts or []) if not pool_account_allowed(account))
        ),
    )
