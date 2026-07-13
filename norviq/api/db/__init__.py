# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Database models and session exports."""

from norviq.api.db.models import (
    AgentRegistryEntry,
    AssetGraph,
    AttackPath,
    AuditLogEntry,
    Base,
    Policy,
    PolicyVersion,
    User,
)
from norviq.api.db.session import (
    bump_policy_version,
    close_db,
    create_tables,
    get_session,
    init_db,
    lock_policy_for_update,
    upsert_policy,
)

__all__ = [
    "AgentRegistryEntry",
    "AssetGraph",
    "AttackPath",
    "AuditLogEntry",
    "Base",
    "Policy",
    "PolicyVersion",
    "User",
    "bump_policy_version",
    "close_db",
    "create_tables",
    "get_session",
    "init_db",
    "lock_policy_for_update",
    "upsert_policy",
]
