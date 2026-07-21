# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Pydantic schemas for Asset Graph and Attack Graph endpoints."""

from pydantic import BaseModel


class AssetNode(BaseModel):
    id: str
    type: str
    name: str
    properties: dict


class AssetEdge(BaseModel):
    source: str
    target: str
    type: str
    weight: float
    properties: dict


class AssetGraphResponse(BaseModel):
    nodes: list[AssetNode]
    edges: list[AssetEdge]
    # Namespaces represented in this response (multi-namespace union support; additive — [] for legacy
    # single-namespace responses with no data).
    namespaces: list[str] = []
    # Number of synthetic/probe agents excluded from this response (drives the "N test/probe agents
    # hidden — Show" chip). 0 when none were hidden or when include_synthetic=true.
    synthetic_hidden: int = 0
    # Number of real-but-awaiting (registered, never observed) agents excluded by default (drives the
    # "Awaiting (N) — Show" chip). 0 when none or when include_awaiting=true.
    awaiting_hidden: int = 0


class AttackStep(BaseModel):
    step_num: int
    node_id: str
    action: str
    policy_check: str


class AttackPath(BaseModel):
    path_id: str
    source_id: str
    target_id: str
    steps: list[AttackStep]
    risk_score: float
    severity: str
    mitre_techniques: list[str]
    blocked_by_policy: bool


class AttackPathsResponse(BaseModel):
    paths: list[AttackPath]
    nodes: list[AssetNode]
