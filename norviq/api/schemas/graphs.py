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
