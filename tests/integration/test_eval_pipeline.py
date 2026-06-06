# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Integration tests for OPA subprocess behavior."""

from __future__ import annotations

import asyncio
import json
import shutil
import time

import pytest


@pytest.fixture
def opa_path() -> str:
    path = shutil.which("opa")
    if not path:
        pytest.skip("OPA binary not found on PATH")
    return path


@pytest.fixture
def sample_rego() -> str:
    return (
        "package norviq.strict\n"
        'default decision = "allow"\n'
        'decision = "block" { input.tool_name == "delete_record" }\n'
        'rule_id = "llm06" { input.tool_name == "delete_record" }\n'
        'reason = "blocked by policy" { input.tool_name == "delete_record" }\n'
    )


@pytest.fixture
def sample_rego_v0_syntax() -> str:
    return (
        "package norviq.strict\n"
        'default decision = "allow"\n'
        'decision = "block" { input.tool_name == "legacy_tool" }\n'
    )


@pytest.mark.asyncio
async def test_opa_subprocess_cold_start_under_2s(opa_path: str, sample_rego: str, tmp_path) -> None:
    policy_file = tmp_path / "policy.rego"
    policy_file.write_text(sample_rego, encoding="utf-8")
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps({"tool_name": "delete_record"}), encoding="utf-8")

    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        opa_path,
        "eval",
        "--format=json",
        "--v0-compatible",
        "--data",
        str(policy_file),
        "--input",
        str(input_file),
        "data.norviq.strict",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    elapsed = time.monotonic() - start

    assert proc.returncode == 0, stderr.decode("utf-8", errors="replace")
    assert elapsed < 2.0
    assert b'"result"' in stdout


@pytest.mark.asyncio
async def test_opa_v0_compat_flag_required(opa_path: str, sample_rego_v0_syntax: str, tmp_path) -> None:
    policy_file = tmp_path / "policy.rego"
    policy_file.write_text(sample_rego_v0_syntax, encoding="utf-8")

    proc_no_flag = await asyncio.create_subprocess_exec(
        opa_path,
        "eval",
        "--format=json",
        "--data",
        str(policy_file),
        "data.norviq.strict",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, _ = await proc_no_flag.communicate()

    proc_with_flag = await asyncio.create_subprocess_exec(
        opa_path,
        "eval",
        "--format=json",
        "--v0-compatible",
        "--data",
        str(policy_file),
        "data.norviq.strict",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_with, stderr_with = await proc_with_flag.communicate()

    assert proc_no_flag.returncode != 0
    assert proc_with_flag.returncode == 0, stderr_with.decode("utf-8", errors="replace")
    assert b'"result"' in stdout_with


@pytest.mark.asyncio
async def test_opa_query_path_returns_package_payload(opa_path: str, sample_rego: str, tmp_path) -> None:
    policy_file = tmp_path / "policy.rego"
    policy_file.write_text(sample_rego, encoding="utf-8")
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps({"tool_name": "delete_record"}), encoding="utf-8")

    proc = await asyncio.create_subprocess_exec(
        opa_path,
        "eval",
        "--format=json",
        "--v0-compatible",
        "--data",
        str(policy_file),
        "--input",
        str(input_file),
        "data.norviq.strict",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    assert proc.returncode == 0, stderr.decode("utf-8", errors="replace")
    parsed = json.loads(stdout.decode("utf-8"))
    value = parsed["result"][0]["expressions"][0]["value"]
    assert value["decision"] == "block"
    assert value["rule_id"] == "llm06"


@pytest.mark.asyncio
async def test_opa_data_root_query_shape_differs_from_package_query(opa_path: str, sample_rego: str, tmp_path) -> None:
    policy_file = tmp_path / "policy.rego"
    policy_file.write_text(sample_rego, encoding="utf-8")

    proc_data = await asyncio.create_subprocess_exec(
        opa_path,
        "eval",
        "--format=json",
        "--v0-compatible",
        "--data",
        str(policy_file),
        "data",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_data, stderr_data = await proc_data.communicate()
    assert proc_data.returncode == 0, stderr_data.decode("utf-8", errors="replace")

    proc_package = await asyncio.create_subprocess_exec(
        opa_path,
        "eval",
        "--format=json",
        "--v0-compatible",
        "--data",
        str(policy_file),
        "data.norviq.strict",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_package, stderr_package = await proc_package.communicate()
    assert proc_package.returncode == 0, stderr_package.decode("utf-8", errors="replace")

    parsed_data = json.loads(stdout_data.decode("utf-8"))
    parsed_package = json.loads(stdout_package.decode("utf-8"))
    root_value = parsed_data["result"][0]["expressions"][0]["value"]
    package_value = parsed_package["result"][0]["expressions"][0]["value"]
    assert isinstance(root_value, dict)
    assert isinstance(package_value, dict)
    assert "norviq" in root_value
