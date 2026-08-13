# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-026: every adapter must STATE what its guard covers, and the two shapes must stay distinct.

The finding reads the missing `protect()` / `allow_unwrapped` on the LangGraph and Semantic-Kernel
adapters as an asymmetry to be unified. Checking it inverts the conclusion: those two guard the
EXECUTION PATH (the graph node, the kernel filter) rather than individual tool objects, so there is
no per-tool wrapping step that can be forgotten and nothing for `allow_unwrapped` to mean. That is
structurally stronger than the per-tool shape, not weaker.

What was genuinely missing is that none of this was written down, so the difference looked like an
oversight and an operator had no way to know which surface their framework governs. These tests pin
the documentation and the structural difference together, so neither can drift from the other.
"""

from __future__ import annotations

import importlib

import pytest

_PER_TOOL = ("langchain", "crewai", "autogen")
_PER_PATH = ("langgraph", "semantic_kernel")


def _module(name: str):
    return importlib.import_module(f"norviq.sdk.{name}.adapter")


@pytest.mark.parametrize("name", _PER_TOOL + _PER_PATH)
def test_every_adapter_documents_its_governed_surface(name):
    doc = _module(name).__doc__ or ""
    assert "GOVERNED SURFACE" in doc, (
        f"{name} does not say what its guard covers — an operator cannot tell whether a tool they "
        "did not register runs ungoverned"
    )


@pytest.mark.parametrize("name", _PER_TOOL)
def test_per_tool_adapters_fail_closed_on_an_unrecognised_item(name):
    """These wrap individual tools, so an item that cannot be wrapped is a real gap and must be a
    loud startup error rather than a silently unprotected tool."""
    mod = _module(name)
    assert hasattr(mod, "protect")
    import inspect

    sig = inspect.signature(mod.protect)
    assert "allow_unwrapped" in sig.parameters
    assert sig.parameters["allow_unwrapped"].default is False, (
        f"{name} would accept an unwrappable tool by default"
    )


@pytest.mark.parametrize("name", _PER_PATH)
def test_path_adapters_have_no_per_tool_escape_hatch(name):
    """Asserted as a PROPERTY, not an absence: these have no `protect()` because there is no per-tool
    wrapping step, and adding one later would mean the guard had moved off the execution path."""
    mod = _module(name)
    assert not hasattr(mod, "protect"), (
        f"{name} grew a protect() — if wrapping moved to individual tools, the execution-path "
        "guarantee is gone and allow_unwrapped now has to exist"
    )
    doc = mod.__doc__ or ""
    assert "EXECUTION PATH" in doc


@pytest.mark.parametrize("name", _PER_TOOL + _PER_PATH)
def test_every_adapter_names_what_stays_ungoverned(name):
    """Cooperative enforcement has a real boundary. Each adapter has to name it rather than imply
    total coverage — that honesty is the whole point of the card."""
    doc = (_module(name).__doc__ or "").lower()
    assert "ungoverned" in doc
