# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Intent → Rego compilation.

An intent states what an agent class is FOR. Everything it does not state is denied. The compiler
turns that statement into an ordinary Rego policy, so the engine, precedence resolution, audit and
trust are unchanged — an intent is a *generator*, not a second runtime.

See DESIGN-NOTE-MCP-FIREWALL.md §13.
"""

from norviq.engine.intent.compiler import CompiledIntent, IntentError, compile_intent
from norviq.engine.intent.dryrun import DryRunReport, dry_run, opa_subprocess_evaluator
from norviq.engine.intent.propose import propose_intent
from norviq.engine.intent.schema import normalize_intent

__all__ = [
    "CompiledIntent",
    "DryRunReport",
    "IntentError",
    "compile_intent",
    "dry_run",
    "normalize_intent",
    "opa_subprocess_evaluator",
    "propose_intent",
]
