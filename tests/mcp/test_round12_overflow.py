# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A number that overflows a double decodes to inf, and policy evaluation sees inf as null. Every float
is checked at decode, whatever its spelling."""

from __future__ import annotations

import pytest

from norviq.mcp import protocol as P


def _msg(literal: str) -> bytes:
    return ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount":'
            + literal + '}}}').encode()


@pytest.mark.parametrize("literal", ["9" * 250 + "e99", "-" + "9" * 299 + "e10", "1e309", "-1.8e308",
                                     "0.0000001e316", "1" * 400 + ".5"])
def test_an_overflowing_number_is_undecodable_however_it_is_spelled(literal):
    assert P.decode(_msg(literal)) is None


@pytest.mark.parametrize("literal", ["1.7976931348623157e308", "0." + "0" * 400 + "1e700", "1e-400", "12.5"])
def test_a_finite_number_still_decodes(literal):
    assert P.decode(_msg(literal)) is not None
