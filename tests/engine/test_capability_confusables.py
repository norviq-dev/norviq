# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-046 regression: the verb classifier reads the confusable skeleton, not the raw bytes.

The evaluator already computed `skeleton(name)` for Rego name-matching while classifying the RAW name,
so the two disagreed on exactly the input an attacker chooses. With `deny { input.derived.verb ==
"delete" }` in force, `delete_records` and the synonym `remove_records` blocked; `dеlete_records` — one
Cyrillic е — classified UNKNOWN and the verb rule never saw it.

The ordering test is the one that matters most. `skeleton()` casefolds and `_CAMEL_RE` finds boundaries
by looking for an uppercase letter, so folding before splitting silently erases every camelCase
boundary — `aws_s3_DeleteObject` stops classifying as `delete`. That is a loss of enforcement on
ordinary vendor names, and it is invisible unless something asserts it.
"""

from __future__ import annotations

import re

import pytest

import norviq.engine.capability.source_registry as sr
from norviq.engine.capability import classify_tool

# Realistic vendor names spanning every shape the classifier is documented to care about: reads that
# carry an egress noun, exec qualifiers beside an operation token, camelCase, colon- and dot-separated
# vendor spellings, digits inside tokens, and the control-plane actuation pair.
VENDOR_CORPUS = [
    "get_mail", "list_mail", "read_email_thread", "search_mail", "get_sync_status", "download_export",
    "slack_post_message", "chat.postMessage", "SES:SendRawEmail", "aws_s3_DeleteObject", "s3_get_object",
    "md5_hash", "base64_decode", "execute_sql", "run_query", "run_report", "http_get", "put_object",
    "delete_email", "remove_webhook", "revoke_share", "purge_mail_queue", "invalidate_push_token",
    "invoke_send_pipeline", "run_export", "exec_upload", "restart_sync", "eval_dispatch", "milvus_search",
    "fetch_url", "getMail", "sendEmail", "transfer_funds", "open_breaker", "set_valve", "acme_widget",
]


def _raw_tokens(name: str) -> list[str]:
    """How the tokenizer behaved BEFORE the fix — the baseline nothing may drift from."""
    spaced = sr._CAMEL_RE.sub(" ", name or "")
    return [t.lower() for t in re.split(r"[^A-Za-z0-9]+", spaced) if t and not t.isdigit()]


@pytest.mark.parametrize(
    ("label", "name"),
    [
        ("cyrillic e", "dеlete_records"),
        ("cyrillic komi de", "ԁelete_records"),
        ("zero-width split", "dele​te_records"),
        ("fullwidth", "ｄｅｌｅｔｅ_records"),
        ("camelCase + cyrillic", "dеleteObject"),
    ],
)
def test_homoglyph_names_classify_as_what_they_impersonate(label, name):
    verb, _risk = classify_tool(name, {})
    assert verb.value == "delete", label


def test_the_ascii_controls_are_unchanged():
    assert classify_tool("delete_records", {})[0].value == "delete"
    assert classify_tool("remove_records", {})[0].value == "delete"


@pytest.mark.parametrize("name", VENDOR_CORPUS)
def test_ordinary_vendor_names_tokenize_exactly_as_before(name):
    """A pure-ASCII name is its own skeleton, so folding must move nothing here.

    This is what catches the wrong ORDER: fold-then-split quietly rewrote five of these
    (`aws_s3_DeleteObject`, `chat.postMessage`, `SES:SendRawEmail`, `getMail`, `sendEmail`) into single
    unmatched tokens, dropping their verbs.
    """
    assert sr._tokenize_tool(name) == _raw_tokens(name)


def test_camelcase_boundaries_survive_the_fold():
    # The specific casualty of the wrong order, asserted on the classification and not just the tokens.
    assert sr._tokenize_tool("aws_s3_DeleteObject") == ["aws", "s3", "delete", "object"]
    assert classify_tool("aws_s3_DeleteObject", {})[0].value == "delete"
    assert classify_tool("sendEmail", {})[0].value == "send"


def test_leetspeak_is_deliberately_not_folded():
    """Pinned as a decision, not an oversight — see `_tokenize_tool`.

    `skeleton()` is Unicode-TR39-aligned. Folding digits to letters would close `de1ete_records` at the
    cost of rewriting `s3_get_object` and `md5_hash`, which are ordinary names, not evasions.
    """
    assert classify_tool("de1ete_records", {})[0].value == "unknown"
    assert sr._tokenize_tool("s3_get_object") == ["s3", "get", "object"]
    assert sr._tokenize_tool("md5_hash") == ["md5", "hash"]
