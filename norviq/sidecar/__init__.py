# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Sidecar exports."""

from norviq.sidecar.http_fallback import create_http_fallback
from norviq.sidecar.proxy import SidecarProxy

__all__ = ["SidecarProxy", "create_http_fallback"]
