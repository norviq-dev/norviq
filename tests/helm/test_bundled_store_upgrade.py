# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""0.2.6's Valkey must not open the files 0.2.5's Redis left on the same volume.

Measured live on 2026-10-30 (kind, Kubernetes 1.34). 0.2.5 was installed from the v0.2.5 chart, given
ordinary state (a policy, a login and a logout), then upgraded with the README's own command,
`helm upgrade --reset-then-reuse-values`, into the 0.2.6 chart:

    UPGRADE FAILED: context deadline exceeded
    norviq-redis-0   CrashLoopBackOff
        Valkey version=8.1.11 ... Server initialized
        # Can't handle RDB format version 12
        # Fatal error loading the DB, check server logs. Exiting.

api and engine sat in Init:1/2 on wait-for-redis, and evaluations came back `evaluator_fallback`.

The cause is the single-instance store's PERSISTENT claim, `norviq-redis-pvc`, mounted at /data. 0.2.5
ran `redis:7-alpine` there, which by then resolved to Redis 7.4, and 7.4 writes RDB format 12. 0.2.6
runs `valkey/valkey:8.1-alpine` in the same StatefulSet, on the same claim, at the same path. Valkey
forked before Redis 7.4, reads format 11 at most, and exits on anything newer. Every 0.2.5 install of
the bundled store that had saved a dump was going to fail the same way.

`helm template` of either chart alone looks fine. The failure only exists between the volume one release
wrote and the mount the next one reads, so the assertion is on that: Valkey's mount of the claim must not
be the volume root.

The fix does not delete or rewrite anything. Valkey works in its own subdirectory and starts empty, and
0.2.5's dump stays at the root, where a `helm rollback` to 0.2.5 still finds it.
"""

from __future__ import annotations

import pathlib
import posixpath
import shutil
import subprocess

import pytest
import yaml

CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"
BASE = ["--set-json", 'policyQuotaNamespaces=["default"]']

# The claim 0.2.5's Redis wrote to (helm/norviq/templates/redis-pvc.yaml). If it is ever renamed, the
# store moves to a new, empty volume and that also fixes the upgrade. Update this test deliberately in
# that case; do not delete it.
CLAIM_0_2_5_WROTE = "norviq-redis-pvc"
# The image's WORKDIR. Valkey runs with no `dir` setting, so it writes dump.rdb to its working directory.
# Move the mount anywhere else and the dump goes to the container's own writable layer, which is gone on
# the next restart. Nothing reports that.
VALKEY_WORKDIR = "/data"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not on PATH")


def _redis_statefulset() -> dict:
    res = subprocess.run(
        ["helm", "template", "norviq", str(CHART), *BASE,
         "--show-only", "templates/redis-statefulset.yaml"],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, res.stderr[-600:]
    docs = [d for d in yaml.safe_load_all(res.stdout) if d]
    assert len(docs) == 1 and docs[0]["kind"] == "StatefulSet", "expected one norviq-redis StatefulSet"
    return docs[0]


def _store_container(sts: dict) -> dict:
    containers = sts["spec"]["template"]["spec"]["containers"]
    assert len(containers) == 1, f"expected one store container, got {[c['name'] for c in containers]}"
    return containers[0]


def _mounts_of_claim(sts: dict, claim: str) -> list[dict]:
    pod = sts["spec"]["template"]["spec"]
    volumes = {
        v["name"] for v in pod.get("volumes") or []
        if (v.get("persistentVolumeClaim") or {}).get("claimName") == claim
    }
    return [m for m in _store_container(sts).get("volumeMounts") or [] if m["name"] in volumes]


def test_valkey_does_not_mount_the_volume_root_that_redis_wrote() -> None:
    """Valkey mounts a subdirectory of the claim, so it never sees 0.2.5's RDB-12 dump."""
    sts = _redis_statefulset()
    mounts = _mounts_of_claim(sts, CLAIM_0_2_5_WROTE)
    assert mounts, (
        f"the store no longer mounts {CLAIM_0_2_5_WROTE}. If it moved to a new claim the upgrade is safe "
        f"by other means; update CLAIM_0_2_5_WROTE on purpose rather than letting this pass vacuously"
    )
    for m in mounts:
        sub = posixpath.normpath(m.get("subPath") or ".")
        assert sub not in (".", "/"), (
            f"the store mounts the ROOT of {CLAIM_0_2_5_WROTE} at {m['mountPath']} (subPath "
            f"{m.get('subPath')!r}). That root holds the dump.rdb 0.2.5's Redis 7.4 wrote in RDB format "
            f"12, which Valkey 8.1 cannot load. It exits with \"Can't handle RDB format version 12\" and "
            f"the upgrade times out. Mount a subdirectory (subPath: valkey) and leave the root alone for "
            f"`helm rollback`."
        )
        assert m["mountPath"] == VALKEY_WORKDIR, (
            f"the store's data is mounted at {m['mountPath']}, but Valkey writes dump.rdb to its working "
            f"directory {VALKEY_WORKDIR}. Every save would go to the container layer and be lost on restart"
        )


def test_valkey_runs_as_the_owner_of_the_directory_the_kubelet_creates() -> None:
    """The subPath directory is created by the kubelet, as root. Only a root process is sure to write it.

    The kubelet gives a missing subPath directory the volume root's mode and root ownership. On kind's
    local-path (a hostPath volume, which never gets fsGroup) the root is 0777, so anyone could write.
    A freshly formatted block volume with no fsGroup has a 0755 root:root root, so only root can.
    The store writes on both today because its server runs as uid 0: the chart's `command` replaces
    the image entrypoint, and the entrypoint is the only step that drops to valkey (uid 999).

    That makes the ownership a property of this spec, so it is asserted here. Making the container
    non-root is a reasonable hardening. Done alone, it leaves Valkey unable to save on block storage,
    and that shows up only at the first save, as `MISCONF ... Permission denied` on writes.
    """
    sts = _redis_statefulset()
    pod_sc = sts["spec"]["template"]["spec"].get("securityContext") or {}
    csc = _store_container(sts).get("securityContext") or {}
    run_as_user = csc.get("runAsUser", pod_sc.get("runAsUser"))
    run_as_non_root = csc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
    assert run_as_user in (None, 0) and run_as_non_root is not True, (
        f"the store container now runs non-root (runAsUser={run_as_user}, runAsNonRoot="
        f"{run_as_non_root}). Its data directory is a kubelet-created subPath directory owned by root "
        f"with the volume root's mode, so it is not writable wherever that root is 0755 root:root and no "
        f"fsGroup applies, as on a freshly formatted block volume. Give the directory to that uid first, "
        f"for example with a root init container that runs `chown` on it, then update this test."
    )
