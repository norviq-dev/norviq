# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Hook phases vs. what `helm install --wait` blocks on.

A workload that mounts a Secret NON-OPTIONALLY cannot start until that Secret exists. If the only
thing that creates it is a `post-install` hook, `helm install --wait` deadlocks by construction:
Helm applies the chart, waits for every workload to be Ready, and runs post-install hooks only after
that wait returns. The pod sits in Init on `secret "..." not found`, --wait never returns, and the
hook that would have unblocked it never runs. The install dies at its --timeout with the release left
in `pending-install`.

That is not hypothetical — it is what `norviq-webhook` + `norviq-webhook-tls` did on every fresh
cluster, in every released version, until the cert hook was moved to run in BOTH phases. It stayed
hidden because the documented install commands do not pass `--wait`; anything scripted (CI, GitOps,
`--wait --atomic`) hits it on the first try.

These tests are deliberately about ORDERING rather than that one Secret: the next runtime-provisioned
Secret to be mounted by a workload would reintroduce the same deadlock, and the failure mode gives no
hint about hook phases when you meet it.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest
import yaml

_CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"
_BASE = ["--set", "policyQuotaNamespaces={default}"]
_WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "Pod"}

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")


def _docs(*extra: str):
    res = subprocess.run(
        ["helm", "template", "norviq", str(_CHART), *_BASE, *extra], capture_output=True, text=True
    )
    assert res.returncode == 0, res.stderr
    return [d for d in yaml.safe_load_all(res.stdout) if d]


def _hook_phases(doc) -> list[str]:
    raw = (doc.get("metadata", {}).get("annotations") or {}).get("helm.sh/hook", "")
    return [p.strip() for p in raw.split(",") if p.strip()]


def _pod_spec(doc):
    """A bare Pod carries its spec at .spec; controllers wrap it in .spec.template.spec."""
    spec = doc.get("spec") or {}
    return (spec.get("template") or {}).get("spec") or (spec if doc.get("kind") == "Pod" else {})


def _required_secret_mounts(docs):
    """(owner, secretName) for every NON-optional secret volume on a NON-hook workload.

    Hook pods are excluded on purpose: Helm waits on them one phase at a time, so a hook mounting a
    secret produced by an earlier hook is ordinary sequencing, not a deadlock.
    """
    for d in docs:
        if d.get("kind") not in _WORKLOADS or _hook_phases(d):
            continue
        for vol in _pod_spec(d).get("volumes") or []:
            sec = vol.get("secret") or {}
            if sec.get("secretName") and not sec.get("optional"):
                yield f"{d['kind']}/{d['metadata']['name']}", sec["secretName"]


def _creating_hooks(docs, secret_name: str):
    """Hook Jobs that provision `secret_name` at runtime, by naming it in their container args."""
    for d in docs:
        phases = _hook_phases(d)
        if d.get("kind") != "Job" or not phases:
            continue
        blob = yaml.safe_dump(_pod_spec(d).get("containers") or [])
        if secret_name in blob:
            yield d["metadata"]["name"], phases


def test_no_workload_waits_on_a_secret_only_a_post_hook_creates() -> None:
    """The deadlock, stated as a rule. Renders with injection ON — the fullest set of workloads."""
    docs = _docs("--set", "webhook.injection.enabled=true")
    rendered_secrets = {d["metadata"]["name"] for d in docs if d.get("kind") == "Secret"}

    deadlocks = []
    for owner, secret in _required_secret_mounts(docs):
        if secret in rendered_secrets:
            continue  # applied with the chart, present before --wait begins
        creators = list(_creating_hooks(docs, secret))
        if not creators:
            # Operator-supplied (an existingSecret they pre-create) — not the chart's ordering to own.
            continue
        if not any(p.startswith("pre-") for _, phases in creators for p in phases):
            deadlocks.append((owner, secret, creators))

    assert not deadlocks, (
        "these workloads block `helm install --wait` forever — each mounts a Secret non-optionally "
        "that only a post-install hook creates, and post-install hooks run AFTER --wait returns:\n"
        + "\n".join(f"  {o} needs {s}, created by {c}" for o, s, c in deadlocks)
    )


def test_webhook_serving_cert_hook_runs_in_both_phases() -> None:
    """The concrete contract, so a phase list edited down to one half fails loudly here.

    Both halves are load-bearing and they pull in opposite directions: the SECRET has to exist before
    --wait blocks on the Deployment mounting it, and the caBundle patch has to happen after the
    MutatingWebhookConfiguration it targets is applied.
    """
    docs = _docs("--set", "webhook.injection.enabled=true")
    job = next(d for d in docs if d.get("kind") == "Job" and d["metadata"]["name"] == "norviq-webhook-cert")
    phases = set(_hook_phases(job))

    assert {"pre-install", "pre-upgrade"} <= phases, (
        f"norviq-webhook-cert must run pre-* so norviq-webhook-tls exists before --wait; got {sorted(phases)}"
    )
    assert {"post-install", "post-upgrade"} <= phases, (
        f"norviq-webhook-cert must ALSO run post-* to patch the caBundle; got {sorted(phases)}"
    )


def test_cert_hook_rbac_is_present_in_every_phase_the_job_runs() -> None:
    """Hook RBAC is deleted after each phase and recreated for the next.

    A Job granted permissions only in post-install would run un-authorized in pre-install and fail
    the whole install — a worse outcome than the deadlock it was meant to fix.
    """
    docs = _docs("--set", "webhook.injection.enabled=true")
    job_phases = set(
        _hook_phases(next(d for d in docs if d.get("kind") == "Job" and d["metadata"]["name"] == "norviq-webhook-cert"))
    )
    kinds = {"ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}
    supporting = [d for d in docs if d.get("kind") in kinds and d["metadata"]["name"] == "norviq-webhook-cert"]

    assert supporting, "no RBAC rendered for the norviq-webhook-cert hook"
    for d in supporting:
        assert job_phases <= set(_hook_phases(d)), (
            f"{d['kind']}/norviq-webhook-cert is missing phases the Job runs in: "
            f"{sorted(job_phases - set(_hook_phases(d)))}"
        )
