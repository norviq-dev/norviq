#!/bin/bash
# Sync CRDs from source of truth to Helm chart
cp crds/norviq.io_nrvqpolicies.yaml helm/norviq/crds/
cp crds/norviq.io_nrvqclasses.yaml helm/norviq/crds/
cp crds/norviq.io_nrvqconfigs.yaml helm/norviq/crds/
echo "CRDs synced to Helm chart"
