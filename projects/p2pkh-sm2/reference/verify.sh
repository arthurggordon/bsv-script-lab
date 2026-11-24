#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec bash ../../../shared/verify_node.sh test_sighash test_node test_signed_data test_signed_data_acceptance
