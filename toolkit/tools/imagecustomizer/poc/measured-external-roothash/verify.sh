#!/bin/sh
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -eu

if [ "$#" -ne 5 ]; then
    echo "Usage: $0 AK_PUBLIC_KEY NONCE_HEX EXPECTED_ROOT_HASH EXPECTED_CMDLINE_FILE BUNDLE_DIRECTORY" >&2
    exit 2
fi

ak_public=$1
nonce=$2
roothash=$3
expected_cmdline=$4
bundle=$5
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

command -v tpm2_checkquote >/dev/null 2>&1 || {
    echo "$0: tpm2_checkquote is required" >&2
    exit 1
}

tpm2_checkquote \
    -u "$ak_public" \
    -m "$bundle/quote.msg" \
    -s "$bundle/quote.sig" \
    -g sha256 \
    -q "$nonce"

python3 "$script_dir/verify.py" \
    --eventlog "$bundle/eventlog.bin" \
    --quote-message "$bundle/quote.msg" \
    --expected-roothash "$roothash" \
    --expected-cmdline-file "$expected_cmdline"
