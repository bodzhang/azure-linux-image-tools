#!/bin/sh
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -eu

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 AK_CONTEXT NONCE_HEX OUTPUT_DIRECTORY" >&2
    exit 2
fi

ak_context=$1
nonce=$2
output=$3
eventlog=/sys/kernel/security/tpm0/binary_bios_measurements

case "$nonce" in
    *[!0-9A-Fa-f]*|'')
        echo "$0: nonce must be a non-empty hexadecimal string" >&2
        exit 1
        ;;
esac

[ -r "$eventlog" ] || {
    echo "$0: TPM event log is not readable: $eventlog" >&2
    exit 1
}

command -v tpm2_quote >/dev/null 2>&1 || {
    echo "$0: tpm2_quote is required" >&2
    exit 1
}

umask 077
mkdir -p "$output"

tpm2_quote \
    -c "$ak_context" \
    -l sha256:12 \
    -q "$nonce" \
    -m "$output/quote.msg" \
    -s "$output/quote.sig" \
    -g sha256

cp "$eventlog" "$output/eventlog.bin"

echo "Created attestation bundle in $output"
