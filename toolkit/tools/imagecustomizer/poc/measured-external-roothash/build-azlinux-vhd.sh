#!/bin/sh
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -eu

usage()
{
    cat >&2 <<EOF
Usage: $0 --imagecustomizer FILE --secureboot-key FILE --secureboot-cert FILE
          INPUT_IMAGE OUTPUT.vhd

Create an Azure Linux root-verity UKI image with Image Customizer, then move
the UKI addon's command line into measured external EFI LoadOptions.
EOF
    exit 2
}

die()
{
    echo "$0: $*" >&2
    exit 1
}

imagecustomizer=
secureboot_key=
secureboot_cert=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --imagecustomizer)
            [ "$#" -ge 2 ] || usage
            imagecustomizer=$2
            shift 2
            ;;
        --secureboot-key)
            [ "$#" -ge 2 ] || usage
            secureboot_key=$2
            shift 2
            ;;
        --secureboot-cert)
            [ "$#" -ge 2 ] || usage
            secureboot_cert=$2
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        --)
            shift
            break
            ;;
        -*)
            usage
            ;;
        *)
            break
            ;;
    esac
done

if [ -z "$imagecustomizer" ] || [ -z "$secureboot_key" ] ||
   [ -z "$secureboot_cert" ] || [ "$#" -ne 2 ]; then
    usage
fi

input=$1
output=$2
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
output_dir=$(dirname "$output")
mkdir -p "$output_dir"
output_dir=$(readlink -f "$output_dir")
intermediate="$output_dir/.$(basename "$output").imagecustomizer.$$"
build_dir="$output_dir/.$(basename "$output").build.$$"
success=false

cleanup()
{
    status=$?
    trap - EXIT HUP INT TERM
    rm -f "$intermediate"
    rm -rf "$build_dir"
    if [ "$success" != true ]; then
        rm -f "$output" "${output}.cmdline" "${output}.roothash"
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -x "$imagecustomizer" ] ||
    die "Image Customizer is not executable: $imagecustomizer"
[ -f "$input" ] || die "input Azure Linux image does not exist: $input"
[ -f "$secureboot_key" ] || die "Secure Boot key does not exist: $secureboot_key"
[ -f "$secureboot_cert" ] ||
    die "Secure Boot certificate does not exist: $secureboot_cert"
[ ! -e "$output" ] || die "refusing to overwrite output: $output"
[ ! -e "${output}.cmdline" ] ||
    die "refusing to overwrite policy: ${output}.cmdline"
[ ! -e "${output}.roothash" ] ||
    die "refusing to overwrite root hash: ${output}.roothash"

mkdir -p "$build_dir"

"$imagecustomizer" \
    --build-dir "$build_dir" \
    --image-file "$input" \
    --output-image-file "$intermediate" \
    --output-image-format vhd-fixed \
    --config-file "$script_dir/azlinux-image.yaml"

"$script_dir/externalize-azlinux-vhd.sh" \
    --secureboot-key "$secureboot_key" \
    --secureboot-cert "$secureboot_cert" \
    "$intermediate" "$output"

success=true
echo "Created Azure Linux PCR 12 roothash PoC image: $output"
