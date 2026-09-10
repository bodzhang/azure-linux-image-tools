#!/bin/sh
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -eu

usage()
{
    cat >&2 <<EOF
Usage: $0 --secureboot-key FILE --secureboot-cert FILE INPUT.vhd OUTPUT.vhd

Move an Azure Linux UKI addon's command line into a Type #1 systemd-boot entry,
sign the cmdline-free UKI and systemd-boot, and emit attestation policy files.
EOF
    exit 2
}

die()
{
    echo "$0: $*" >&2
    exit 1
}

require()
{
    command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

secureboot_key=
secureboot_cert=

while [ "$#" -gt 0 ]; do
    case "$1" in
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

if [ -z "$secureboot_key" ] || [ -z "$secureboot_cert" ] ||
   [ "$#" -ne 2 ]; then
    usage
fi

input=$1
output=$2
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
policy_output="${output}.cmdline"
roothash_output="${output}.roothash"

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -f "$input" ] || die "input Azure Linux VHD does not exist: $input"
[ -f "$secureboot_key" ] || die "Secure Boot key does not exist: $secureboot_key"
[ -f "$secureboot_cert" ] ||
    die "Secure Boot certificate does not exist: $secureboot_cert"
[ ! -e "$output" ] || die "refusing to overwrite output: $output"
[ ! -e "$policy_output" ] || die "refusing to overwrite policy: $policy_output"
[ ! -e "$roothash_output" ] || die "refusing to overwrite root hash: $roothash_output"

for program in awk basename cat cp find grep head id losetup lsblk mkdir mktemp mount \
    mountpoint mv objcopy objdump python3 readlink rm rmdir sbsign sort stat \
    sync umount veritysetup; do
    require "$program"
done

input_real=$(readlink -f "$input")
output_dir=$(dirname "$output")
mkdir -p "$output_dir"
output_dir=$(readlink -f "$output_dir")
output_real="$output_dir/$(basename "$output")"
[ "$input_real" != "$output_real" ] || die "input and output must differ"

loop=
esp_mount=
tempdir=$(mktemp -d)
success=false

cleanup()
{
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$esp_mount" ] && mountpoint -q "$esp_mount"; then
        umount "$esp_mount" || status=1
    fi
    if [ -n "$loop" ]; then
        losetup -d "$loop" || status=1
    fi
    if [ "$success" != true ]; then
        rm -f "$output" "$policy_output" "$roothash_output"
    fi
    rm -rf "$tempdir"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

python3 "$script_dir/vhd_info.py" "$input"
cp --reflink=auto --sparse=always -- "$input" "$output"

size=$(stat -c %s "$output")
loop=$(losetup -P --sizelimit $((size - 512)) -f --show "$output")
if command -v udevadm >/dev/null 2>&1; then
    udevadm settle
fi

efi_type=c12a7328-f81f-11d2-ba4b-00a0c93ec93b
esp_matches=$(lsblk -nrpo NAME,PARTTYPE "$loop" |
    awk -v type="$efi_type" 'tolower($2) == type { print $1 }')
esp_count=$(printf '%s\n' "$esp_matches" |
    awk 'NF { count++ } END { print count + 0 }')
[ "$esp_count" -eq 1 ] ||
    die "expected one EFI system partition, found $esp_count"
esp=$esp_matches

esp_mount=$(mktemp -d "$tempdir/esp.XXXXXX")
mount -t vfat "$esp" "$esp_mount"

ukis=$(find "$esp_mount/EFI/Linux" -maxdepth 1 -type f -name '*.efi' |
    LC_ALL=C sort)
uki_count=$(printf '%s\n' "$ukis" |
    awk 'NF { count++ } END { print count + 0 }')
[ "$uki_count" -eq 1 ] ||
    die "expected one Azure Linux UKI under EFI/Linux, found $uki_count"
uki=$ukis

sections=$(objdump -h "$uki") || die "objdump could not inspect Azure Linux UKI"
echo "$sections" | awk '$2 == ".linux" { found = 1 } END { exit !found }' ||
    die "Azure Linux EFI/Linux image is not a UKI"
if echo "$sections" | awk '$2 == ".cmdline" { found = 1 } END { exit !found }'; then
    die "Azure Linux UKI embeds .cmdline; expected the addon architecture"
fi

addon_dir="${uki}.extra.d"
[ -d "$addon_dir" ] || die "Azure Linux UKI addon directory is missing"
addons=$(find "$addon_dir" -maxdepth 1 -type f -name '*.addon.efi' |
    LC_ALL=C sort)
addon_count=$(printf '%s\n' "$addons" |
    awk 'NF { count++ } END { print count + 0 }')
[ "$addon_count" -ge 1 ] || die "Azure Linux UKI has no command-line addon"

if [ -d "$esp_mount/loader/addons" ] &&
   find "$esp_mount/loader/addons" -maxdepth 1 -type f \
       -name '*.addon.efi' | grep -q .; then
    die "global UKI addons would change the measured command line"
fi

set --
index=0
for addon in $addons; do
    section="$tempdir/addon-$index.cmdline"
    objcopy --dump-section ".cmdline=$section" "$addon" ||
        die "cannot extract .cmdline from addon: $addon"
    set -- "$@" "$section"
    index=$((index + 1))
done

data_device_output="$tempdir/data-device"
hash_device_output="$tempdir/hash-device"
python3 "$script_dir/addon_cmdline.py" \
    --cmdline-output "$policy_output" \
    --roothash-output "$roothash_output" \
    --data-device-output "$data_device_output" \
    --hash-device-output "$hash_device_output" \
    "$@"

cmdline=$(cat "$policy_output")
[ -n "$cmdline" ] || die "external command-line policy is empty"
root_hash=$(cat "$roothash_output")
data_device=$(cat "$data_device_output")
hash_device=$(cat "$hash_device_output")

case "$data_device" in
    PARTUUID=*) data_partuuid=${data_device#PARTUUID=} ;;
    *) die "root data device is not identified by PARTUUID: $data_device" ;;
esac
case "$hash_device" in
    PARTUUID=*) hash_partuuid=${hash_device#PARTUUID=} ;;
    *) die "root hash device is not identified by PARTUUID: $hash_device" ;;
esac

data_matches=$(lsblk -nrpo NAME,PARTUUID "$loop" |
    awk -v uuid="$data_partuuid" 'tolower($2) == tolower(uuid) { print $1 }')
hash_matches=$(lsblk -nrpo NAME,PARTUUID "$loop" |
    awk -v uuid="$hash_partuuid" 'tolower($2) == tolower(uuid) { print $1 }')
data_count=$(printf '%s\n' "$data_matches" |
    awk 'NF { count++ } END { print count + 0 }')
hash_count=$(printf '%s\n' "$hash_matches" |
    awk 'NF { count++ } END { print count + 0 }')
[ "$data_count" -eq 1 ] ||
    die "expected one root data partition for $data_device, found $data_count"
[ "$hash_count" -eq 1 ] ||
    die "expected one root hash partition for $hash_device, found $hash_count"
veritysetup verify "$data_matches" "$hash_matches" "$root_hash" ||
    die "external roothash does not verify the output root filesystem"

sbsign \
    --key "$secureboot_key" \
    --cert "$secureboot_cert" \
    --output "$tempdir/uki.efi" \
    "$uki"
cp -f -- "$tempdir/uki.efi" "$uki"

bootloader=$(find "$esp_mount/EFI/BOOT" -maxdepth 1 -type f \
    -iname 'bootx64.efi' | LC_ALL=C sort | head -n 1)
[ -n "$bootloader" ] || die "systemd-boot fallback executable is missing"
sbsign \
    --key "$secureboot_key" \
    --cert "$secureboot_cert" \
    --output "$tempdir/systemd-bootx64.efi" \
    "$bootloader"
cp -f -- "$tempdir/systemd-bootx64.efi" "$bootloader"

canonical_bootloader=$(find "$esp_mount/EFI/systemd" -maxdepth 1 -type f \
    -iname 'systemd-bootx64.efi' 2>/dev/null | LC_ALL=C sort | head -n 1)
if [ -n "$canonical_bootloader" ]; then
    sbsign \
        --key "$secureboot_key" \
        --cert "$secureboot_cert" \
        --output "$tempdir/canonical-systemd-bootx64.efi" \
        "$canonical_bootloader"
    cp -f -- "$tempdir/canonical-systemd-bootx64.efi" "$canonical_bootloader"
fi

for addon in $addons; do
    rm -f -- "$addon"
done
rmdir "$addon_dir"

mkdir -p "$esp_mount/EFI/azlinux"
external_uki="$esp_mount/EFI/azlinux/$(basename "$uki")"
mv -- "$uki" "$external_uki"

mkdir -p "$esp_mount/loader/entries"
entry="$esp_mount/loader/entries/azlinux-verity-attestation.conf"
{
    echo "title Azure Linux dm-verity attestation PoC"
    echo "efi /EFI/azlinux/$(basename "$external_uki")"
    echo "options $cmdline"
} > "$entry"

cat > "$esp_mount/loader/loader.conf" <<EOF
default azlinux-verity-attestation.conf
timeout 0
console-mode keep
editor no
EOF

sync "$esp_mount"
umount "$esp_mount"
rmdir "$esp_mount"
esp_mount=
losetup -d "$loop"
loop=

python3 "$script_dir/vhd_info.py" "$output"
success=true
echo "Created Azure Linux attestation VHD: $output"
echo "Created root-hash policy: $roothash_output"
echo "Created measured command-line policy: $policy_output"
