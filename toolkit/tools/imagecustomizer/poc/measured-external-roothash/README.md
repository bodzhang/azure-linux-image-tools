# Azure Linux measured external roothash PoC

This PoC extends Azure Linux Image Customizer to place the dm-verity root hash
in external EFI LoadOptions and attest the resulting systemd-stub PCR 12
measurement.

The security model separates measurement from authorization:

- systemd-stub guarantees that the command line used by Linux is fully
  represented in measured boot;
- the remote verifier authorizes the measured `roothash=` and complete command
  line.

## Implementation status

### Implemented in this branch

The code in this directory implements:

- an Image Customizer configuration for Azure Linux root dm-verity, a
  Dracut/systemd initrd, UKI creation, systemd-boot, and Azure fixed VHD output;
- an end-to-end wrapper around Image Customizer;
- extraction of Image Customizer's generated UKI-addon command line;
- validation of exactly one SHA-256 `roothash=` and the required systemd root
  verity arguments;
- resolution of root data and hash partitions by PARTUUID;
- verification of the generated root hash with `veritysetup verify`;
- removal of command-line addons and conversion to a Type #1 BLS `efi` entry
  with external `options`;
- Secure Boot signing of the UKI and systemd-boot;
- Azure fixed-VHD validation;
- TPM quote and event-log collection;
- PCR 12 replay and exact command-line policy verification;
- unit tests for command-line extraction, quote verification, event-log replay,
  and VHD validation.

The PoC has 19 local unit tests. No Azure Linux VHD has been built or booted in
this development environment because it does not contain an Azure Linux base
image, Image Customizer binary, Secure Boot credentials, or a target VM.

### Not implemented in this branch

This branch does not modify systemd-stub. Consequently:

- the generated image can use external LoadOptions with an unmodified
  systemd-stub on a standard Azure Generation 2 VM;
- the generated image cannot use external LoadOptions on an SEV, SEV-SNP, or
  TDX confidential VM when Secure Boot is enabled;
- confidential-VM support depends on the upstream systemd-stub proposal
  described below.

The branch also does not provision a TPM attestation key, establish AK trust,
enroll Secure Boot keys in Azure, or implement a production service that
releases secrets after successful attestation.

## Implemented image flow

```text
Azure Linux base image
        |
        v
Azure Linux Image Customizer
  - root dm-verity
  - Dracut/systemd initrd
  - UKI plus command-line addon
  - systemd-boot
  - fixed VHD
        |
        v
externalize-azlinux-vhd.sh
  - extract generated command line
  - validate roothash and verity arguments
  - run veritysetup verify
  - remove command-line addons
  - sign UKI and systemd-boot
  - create external Type #1 BLS options
        |
        v
systemd-boot passes options as EFI LoadOptions
        |
        v
systemd-stub measures command line into PCR 12
        |
        v
Linux and systemd-veritysetup-generator mount the verified root
```

The Type #1 entry is unsigned. The PoC does not treat it as locally trusted.
Any modification changes the PCR 12 measurement and is rejected by the remote
attestation policy.

## Upstream systemd-stub blocker

Upstream systemd-stub currently contains this confidential-VM restriction:

```c
if (secure_boot_enabled() && (have_cmdline || is_confidential_vm()))
        return false;
```

With Secure Boot enabled, `is_confidential_vm()` causes systemd-stub to ignore
all external EFI LoadOptions. Removing `.cmdline` from the UKI is therefore
sufficient for a standard VM but not for SEV, SEV-SNP, or TDX.

This restriction is the only systemd behavior that the confidential-VM version
of this PoC needs to change. The Image Customizer integration, dm-verity image
layout, external BLS entry, and verifier are implemented here.

## Proposed upstream systemd-stub change

This section is a design proposal. It is not implemented by this branch.

The proposal retains the current denial as the default and adds a signed UKI
opt-in for **measured external LoadOptions**. The opt-in authorizes the
measurement mechanism; it does not authorize any particular command-line
value. The remote verifier remains responsible for deciding whether the
measured value is approved.

When the signed opt-in is present, systemd-stub performs the following
fail-closed sequence:

1. Read EFI LoadOptions.
2. Convert and canonicalize them into the representation used for the Linux
   command line.
3. Merge every accepted command-line source in a deterministic order.
4. Measure the final effective command line into PCR 12.
5. Pass exactly the measured bytes to Linux.
6. Fail boot if the TPM measurement cannot be completed.
7. Reject any command-line source that can alter the result after measurement.
8. Emit an event-log record containing an unambiguous representation of the
   final effective command line.

Host-controlled SMBIOS command-line injection remains disabled on confidential
VMs. Signed addons are either disabled in this mode or included before the
single final command-line measurement.

```text
unsigned EFI LoadOptions
        |
        v
signed systemd-stub with measured-LoadOptions opt-in
        |
        +-- build final command line
        +-- extend exact final bytes into PCR 12
        +-- pass the same bytes to Linux
        |
        v
remote verifier checks quote, event log, expected roothash, and command line
```

The proposal provides detection before remote authorization or secret release.
It does not require systemd-stub to know the approved root hash. If local
rejection before Linux starts is required, the VM needs a different model in
which an expected hash, allowlist, or signature-verification key is present in
authenticated local policy.

## Remote verifier contract

The verifier:

1. authenticates the attestation key;
2. supplies a fresh nonce;
3. validates the quote signature and nonce;
4. validates the expected Secure Boot, systemd-stub, and UKI identity PCRs;
5. replays the SHA-256 PCR 12 event sequence;
6. confirms that replay produces the quoted PCR 12 value;
7. validates the event digest against the raw command-line event data;
8. compares the measured effective command line with approved policy;
9. confirms that the measured `roothash=` equals the expected dm-verity root
   hash;
10. releases identity, secrets, or service authorization only after every
    check succeeds.

The full command line is policy-relevant. Checking only `roothash=` would allow
an attacker to retain the expected root hash while adding an option such as
`init=` or `rd.break`.

## Build

`azlinux-image.yaml` defines separate ESP, `/boot`, root, root-hash, and `/var`
partitions. Image Customizer builds the native Dracut/systemd verity path.

```sh
sudo ./build-azlinux-vhd.sh \
    --imagecustomizer /path/to/imagecustomizer \
    --secureboot-key ./db.key \
    --secureboot-cert ./db.crt \
    azure-linux-base.vhdx azlinux-roothash-pcr12.vhd
```

The signing certificate must be enrolled in the target VM's custom Secure Boot
`db`.

The build produces:

```text
azlinux-roothash-pcr12.vhd
azlinux-roothash-pcr12.vhd.roothash
azlinux-roothash-pcr12.vhd.cmdline
```

The `.roothash` and `.cmdline` files are verifier policy inputs. Provision them
through an authenticated channel; do not accept copies supplied by the
attested VM.

## Collect evidence

The nonce is fresh verifier-provided hex. The AK context is local to the
attested machine:

```sh
./collect.sh ak.ctx 7f9c... /tmp/attestation
```

The collector quotes SHA-256 PCR 12, writes `quote.msg` and `quote.sig`, and
copies the firmware binary event log.

## Verify evidence

```sh
./verify.sh \
    akpub.pem \
    7f9c... \
    66edc2dedf7a1aecc608d49cb2185415be3c2ba8b075675f9cc8222b41a846f3 \
    azlinux-roothash-pcr12.vhd.cmdline \
    /tmp/attestation
```

`verify.sh` fails unless:

- the AK signature and verifier nonce are valid;
- the quote selects exactly SHA-256 PCR 12;
- replaying every SHA-256 PCR 12 event reproduces the quoted PCR value;
- the command-line event contains the approved root hash;
- every measured command-line fragment exactly matches approved policy;
- each event digest matches its raw UTF-16LE event data.

A production verifier also validates the PCRs that identify Secure Boot,
systemd-stub, and the UKI. The current verifier intentionally focuses on the
PCR 12 command-line policy.

## Repository scope

This experimental PoC lives under Image Customizer because it augments the
Azure Linux image-building pipeline. The proposed LoadOptions opt-in belongs in
upstream systemd-stub and remains a separate change.

## Requirements

Image build:

- Azure Linux base image;
- Azure Linux Image Customizer with UKI support;
- `binutils`, `sbsign`, `veritysetup`, `util-linux`, and Python 3;
- Secure Boot key and certificate enrolled by the target VM policy;
- patched systemd-stub for confidential-VM execution.

Attested VM and verifier:

- TPM 2.0 with a SHA-256 PCR bank;
- `tpm2-tools`;
- verifier-provisioned AK public key and policy files.

Run the local checks with:

```sh
make check
```
