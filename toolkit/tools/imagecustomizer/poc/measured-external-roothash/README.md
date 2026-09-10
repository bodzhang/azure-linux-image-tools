# Azure Linux measured external roothash PoC

This proof of concept augments Microsoft Azure Linux Image Customizer with an
external, measured dm-verity root hash:

1. Image Customizer creates an Azure Linux image with root dm-verity, a
   Dracut/systemd initrd, a UKI, systemd-boot, and an Azure fixed VHD.
2. The image post-processor extracts the generated command line from the UKI
   addon, including `roothash=` and the root data/hash partition identifiers.
3. It verifies the root filesystem and hash tree with `veritysetup verify`.
4. It removes the command-line addon and creates a Type #1 Boot Loader
   Specification entry whose `options` are passed to the UKI as EFI
   LoadOptions.
5. systemd-stub measures the final effective command line into TPM PCR 12 and
   passes the same command line to Linux.
6. A remote verifier checks a fresh TPM quote, replays PCR 12, and authorizes
   only the expected root hash and command-line policy.

The unsigned Type #1 entry is not locally trusted. Its integrity and
authorization are established by remote attestation.

## Repository placement

This PoC lives on a topic branch of an Azure Linux Image Tools fork because it
extends the Image Customizer pipeline and consumes Image Customizer's verity,
UKI-addon, systemd-boot, and VHD output.

The fork should contain:

- the Azure Linux Image Customizer configuration;
- the external-LoadOptions image post-processing step;
- Secure Boot signing and artifact injection;
- PCR 12 evidence collection and verifier tests;
- an experimental patched systemd-stub package or artifact.

The systemd-stub behavior itself should remain a small systemd topic patch
intended for upstream submission. Once systemd defines the opt-in API, the
Image Customizer fork can replace its experimental stub with the upstream
implementation and propose a generic Image Customizer configuration option.

This directory is experimental and is not part of the supported Image
Customizer interface.

## Current upstream limitation

Upstream systemd-stub rejects external EFI LoadOptions whenever Secure Boot is
enabled and confidential-VM detection reports SEV, SEV-SNP, or TDX. Therefore
the unmodified upstream stub supports this PoC only on a standard Azure
Generation 2 VM with Secure Boot and TPM 2.0.

A confidential-VM build requires the systemd-stub design change below. A signed
UKI command-line addon works with the current upstream stub, but it does not
satisfy the requirement that `roothash=` remain externally supplied.

## Proposed systemd-stub design

In this design, systemd-stub is a **measurement-completeness boundary**, not
the authority that decides whether a particular `roothash=` is approved. The
remote verifier makes that policy decision.

The current confidential-VM denial should remain the default. A signed UKI
must explicitly opt into measured external LoadOptions. The exact UKI section
or metadata key is an upstream API decision; the opt-in authorizes the
measurement mechanism, not any particular external value.

When the opt-in is present, systemd-stub must:

1. Convert and canonicalize EFI LoadOptions before use.
2. Merge every accepted command-line source in a deterministic order.
3. Measure the final effective command line into PCR 12 using exactly the bytes
   subsequently passed to Linux.
4. Make no command-line modification after measurement.
5. Fail boot if the TPM measurement cannot be completed.
6. Continue rejecting host-controlled SMBIOS command-line injection.
7. Accept signed addons only when their contribution is included in the same
   final effective-command-line measurement.
8. Emit an unambiguous event-log record from which a verifier can recover the
   exact effective command line and replay PCR 12.

```text
unsigned BLS options / EFI LoadOptions
                |
                v
signed systemd-stub with measured-LoadOptions opt-in
                |
                +-- construct final effective command line
                +-- extend those exact bytes into PCR 12
                +-- pass the same bytes to Linux
                |
                v
remote verifier checks quote, event log, root hash, and command-line policy
```

This provides detection before remote authorization or secret release. It does
not prevent Linux from starting with an unauthorized value. Rejecting a value
before Linux starts would require an expected hash, allowlist, or signature
verification key in authenticated local policy, which is a different
verified-boot model.

The verifier should normally validate the complete effective command line, not
only extract `roothash=`. Otherwise an attacker could retain the expected root
hash while adding an option such as `init=` or `rd.break`.

## Build an Azure Linux image

`azlinux-image.yaml` defines separate ESP, `/boot`, root, root-hash, and `/var`
partitions. Image Customizer creates the root verity mapping and a
Dracut/systemd initrd containing `systemd-veritysetup`.

```sh
sudo ./build-azlinux-vhd.sh \
    --imagecustomizer /path/to/imagecustomizer \
    --secureboot-key ./db.key \
    --secureboot-cert ./db.crt \
    azure-linux-base.vhdx azlinux-roothash-pcr12.vhd
```

`externalize-azlinux-vhd.sh` then:

1. Validates the Azure fixed VHD.
2. Locates the EFI system partition and the single generated UKI.
3. Rejects a main UKI containing an embedded `.cmdline`.
4. Extracts and deterministically combines the UKI addon `.cmdline` sections.
5. Requires exactly one SHA-256 `roothash=` and the complete native systemd
   root-verity arguments.
6. Resolves the data and hash partitions by their generated PARTUUID values and
   runs `veritysetup verify`.
7. Rejects global addons that would alter the measured command line.
8. Signs the UKI and systemd-boot with the supplied Secure Boot key.
9. Removes the command-line addons and moves the UKI outside `EFI/Linux` to
   suppress its optionless Type #2 entry.
10. Creates a Type #1 `efi`/`options` entry containing the external command
    line.

The signing certificate must be enrolled in the VM's custom Secure Boot `db`.
The outputs are:

```text
azlinux-roothash-pcr12.vhd
azlinux-roothash-pcr12.vhd.roothash
azlinux-roothash-pcr12.vhd.cmdline
```

Provision the `.roothash` and `.cmdline` files to the verifier through an
authenticated channel. Never accept policy files supplied by the attested VM.

## Collect evidence

The nonce must be fresh verifier-provided hex. The AK context is local to the
attested machine:

```sh
./collect.sh ak.ctx 7f9c... /tmp/attestation
```

The collector quotes SHA-256 PCR 12, writes `quote.msg` and `quote.sig`, and
copies the firmware binary event log. A production policy must also attest the
Secure Boot and UKI identity PCRs, either in an additional quote or in a wider
quote handled by a verifier that validates the full PCR selection.

## Verify evidence

```sh
./verify.sh \
    akpub.pem \
    7f9c... \
    66edc2dedf7a1aecc608d49cb2185415be3c2ba8b075675f9cc8222b41a846f3 \
    azlinux-roothash-pcr12.vhd.cmdline \
    /tmp/attestation
```

Verification fails unless:

- the AK signature and verifier nonce are valid;
- the quote selects exactly SHA-256 PCR 12;
- replaying every SHA-256 PCR 12 event reproduces the quoted PCR value;
- the measured command-line event contains the approved root hash;
- every measured command-line fragment exactly matches the approved policy;
- the event digest matches its raw UTF-16LE event data.

The verifier must authenticate the AK independently. The evidence bundle,
event log, nonce response, and policy transport are otherwise untrusted.

## Requirements

Image build:

- Azure Linux base image;
- Azure Linux Image Customizer with UKI support;
- `binutils`, `sbsign`, `veritysetup`, `util-linux`, and Python 3;
- Secure Boot key and certificate enrolled by the target VM policy;
- patched systemd-stub for a confidential-VM build.

Attested VM and verifier:

- TPM 2.0 with a SHA-256 PCR bank;
- `tpm2-tools`;
- verifier-provisioned AK public key and policy files.

Run the local checks with:

```sh
make check
```
