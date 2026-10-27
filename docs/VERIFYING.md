# Verifying a release

No release of Zero Breach Toolkit has been published yet. When one is, it will be
verifiable in two independent ways: a signature you can check against a key you already
trust, and a build you can reproduce yourself. Use both.

## 1. The publisher's GPG signature

Each release will carry detached GPG signatures for its files and for a `SHA256SUMS.txt`
manifest, made with ArchiveGenocide's established Ed25519 release-signing key, the same
key that signs the archive's other releases. Its full fingerprint is:

    C24E C92B 12D6 670A 2516 065F 9B4D 5754 99AF A53C

Before trusting the key, compare that fingerprint with
[ArchiveGenocide's verification page](https://archivegenocide.com/verify.html) or another
record you already trust. Then:

    gpg --show-keys --with-fingerprint archivegenocide-signing-key.asc
    gpg --import archivegenocide-signing-key.asc
    gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt
    sha256sum -c SHA256SUMS.txt          # macOS: shasum -a 256 -c SHA256SUMS.txt

A warning that the key is "not certified with a trusted signature" is about your own web of
trust; it is different from a BAD signature. Never ignore a fingerprint mismatch or a failed
verification.

## 2. Rebuilding the single file yourself

The second check does not depend on us at all. The single-file scanner is generated from
this repository's source, so you can regenerate it and compare:

    python build/bundle.py
    sha256sum dist/zero-breach-triage.py

If your hash matches the one published with the release, that file holds this source and
nothing else. The build is deterministic, so a mismatch means something is wrong, not merely
different.

Running from source is the other half of the same idea: nothing is compiled, and every line
the tool executes is readable in the clone.

## Why there is no code signature

There is no signed Windows release, and none is planned while this project stays anonymous.
Code-signing certificates require a verifiable legal identity, and every signing route,
including [SignPath Foundation](https://signpath.org/), expects named and publicly
identified maintainers and approvers. This project does not have them, by choice. It
therefore claims no certificate, no signing service and no signed binary, and it asks nobody
to trust it on the strength of one.

Do not trust this project because of a certificate. Rebuild it and compare.

## If you build the Windows executable

Any `.exe` produced from this source with PyInstaller is unsigned and carries no download
reputation, so Windows SmartScreen will warn about it and some antivirus products will flag
it. PyInstaller output is also not byte-reproducible, so the rebuild comparison above
applies to the single-file Python build and not to an executable. Running from source avoids
both problems and is what this project recommends.

## What a signature does and does not tell you

A signature proves who published these exact bytes. It does not prove the program has no
bugs, and an older signed release is not necessarily the latest one. A checksum on its own
is not publisher authentication.

## Indicator updates are a separate trust path

`--update` downloads published indicator lists over HTTPS from a fixed list of official
sources, checks that each file parses before it replaces the previous copy, and records a
SHA-256 for every file; a cached file changed afterwards is refused at scan time. This project
does not sign those lists; they are only as trustworthy as their publishers' own
repositories, and the release signature does not cover them.

What the program sends, and when, is described in [PRIVACY.md](../PRIVACY.md).

## If the signing position ever changes

A signed Windows release would require a named maintainer willing to hold the certificate
and be publicly identified. Before any signed distribution, the project would publish its
build workflow, identify the release roles, require manual approval of signing requests and
document verification of the resulting executable. That decision has not been made, and the
anonymity of the project is the reason.

## Maintainer procedure

Use the release key only through its configured keyring; never export a private key into
this project, GitHub, a chat or logs. Finish and test the release artifacts first, then sign
the manifest; verify with a separate keyring holding only the public key, and confirm that a
modified file is rejected.

`python tools/make_release.py` does those steps in order: it builds the single file twice and
refuses to continue if the two differ, writes `release/v<version>/` with the scanner, the
public key and `SHA256SUMS.txt`, signs the manifest and the scanner (gpg asks for the
passphrase itself), then verifies each signature with a temporary keyring that holds only the
public key and checks that a modified scanner is rejected. It publishes nothing; attaching
the folder's files to a GitHub release is a separate, deliberate step.
