# Unattended signing key on macOS, scoped to a team

## Scope

This document specifies how to hold a private signing key on macOS so that it can be used
without user interaction, is scoped to a set of binaries that can be rotated freely, and
cannot be extracted from the machine. It states what should be built, and why.

The recommended design uses a **Secure Enclave key scoped by a team access group**. A
**keychain ACL pinned to a code requirement** is the documented alternative when an Apple
Developer account is not available; it is fully measured below and is retained for that
reason, but it is not the recommendation.

Two classes of evidence are used, and they are not equivalent:

- **Measured** — reproduced by a script in this repository, named alongside each result.
  Recorded in full in `EVIDENCE.md`.
- **Documented or decoded** — taken from vendor documentation or decoded from real
  artifacts such as provisioning profiles, because the behaviour could not be exercised
  without an Apple Developer account.

All measurements were taken on macOS 26.6.2 (build 25G83), arm64, OpenSSL 3.6.4, command
line tools only, none requiring `sudo`.

### Terminology

| term | meaning |
|---|---|
| **SE key** | a private key generated in and never leaving the Secure Enclave; non-extractable, including by root |
| **data-protection keychain** | the keychain used for SE keys; scoped by entitlement, not by CSSM ACL |
| **legacy file keychain** | the login/System keychain; scoped by CSSM ACL carrying a code requirement |
| **access group** | a string of the form `TEAMID.name` declared as an entitlement and granted by a provisioning profile |
| **pin** | a code requirement in a legacy keychain ACL naming the code permitted to use a key |
| **presence gate** | an SE access-control flag (`UserPresence`, `BiometryAny`, `DevicePasscode`, …) requiring a human per operation |

---

## 1. Recommendation

### 1.1 Primary: Secure Enclave key scoped by a team access group

1. **Generate the key in the Secure Enclave, persistent, with no presence gate.** The key
   is then non-extractable — no ACL, no password, and no root access yields the material —
   and every operation is unattended. `kSecAccessControlPrivateKeyUsage` may be set; it is
   not a presence requirement (§5.2).
2. **Scope access with `keychain-access-groups`**, declaring a stable group of the form
   `TEAMID.com.example.signing`. The group is anchored to the team, not to a certificate or
   a binary hash, so binaries may be rotated and certificates renewed without touching the
   key's access control (§5.1).
3. **Sign every binary that declares the group with the hardened runtime and library
   validation.** With no per-binary pin, this is the control that prevents code injected
   into a group-entitled binary from inheriting the key, rather than defence in depth
   (§6.4). Enforce it in the build pipeline.
4. **Obtain an Apple Developer account.** This design is not reachable without one:
   `keychain-access-groups` is a restricted entitlement and AMFI terminates any binary
   claiming it on a chain it cannot anchor to Apple (§3.2, F9, measured).

### 1.2 Alternative: keychain ACL pinned to a code requirement

Where an Apple Developer account is unavailable, a key in the **legacy file keychain** can
be pinned to a code requirement instead:

5. **Pin the key's ACL to a requirement naming the permitted signers** — a binary directly,
   or a team identity on the leaf certificate. One entry names a set of binaries and refuses
   others (§5.3, measured). This works with a privately operated CA and no account.
6. **Create the key with its final ACL, in the System keychain, during installation or via
   MDM**, because the write is gated by an authorization that root alone does not satisfy
   and no MDM payload key can set a keychain ACL (F5, F6).
7. **Accept two residual exposures that the Secure Enclave path does not have:** the key
   material is recoverable from the keychain container by anyone who can open it, including
   root via `/var/db/SystemKey`; and the ACL entry always carries a prompt alternative that
   grants access to a caller presenting the keychain password, which cannot be suppressed
   (§5.4, measured).

### 1.3 Applying to either path

8. **Keep the machine inside an organisationally controlled management plane** — MDM
   enrolment, supervision, and a recovery lock. This, and not the key's access control, is
   what constrains an administrator. A local administrator defeats a keychain ACL on its
   own, but cannot remove a supervised device from enrolment, cannot reach recoveryOS if a
   recovery lock is set, and cannot bypass an endpoint agent that intercepts the
   authorization request an ACL change depends on. Conversely, on a machine outside such a
   plane an administrator **does** defeat the ACL, because they can take the key material.
   The relevant boundary is therefore *inside the management plane versus outside it*, not
   *administrator versus non-administrator* (§6.2, EVIDENCE §6.4).

### 1.4 A note on trust settings, for the alternative path

Trust settings are the one part of the alternative path that **cannot be established
unattended from the command line, but can be established unattended through MDM.**

Locally, establishing a trust setting for a CA raises an authorization dialog (Touch ID or the
login password) **every time it changes**, including the first time — measured.
`trust-settings-import` prompts on any real modification too, and no command-line option avoids
it. On an unmanaged machine, trust must therefore be established once, interactively, and the CA
must not be regenerated afterwards, because that invalidates the trust and prompts again. The
scripts in this repository refuse to modify trust settings unless `POC_ALLOW_TRUST_CHANGE=1` is
set, so an unattended run fails with an explanation instead of hanging on a dialog.

The dialog is not intrinsic to the operation. It is the fallback that `trustd` takes when the
caller lacks the `com.apple.trust-settings.user` (or `.admin`) entitlement: absent the
entitlement it fails `AuthorizationCopyRights`, which is what raises the dialog. A payload
installer holds the entitlement and therefore sets trust silently. The Certificate payload
(`com.apple.security.root`, and the trust block of `com.apple.security.pkcs12`) carries exactly
the `kSecTrustSettingsPolicy`, `kSecTrustSettingsResult` and `kSecTrustSettingsAllowedError`
values that the local call sets, so the same trust state is reachable from a profile with no user
present (F20). **Deploying the CA by profile is the supported method for this step.**

Two constraints apply. The profile path requires MDM or supervised local profile installation, and
it installs trust rather than a keychain ACL: it does not remove the need for §1.2 step 5 or the
§1.2 step 6 constraint. The recommended Secure Enclave path involves no user trust settings at
all, so this note applies only to the alternative.

### 1.5 Sequencing

Steps 1–3 constitute the recommended design; step 4 is its precondition. Steps 5–7 are an
independent alternative reachable without an account. Step 8 is a precondition for the
integrity of either, and is the critical step because it is the one most easily assumed
to be unnecessary: on an unmanaged machine, an ACL and a hardened binary are both defeated
by the same person they are intended to constrain.

---

## 2. Findings

| ID | question | result | basis | reproduces via |
|---|---|---|---|---|
| F1 | Can a legacy keychain item be pinned to a code requirement? | **yes** | the public API does not expose it; an exported but undeclared SPI does | `run-matrix.sh` |
| F2 | Is a trusted-but-not-pinned signer refused? | **yes** | the requirement is evaluated per call against the caller's actual signature | `run-matrix.sh` |
| F3 | Is the pin a hard boundary? | **no** | the ACL entry is `(requirement matches) OR (user approves)`, and no "never prompt" flag exists | `run-aclstruct.sh`, `run-prompt-approval.sh` |
| F4 | Does the System keychain make the pin tamper-proof? | **only against non-admins** | the store is `0600 root:wheel` and writes require an admin authorization, which a local admin holds | `system.keychain.modify` rule |
| F5 | Can a privilege-management tool install the ACL as root? | **not without authentication** | `system.keychain.modify` is `allow-root=false` with `authenticate-user=true` in group `admin` | `system.keychain.modify` rule |
| F6 | Can MDM set a keychain item ACL, or a partition list? | **no** | no payload key for a keychain item ACL or partition list; the profile machinery reaches `SecAccessCreate` only for the *certificate's* trusted-application list, and offers no requirement-based option (F20) | decoded `CertificateService` |
| F7 | Is a code-identity pin effective against injected code? | **no, unless hardened** | signatures do not cover `dlopen`ed libraries; hardened runtime plus library validation prevents it | `run-injection.sh` |
| F8 | Can a Secure Enclave key be pinned to a binary? | **no** | SE access control has no code-identity field; the nearest equivalent is a team access group | `run-se.sh` |
| F9 | Can a persistent SE key be created without an Apple account? | **no** | `keychain-access-groups` is a restricted entitlement; AMFI terminates signatures it cannot chain to Apple | `run-se.sh` |
| F10 | In a three-tier hierarchy, does the obvious pin isolate a team? | **no — it admits every team** | `certificate root` denotes the *enterprise* root, not the team CA | `run-tiered.sh`, `run-acl-tiered.sh` |
| F11 | Are X.509 name constraints a usable additional control? | **no, given Apple's DN ordering** | a permitted subtree must be a prefix of the RDN sequence; Apple places `CN` first, so an `OU` constraint rejects even correct leaves | `run-nameconstraints.sh` |
| F12 | Does `anchor trusted` work inside a keychain ACL? | **not established** | it matched under the requirement evaluator but denied in an ACL; distinguishing the cause requires `sudo` | `run-reqmatrix.sh` |
| F13 | Can a privilege-management product constrain a local administrator? | **yes** | a supervised Mac cannot be unenrolled, and the agent can gate the authorization request an ACL change requires | vendor documentation (the test machine is not enrolled) |
| F14 | Is the keychain ACL by itself a defence against an administrator? | **no** | an administrator satisfies `system.keychain.modify`, so the ACL must be protected by the management plane | `system.keychain.modify` rule |
| F15 | Can one ACL entry pin several binaries, and still exclude others? | **yes** | a code requirement names a set of code; the entry admits two binaries and refuses a third | `run-acl-tiered.sh` |
| F16 | Does a code-identity pin also prevent extracting the key material? | **no — it is irrelevant to extraction** | export is refused because no ACL entry authorizes it; the container opens for anyone who can open the container | `run-extraction.sh` |
| F17 | Can the ACL prompt be removed, leaving a requirement-only entry? | **no** | `SecAccessCreateFromOwnerAndACL` accepts a prompt-free ACL, but the keychain service re-derives a `cdhash` entry for the creating process on write | `run-extraction.sh`, EVIDENCE §4.2 |
| F18 | Does an SE key require user interaction? | **no, unless a presence gate is requested** | `gate=none` and `gate=privateusage` both sign with no interaction; the presence flags are opt-in | `run-se.sh` |
| F19 | Is the data-protection keychain scoped by code requirement? | **no** | `kSecAttrAccess` is documented macOS-only under *legacy* item attributes; the modern path uses `kSecAttrAccessGroup` | SDK headers, decoded profiles |
| F20 | Can MDM establish CA trust, and a certificate's trusted-application list, without a dialog? | **yes** | `trustd` skips its authorization when the caller carries `com.apple.trust-settings.user`/`.admin`, which the profile installer does; the Certificate payload carries `kSecTrustSettings*` keys and an `addlTrustedApps` list, and `CertificateService` builds those ACLs itself | decoded `trustd` and `CertificateService`, Apple payload documentation |

F3, F16, F17 and F19 are the findings that determine the design. F16 and F17 together are
the reason the ACL is not a complete control: it neither prevents extraction nor omits the
prompt. F19 is the reason the Secure Enclave path has no prompt to defeat at all, and F3 is
why the ACL path always does.

---

## 3. The role of the Apple Developer account

On the recommended path the account is a precondition, not an option. It is also the only
reason the account is needed at all: the account itself grants nothing, but it is the only
route to a provisioning profile, and a provisioning profile is the only way to be granted a
restricted entitlement.

### 3.1 Two independent trust roots

Signing a binary answers the question "who certified this code?". Two answers can coexist on
one binary, and they serve different validators. In both cases the private key remains under
local control; Apple never has access to it. Obtaining a Developer ID certificate is
structurally identical to operating a private CA:

```
private CA:     leaf -> POC Private Root CA 1                                  (locally signed)
Developer ID:   leaf -> Developer ID Certification Authority -> Apple Root CA   (Apple-signed)
```

The distinction is which CA key is held by whom, and therefore whose validation the signature
satisfies. Decoding an installed application shows the shape (`run-profile.sh`):

```
Authority=Developer ID Application: AgileBits Inc. (2BUA8C4S2C)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=2BUA8C4S2C
```

### 3.2 Restricted versus unrestricted entitlements

The ACL mechanism is independent of CA identity: it evaluates a code requirement against the
caller's signature, and a privately operated CA is a valid anchor for that. What a private CA
cannot do is satisfy validation performed inside Apple's own code, because AMFI and Gatekeeper
anchor to Apple and disregard the user's trust settings. Measured:

```
non-restricted entitlement (com.apple.security.cs.disable-library-validation),
  signed by a private CA                  -> runs
restricted entitlement (keychain-access-groups),
  signed by a private CA                  -> SIGKILL at launch
```

AMFI's stated reason is `Unable to retrieve certificate chain`. Adding the CA to the user
trust store does not alter this, because AMFI's anchor set is not the user's trust settings.

The dividing line is therefore not "signed versus unsigned" but **restricted versus
unrestricted entitlements**. `keychain-access-groups` is restricted, so the recommended design
requires the account; the ACL-based alternative claims no restricted entitlement and therefore
does not.

### 3.3 Provisioning profiles

A provisioning profile is Apple's signed authorization binding a team, a set of certificates
and a set of entitlements. Decoded from an installed application:

```
"TeamIdentifier"          => [ "2BUA8C4S2C" ]
"keychain-access-groups"  => [ "2BUA8C4S2C.*" ]
DeveloperCertificates listed: 2
```

AMFI verifies three conditions: the signature chains to Apple, the signing certificate appears
in `DeveloperCertificates`, and the profile grants the entitlement being claimed. The profile
grants a **prefix**; the binary declares concrete groups beneath it (§5.1).

### 3.4 When an account is not required

Signing with a Developer ID certificate does not require a provisioning profile: a Developer ID
`launchd` background service inspected on this machine carries no entitlements at all, because
it claims no restricted entitlement. A profile is required only when a restricted entitlement
is claimed. For the ACL-based alternative, therefore, the account is needed only for
notarization and for Gatekeeper on machines outside administrative control, not for the pin.

---

## 4. PKI structure

```
Enterprise Root CA                 self-signed, pathlen:1, held offline
  |
  +-- Team A Intermediate CA       pathlen:0, held by team A
  |     +-- signing leaf            OU=TEAMA
  |
  +-- Team B Intermediate CA       pathlen:0, held by team B
        +-- signing leaf            OU=TEAMB
```

The enterprise root signs team intermediates only and remains offline; each team CA signs only
its own leaves. `pathlen:1` on the root and `pathlen:0` on each team CA prevent a team CA from
creating further CAs, which bounds the damage from a compromised team CA. This is the **only**
X.509-layer constraint available here, for the reason given in F11.

The team identity appears in two places, and they serve different mechanisms:

- **`OU` on the leaf certificate** — what the ACL-based alternative pins
  (`certificate leaf[subject.OU]`), and what Apple's own designated requirements use.
- **the Team ID prefix on the access group** — what the Secure Enclave path is scoped by.

Both are team-level and stable across certificate and binary rotation, which is why either
survives renewal. Where the account is in use, the leaf is issued under the Developer ID
identity so that one certificate serves both mechanisms.

The two mechanisms draw on different certificate paths, and only one of them involves a
privately operated CA:

- **Recommended path (Secure Enclave, access group).** The leaf is a Developer ID certificate.
  Access is granted by the `keychain-access-groups` entitlement, and that entitlement is
  granted by the **provisioning profile**, not by the certificate: the profile carries
  `"TeamIdentifier" => [ "TEAMID" ]` and grants the prefix `TEAMID.*`, and AMFI verifies the
  profile, the Apple-anchored chain and the signing certificate together (§3.3). **No
  privately operated CA is involved anywhere on this path.**
- **Alternative path (ACL, code requirement).** A code requirement needs an anchor, so this
  path needs either a Developer ID certificate pinned through `OU`, or a privately operated
  CA — the latter only where per-application granularity or a leaf-hash pin is wanted, since a
  root under local control is stable indefinitely (EVIDENCE §9.4).

The hierarchy above is therefore the **alternative** path's structure. Adopting a Developer ID
certificate on the recommended path does not replace the team CA with an Apple-issued one; it
removes the CA from that path altogether. Correspondingly, the only pin form that does not
survive renewal is `certificate leaf = H"…"` (EVIDENCE §9.4), which is the form to avoid on the
alternative path.

---

## 5. Key scoping

### 5.1 Team access group (Secure Enclave path)

Access is governed by the `keychain-access-groups` entitlement rather than by any code
requirement. The profile grants a team prefix and the binary declares concrete groups
underneath it, decoded from a real application:

```
profile grants:   "2BUA8C4S2C.*"
binary declares:  2BUA8C4S2C.com.example.webauthn
                  2BUA8C4S2C.com.example.hwkey
```

Two consequences follow, and both are the properties the design depends on:

- **The group string is chosen by the team and is stable.** A rebuilt binary declaring the
  same group reaches the same key. No re-pinning is required, at any rotation frequency.
- **Cross-team access is refused.** A binary from another team cannot declare that prefix,
  because the prefix is not authorised by *its* profile.

The scope is the **team**, not a binary or a certificate hash. This is intentional: binary
rotation requires no action, at the cost of per-binary granularity. The alternatives are
compared by what invalidates them:

| scope | invalidated by |
|---|---|
| `certificate leaf = H"…"` (ACL) | certificate renewal, or any rebuild with a new certificate |
| `certificate leaf[subject.OU]` (ACL) | leaving the team |
| `keychain-access-groups` (SE) | leaving the team |

> **Basis.** This subsection is from decoded provisioning profiles and SDK documentation, not
> from measurement: a persistent data-protection item cannot be created without the
> entitlement (F9). §7 records the specific test to run once an account exists.

### 5.2 No presence gate is imposed

An SE key requires no user interaction unless a presence gate is requested. Only these flags
impose one:

```
= 1u << 0   UserPresence          = 1u << 1   BiometryAny
= 1u << 3   BiometryCurrentSet    = 1u << 4   DevicePasscode
= 1u << 5   Companion
```

`kSecAccessControlPrivateKeyUsage` is documented as "create access control for private key
operations (i.e. sign operation)" — it is a marker about how the key is used, not a demand for a
human, and it coexists with the team-group scope. Measured, both unattended:

```
gate=none           VERDICT: SECURE ENCLAVE  SIGN OK -> no user interaction required
gate=privateusage   VERDICT: SECURE ENCLAVE  SIGN OK -> no user interaction required
```

The presence gates exist for the opposite use case — SE keys backing operations a human
authorises, such as payments or unlocking a credential store — where requiring proof of presence
is the point. They are capabilities rather than requirements, and an unattended signer does not
select them.

### 5.3 Code requirement (ACL-based alternative)

A code requirement identifies *code*, and a binary is code, so the key can be pinned directly
to the binary, or the set of binaries, that should hold it:

```
identifier "com.example.signer" and certificate leaf[subject.OU] = "TEAMA"
```

Measured (`run-acl-tiered.sh`):

| caller | `pin-teamA-via-OU` |
|---|---|
| teamA1 | GRANTED |
| teamA2 | GRANTED |
| teamB1 | deny-use |

One entry admits several binaries and refuses others, so a multi-client deployment needs one
requirement naming the set, not one entry per client.

The ACL gates key **operations**: the authorizations attached to an entry are
`ACLAuthorizationSign`, `Decrypt`, `Derive`, `ExportClear` and similar. There is no tag for
content, context, frequency or requester identity, so any code the requirement admits may sign
arbitrary bytes with the key, as often as it likes, unrecorded. That is a property of what the
ACL expresses, not a defect of it.

### 5.4 The two exposures the ACL path carries

Both are measured, and neither is present on the Secure Enclave path.

**The pin does not protect the key material.** Extraction is refused only because no ACL entry
authorizes it, which is a property of how the ACL was constructed rather than of pinning:

```
1. lookup key ref         : 0 No error.
2. use it (sign)          : DENIED (-25293)
3. take it (copy raw key) : DENIED (-25293)
4. ACL entries            : [0] ACLAuthorizationDecrypt,ACLAuthorizationSign
                            [1] ACLAuthorizationChangeACL
```

There is no `ExportClear` entry at all. The key material nevertheless remains in the keychain
container, and a container-level read consults no ACL: an administrator reading
`/var/db/SystemKey`, or anyone who can open the keychain with its password, obtains the key.
A Secure Enclave key is generated in and never leaves the SEP, so that route does not exist.

**The ACL entry always retains a prompt alternative, and it cannot be removed.** The stored
entry is a threshold subject with two alternatives, from the `securityd` log:

```
ThresholdAclSubject(1 of 2)[
    CodeSignatureAclSubject[requirement: identifier "…" and certificate 1 = H"…"]
][
    KeychainPromptAclSubject(flags: 0x0, desc:pin-teamA)
]
```

"1 of 2" means the requirement matching **or** the user approving satisfies the entry. The
prompt demands the **keychain password**, not a bare click, measured
(`run-prompt-approval.sh`):

```
pocclient-signedB wants to sign using key "prompt-approval-test" in your keychain.
To allow this enter the "poc-test" keychain password.
Password:                    buttons:  Always Allow | Deny | Allow
→ filled password and clicked Allow → RESULT: GRANTED
```

`Always Allow` additionally persists the caller into the ACL; `Allow` grants a single use without
modifying stored state. The prompt cannot be suppressed: `SecKeychainPromptSelector` offers
`RequirePassphase`, `Unsigned`, `UnsignedAct`, `Invalid` and `InvalidAct`, and nothing meaning
"deny instead of prompting"; passing `0` still produces the prompt subject. Hand-building a
prompt-free ACL at the CSSM level does not survive being attached to a key — the keychain
service re-derives a `cdhash` entry for the creating process on write, and that entry also grants
`ExportClear` (F17, EVIDENCE §4.2).

The consequence is that the pin is a boundary against *silent* access, not against a caller that
can present a dialog to someone holding the keychain password. The Secure Enclave path has no
ACL, so it has no prompt to defeat (F19).

---

## 6. Deployment

### 6.1 Creating the Secure Enclave key

```objc
// No presence gate: the flags below are the only ones that impose user interaction.
SecAccessControlRef ac = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAccessControlPrivateKeyUsage,          /* not a presence requirement */
    &err);

NSDictionary *params = @{
    (__bridge id)kSecAttrKeyType:       (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
    (__bridge id)kSecAttrKeySizeInBits: @256,
    (__bridge id)kSecAttrTokenID:       (__bridge id)kSecAttrTokenIDSecureEnclave,
    (__bridge id)kSecAttrAccessControl: (__bridge id)ac,
    (__bridge id)kSecAttrAccessGroup:   @"TEAMID.com.example.signing",  /* team-scoped */
    (__bridge id)kSecAttrIsPermanent:   @YES,
    (__bridge id)kSecUseDataProtectionKeychain: @YES,
};
SecKeyCreateRandomKey((__bridge CFDictionaryRef)params, &err);
```

The binary must declare the matching `keychain-access-groups` entitlement, its profile must
grant the prefix, and the key must be created on the machine that will hold it: SE keys are
per-machine and non-portable. That is the security property the design relies on, and it also
means a host that dies takes its key with it, so provisioning must allow for N+1 capacity or a
rebuild path.

**Assert the two hardware properties at startup.** An SE request can silently degrade: asking
for a persistent key while targeting the legacy keychain produces a software key, with no error
at all (F9 note, EVIDENCE §8.2):

```
persistent, legacy file keychain   VERDICT: SOFTWARE KEY (SE not used)
  kSecAttrTokenID: (absent)
  SecKeyCopyExternalRepresentation: SUCCEEDED -> key material is extractable
```

A genuine SE key reports `tkid = com.apple.setoken` and refuses export (`extr = 0`). Check both,
or the downgrade is invisible.

### 6.2 Keychain selection

| | legacy file keychain | data-protection keychain (SE path) |
|---|---|---|
| scoped by | CSSM ACL carrying a code requirement | `keychain-access-groups` entitlement |
| granularity | one binary, or a set named by a requirement | team |
| prompt alternative | always present | none |
| key material | extractable by anyone who can open the container | never leaves the SEP |
| needs a Developer account | no | yes |

For the ACL-based alternative, the System keychain is the correct location for a machine-wide
key, and its protection is real (measured): `system-keychain-2.db` is `0600 root:wheel`,
`/var/db/SystemKey` is `0400 root`, and the store is not writable by a non-admin. Alteration of
an item's access is separately gated:

```
system.keychain.modify:  allow-root        = false
authenticate-user = true
                         group             = admin
```

uid 0 is not sufficient, so a privilege-management tool cannot *silently* rewrite the ACL. It
does not follow that an administrator is unable to alter it — see §6.5. This is also why the key
should be created with its final ACL during installation or via MDM, where the authorisation is
already satisfied, rather than corrected afterwards from a root agent.

No MDM payload key can set a *keychain item* ACL or partition list (F6), so for the
ACL-pinned key MDM installs the identity and the ACL is whatever the installing code chose.
The profile machinery does build keychain ACLs — `CertificateService` calls `SecAccessCreate`
and `SecACLCreateWithSimpleContents` for imported identities — but only to attach the
certificate's trusted-application list, and only from an `addlTrustedApps` array of bundle
identifiers or app-group identifiers. There is no requirement-based option anywhere in that
path: the SPI this repository depends on (`SecTrustedApplicationCreateFromRequirement`) is
never called by it. A profile can therefore pin a *certificate* to named applications, but it
cannot express the signer requirement, and it cannot set an item's ACL. That gap is the reason
privilege-management tooling is reached for at all, and it has a direct consequence:

> **The privilege-management policy becomes part of the trusted computing base.** The tool that
> installs the ACL is the tool that can remove it. If the allowlist permits an end user to run
> anything capable of calling `SecKeychainItemSetAccess` — `security`, a generic installer, or
> any equivalent — the ACL is bypassable and the control is ineffective. The allowlist must be
> narrow, managed by MDM, and audited. An endpoint agent on macOS can match on the authorization
> request that `SecKeychainItemSetAccess` depends on and deny it (§6.5).

### 6.3 Installing an ACL from code (alternative path only)

```objc
// Declared in Apple's open source SecTrustedApplicationPriv.h, exported from
// Security.framework, absent from the public SDK headers. This is the only route to a
// signer pin: SecTrustedApplicationCreateFromPath always produces a path-based entry,
// including for Apple-signed binaries.
extern OSStatus SecTrustedApplicationCreateFromRequirement(
        const char *description, SecRequirementRef requirement,
        SecTrustedApplicationRef *app);

SecRequirementRef req = NULL;
SecRequirementCreateWithString(
    CFSTR("identifier \"com.example.signer\" and certificate leaf[subject.OU] = \"TEAMA\""),
    kSecCSDefaultFlags, &req);

SecTrustedApplicationRef app = NULL;
SecTrustedApplicationCreateFromRequirement("pinned", req, &app);

SecAccessRef access = NULL;
SecAccessCreate(CFSTR("pinned"), (__bridge CFArrayRef)@[ (__bridge id)app ], &access);

// Remove the default ACL entries, then add only the requirement entry. This step is
// load-bearing: SecAccessCreate's defaults include ExportClear, ExportWrapped and
// Derive, so a key built without it grants export rights that a pin is not expected to.
CFArrayRef existing = NULL;
SecAccessCopyACLList(access, &existing);
for (CFIndex i = 0; i < CFArrayGetCount(existing); i++)
    SecACLRemove((SecACLRef)CFArrayGetValueAtIndex(existing, i));

SecACLRef acl = NULL;
SecACLCreateWithSimpleContents(access, (__bridge CFArrayRef)@[ (__bridge id)app ],
                               CFSTR("pinned"), 0 /* no prompt request */, &acl);
SecACLUpdateAuthorizations(acl, (__bridge CFArrayRef)@[
        (__bridge id)kSecACLAuthorizationDecrypt,
        (__bridge id)kSecACLAuthorizationSign ]);

NSDictionary *params = @{
    (__bridge id)kSecAttrKeyType:       (__bridge id)kSecAttrKeyTypeRSA,
    (__bridge id)kSecAttrKeySizeInBits: @2048,
    (__bridge id)kSecAttrIsPermanent:   @YES,
    (__bridge id)kSecAttrLabel:         @"signing-key",
    (__bridge id)kSecAttrAccess:        (__bridge id)access,
    (__bridge id)kSecPrivateKeyAttrs:   @{ (__bridge id)kSecAttrAccess: (__bridge id)access },
};
SecKeyCreateRandomKey((__bridge CFDictionaryRef)params, NULL);
```

`tools/pocsetup.m` implements this, together with `dumpacl` for reading back what was stored.
The requirement persists into the stored item and is retrievable with
`SecTrustedApplicationCopyRequirement`, so it is a stable, inspectable property.

These mechanics belong to the legacy **file** keychain. The item must be created in, or moved
to, a file keychain for `kSecAttrAccess` to apply; the data-protection keychain scopes access by
entitlement access group instead (EVIDENCE §3, EVIDENCE §9.3).

### 6.4 Controls required on either path

**Hardened runtime with library validation.** Measured:

```
BINARY                             INJECTED CODE                     PROCESS RESULT
signed, no runtime                 signed 256 bytes -> obtained key  GRANTED
signed --options runtime           not loaded (injection blocked)    GRANTED
```

The injected library is unsigned and chains to no CA. Injected into a binary signed without the
hardened runtime, it signs successfully with the pinned key. The same binary signed with
`--options runtime` retains its own access while refusing the foreign library, because the
hardened runtime makes dyld ignore `DYLD_INSERT_LIBRARIES` and enables library validation.
Neither `com.apple.security.cs.allow-dyld-environment-variables` nor
`...disable-library-validation` should be added. On the recommended path this is not defence in
depth but the primary control, because there is no per-binary pin behind it.

### 6.5 What constrains an administrator

The keychain ACL, considered alone, is defeated by an administrator who can satisfy
`system.keychain.modify` (measured, §6.2). On a file keychain, root or an equivalent reader of
`/var/db/SystemKey` can additionally recover the key material directly. Those are properties of
*that control on an unmanaged machine*.

An administrator on a supervised, managed Mac cannot remove the management plane, and the
management plane can gate the very authorization an ACL change requires. The boundary is the
enrolment, not the administrator bit.

| control | effect on an administrator | source |
|---|---|---|
| Supervision | "A supervised device can't be unenrolled by the user. On Mac computers, this prevents unenrollment from System Settings as well as from the `profiles` command-line tool." | Apple Platform Deployment, *Automated Device Enrollment* |
| Non-removable enrolment profile | Automated Device Enrollment offers "the option to prevent the user from removing the device management service's enrollment profile" | same |
| Recovery lock | settable **only** by MDM; without it "they can't access the recovery environment, including the Startup Options screen" | same, *Startup security* |
| Boot-policy changes | on Apple silicon, policy changes require restarting into recoveryOS by holding the power button, "so that malware can't trigger the signal, only a human with physical access can" — which the recovery lock gates | same |
| MDM restrictions | can prevent an administrator "from creating new users in Users & Groups", prevent changing account settings, prevent manually installing configuration profiles, and require an administrator password to install or update apps | same, *Restrictions for Mac* |
| Bootstrap token | escrowed to MDM at first secure-token login; enables supervision, silent Erase All Content and Settings, and authorizing software updates | same, *Use secure and bootstrap tokens* |

The first row determines the outcome: removing an endpoint agent or rewriting an ACL achieves
nothing durable, because the device remains managed. "The user has `sudo`" and "the user can
leave the management plane" are different statements.

**Endpoint agents close the gap identified in §6.2.** The ACL is gated by an authorization right
that an administrator can satisfy, serviced through macOS Authorization Services, and the
documented macOS capability of an endpoint privilege management agent is to match on the
*authorization request URI* and apply block, allow or audit:

> "This applies to anything in macOS that has a padlock on the dialog box or where the system
> requires authorization to change something. … This matching criteria allows you to target any
> authorization request by matching the Auth Request URI, allowing you to target that specific
> Auth Request URI and apply your own controls."
> — BeyondTrust, *Application definitions for macOS*

Two dependencies bound this, both from documentation rather than measurement: the agent's own
integrity on macOS is not established by those sources (they describe enablement in Windows
registry terms and a `sudo`-runnable macOS uninstall), and the enrolment's integrity is now part
of the key's threat model, because unenrolment through the management service removes the
recovery lock and the constraints.

---

## 7. Limitations

Items not established. The first three could not be measured for want of an Apple Developer
account; the next two for want of administrator rights; the last is a documentation gap.

1. **Team-group scoping, end to end.** §5.1 rests on decoded provisioning profiles and SDK
   documentation. A persistent data-protection item cannot be created without the entitlement —
   even a generic password returns `-34018` — so the two properties the design depends on are
   unverified. **This is the highest-value test to run first**, and it is quick: sign two
   distinct binaries declaring the same group and confirm both reach the key; then confirm a
   third declaring a different group is refused.

2. **That the data-protection keychain is prompt-free.** F19 says it is scoped by entitlement
   rather than CSSM ACL, and no ACL entry means no `KeychainPromptAclSubject`. This is reasoning
   from the mechanism: the absence of an ACL prompt on that path was not observed, because no
   item could be created on it.

3. **Non-extractability of a persistent SE key.** Measured only on an *ephemeral* SE key
   (F9 note): genuine SE keys report `tkid = com.apple.setoken`, refuse
   `SecKeyCopyExternalRepresentation` with `-4`, and carry `extr = 0`. The persistent case
   requires the entitlement and was not exercised.

4. **Whether the System-keychain use prompt demands administrator credentials.** For a file
   keychain the prompt asks for that keychain's password and supplying it grants access
   (measured, §5.4); the prompt does not accept a bare confirmation. It follows that the System
   keychain equivalent should demand administrator credentials. Untested, because it requires
   administrator rights. Procedure: Appendix A.

5. **Whether `anchor trusted` functions inside a keychain ACL (F12).** It matched under
   `SecStaticCodeCheckValidity` but denied every caller when stored in an ACL. The probable cause
   is trust domain: the CAs are trusted in the user domain and `securityd` runs as root, so it may
   consult only the admin and system trust settings. Establishing this requires `sudo`. Until it
   is resolved, explicit `certificate leaf` pins should be preferred, since they require no trust
   evaluation to decide.

6. **Whether the agent-protection feature of an endpoint privilege management product covers
   macOS** (§6.5). Affects how the agent resists removal, not whether removal is useful, because
   supervision prevents unenrolment independently.

### 7.1 Test order, once an account exists

1. Create a persistent SE key with `kSecAccessControlPrivateKeyUsage`, no presence gate, one
   access group. Assert `tkid = com.apple.setoken` and that export is refused.
2. Sign two binaries declaring the same group; confirm both use the key with no interaction.
3. Sign a third binary declaring a group *not* under the team prefix; confirm it is refused.
4. Re-sign one binary with a new certificate and confirm that access is unchanged; this is the
   rotation property the design depends on.
5. Confirm no keychain prompt is reachable, by running a non-declaring binary and checking that it
   fails outright rather than offering a dialog.

---

## Appendix A. Procedures for the unmeasured items

To determine whether the System-keychain use-prompt is admin-gated, on a machine where
administrator rights are held:

```bash
sudo security add-generic-password -a acldemo -s acldemo -w secret \
     -k /Library/Keychains/System.keychain
# Pin the item's ACL to a code requirement, then run a non-matching binary while
# logged in as a NON-admin user, with keychain UI enabled (POC_ALLOW_UI=1):
#   denied outright          -> hard enforcement for non-admins (desirable outcome)
#   admin credential prompt  -> acceptable, since non-admins cannot satisfy it
#   ordinary user prompt     -> the limitation in §5.4 applies in the System keychain too
```

To resolve F12:

```bash
sudo security add-trusted-cert -d -r trustRoot -p codeSign \
     -k /Library/Keychains/System.keychain pki/ent/ent-root.crt
./run-tiered.sh && ./run-acl-tiered.sh    # does the anchor-trusted row match?
```

---

## Appendix B. Sources

**Measured locally.** Everything in `EVIDENCE.md` marked `(measured)`, on macOS 26.6.2 (build
25G83), arm64: keychain ACL behaviour, code-requirement evaluation, entitlement rejection by
AMFI, code injection, ACL prompt behaviour, key extraction, and the permission bits and
authorization rules governing the System keychain.

**Decoded from artifacts.** The provisioning-profile structure in §3.3 and §5.1 was extracted
from installed applications with `run-profile.sh` and `security cms -D`. The payload and
trust-setting behaviour in F6 and F20 was decoded from the system binaries that implement it —
`/usr/libexec/trustd` for the entitlement that gates a trust-settings write, and
`ConfigurationProfiles.framework/XPCServices/CertificateService.xpc` for the payload keys, the
trust values applied, and the ACL construction described in §6.2.

**Documented by the vendor.** The claims in §6.5 come from vendor documentation rather than
measurement, because the machine used for this work is not MDM-enrolled
(`profiles status -type enrollment` reports "MDM enrollment: No") and cannot exhibit the
behaviour described.

| topic | source |
|---|---|
| Supervision prevents unenrolment; Automated Device Enrollment options; supervised restrictions | Apple, *Apple Platform Deployment* — "Automated Device Enrollment and device management", "Restrictions for Mac", "Restrictions for supervised devices" |
| Recovery lock, startup security, Apple silicon boot-policy gating | Apple, *Apple Platform Deployment* — "Startup security" |
| Secure token, bootstrap token, volume ownership | Apple, *Apple Platform Deployment* — "Use secure token, bootstrap token, and volume ownership in deployments" |
| Endpoint privilege management model; macOS authorization request matching; agent protection | BeyondTrust, *Endpoint Privilege Management for Windows and Mac* — "Application definitions and types (macOS)", "Policy editor utilities", "Uninstall EPM clients and adapters" |
| Access-control flag semantics | `Security/SecAccessControl.h`; `Security/SecItem.h` for the legacy-versus-data-protection attribute distinction |
| Certificate and trust payload keys; unattended trust establishment | Apple, *Device Management* — `com.apple.security.root` and `com.apple.security.pkcs12` payload documentation; corroborated by decoding `trustd` and `CertificateService` |

`tools/fetch_apple_doc.py` and `tools/fetch_readme_doc.py` retrieve and extract the text of those
documentation pages, so the quotations in §6.5 can be re-derived rather than taken on trust.

---

## Appendix C. Document map

| document | contents |
|---|---|
| `README.md` | the recommendation and the reasoning behind it |
| `EVIDENCE.md` | the measurements: result matrices, log excerpts, negative results, platform notes, and the end-to-end run order |
| `pki/` | certificate authority and leaf certificate material, with the OpenSSL configurations used to generate it |
| `tools/` | source for the test utilities |
| `bin/` | built utilities and the signed test clients |
| `work/` | keychains, PKCS#12 archives, and pinned-requirement records |
| `run-*.sh` | the reproduction scripts, tabulated in §2 |
| `tools/fetch_apple_doc.py`, `tools/fetch_readme_doc.py` | retrieve and extract the vendor documentation cited in Appendix B |
