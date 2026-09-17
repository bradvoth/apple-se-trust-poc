# Unattended signing key on macOS, scoped to a team

## Scope

This document specifies how to hold a private signing key on macOS so that it can be used
without user interaction, is scoped to a set of binaries that can be rotated freely, and
cannot be extracted from the machine. It states what should be built, and why.

There is **one recommended design: a Secure Enclave key scoped by a team access group**. It is
the whole of this document. A second design — a keychain ACL pinned to a code requirement, for use
where an Apple Developer account is not available — was investigated and is documented separately
in [`ALT-ACL-PATH.md`](ALT-ACL-PATH.md). It is not a second recommendation and is not developed
here; the findings that rule it out appear in §2 because they are part of this design's
justification, and they are marked as belonging to it.

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
| **legacy file keychain** | the login/System keychain, used by the alternative path; scoped by CSSM ACL carrying a code requirement |
| **access group** | a string of the form `TEAMID.name` declared as an entitlement and granted by a provisioning profile |
| **presence gate** | an SE access-control flag (`UserPresence`, `BiometryAny`, `DevicePasscode`, …) requiring a human per operation |

---

## 1. Recommendation

### 1.1 Secure Enclave key scoped by a team access group

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
   (§6.3). Enforce it in the build pipeline.
4. **Obtain an Apple Developer account.** This design is not reachable without one:
   `keychain-access-groups` is a restricted entitlement and AMFI terminates any binary
   claiming it on a chain it cannot anchor to Apple (§3.2, F9, measured).
5. **Keep the machine inside an organisationally controlled management plane** — MDM
   enrolment, supervision, and a recovery lock. This, and not the key's access control, is
   what constrains an administrator: a supervised device cannot be unenrolled, a recovery
   lock closes recoveryOS, and restrictions can be placed on an administrator who holds
   `sudo` (§6.4, EVIDENCE §6.4).

### 1.2 The alternative, and why it is not the recommendation

Where an Apple Developer account is unavailable, a key in the legacy file keychain can be pinned
to a code requirement instead. That design was investigated and is documented in
[`ALT-ACL-PATH.md`](ALT-ACL-PATH.md). It is not a variant of the design above and nothing on this
page depends on it. It is named here only so that it is not mistaken for a fallback to it. Three
measured properties separate the two, and none of them can be configured away: the key material
stays in a container that root can read, because the pin governs the ACL and not the container;
the ACL always retains a keychain-password prompt alternative that cannot be suppressed; and the
scope it expresses is code rather than a team, so everything finer than a team pin has to be
re-pinned when a certificate is renewed (F15, F16, F17; EVIDENCE §4.3, §9.4).

### 1.3 Sequencing

Steps 1–3 constitute the design; step 4 is its precondition. Step 5 is required for the integrity
of the design, and is the step most easily assumed to be unnecessary.

---

## 2. Findings

| ID | question | result | basis | path | reproduces via |
|---|---|---|---|---|---|
| F1 | Can a legacy keychain item be pinned to a code requirement? | **yes** | the public API does not expose it; an exported but undeclared SPI does | alternative | `run-matrix.sh` |
| F2 | Is a trusted-but-not-pinned signer refused? | **yes** | the requirement is evaluated per call against the caller's actual signature | alternative | `run-matrix.sh` |
| F3 | Is the pin a hard boundary? | **no** | the ACL entry is `(requirement matches) OR (user approves)`, and no "never prompt" flag exists | alternative | `run-aclstruct.sh`, `run-prompt-approval.sh` |
| F4 | Does the System keychain make the pin tamper-proof? | **only against non-admins** | the store is `0600 root:wheel` and writes require an admin authorization, which a local admin holds | alternative | `system.keychain.modify` rule |
| F5 | Can a privilege-management tool install the ACL as root? | **not without authentication** | `system.keychain.modify` is `allow-root=false` with `authenticate-user=true` in group `admin` | alternative | `system.keychain.modify` rule |
| F6 | Can MDM set a keychain item ACL, or a partition list? | **no** | no payload key for a keychain item ACL or partition list; the profile machinery reaches `SecAccessCreate` only for the *certificate's* trusted-application list, and offers no requirement-based option (F20) | alternative | decoded `CertificateService` |
| F7 | Is a code-identity pin effective against injected code? | **no, unless hardened** | signatures do not cover `dlopen`ed libraries; hardened runtime plus library validation prevents it | both | `run-injection.sh` |
| F8 | Can a Secure Enclave key be pinned to a binary? | **no** | SE access control has no code-identity field; the nearest equivalent is a team access group | recommended | `run-se.sh` |
| F9 | Can a persistent SE key be created without an Apple account? | **no** | `keychain-access-groups` is a restricted entitlement; AMFI terminates signatures it cannot chain to Apple | recommended | `run-se.sh` |
| F10 | In a three-tier hierarchy, does the obvious pin isolate a team? | **no — it admits every team** | `certificate root` denotes the *enterprise* root, not the team CA | alternative | `run-tiered.sh`, `run-acl-tiered.sh` |
| F11 | Are X.509 name constraints a usable additional control? | **no, given Apple's DN ordering** | a permitted subtree must be a prefix of the RDN sequence; Apple places `CN` first, so an `OU` constraint rejects even correct leaves | alternative | `run-nameconstraints.sh` |
| F12 | Does `anchor trusted` work inside a keychain ACL? | **not established** | it matched under the requirement evaluator but denied in an ACL; distinguishing the cause requires `sudo` | alternative | `run-reqmatrix.sh` |
| F13 | Can a privilege-management product constrain a local administrator? | **yes** | a supervised Mac cannot be unenrolled, and the agent can gate the authorization request an ACL change requires | both | vendor documentation (the test machine is not enrolled) |
| F14 | Is the keychain ACL by itself a defence against an administrator? | **no** | an administrator satisfies `system.keychain.modify`, so the ACL must be protected by the management plane | alternative | `system.keychain.modify` rule |
| F15 | Can one ACL entry pin several binaries, and still exclude others? | **yes** | a code requirement names a set of code; the entry admits two binaries and refuses a third | alternative | `run-acl-tiered.sh` |
| F16 | Does a code-identity pin also prevent extracting the key material? | **no — it is irrelevant to extraction** | export is refused because no ACL entry authorizes it; the container opens for anyone who can open the container | alternative | `run-extraction.sh` |
| F17 | Can the ACL prompt be removed, leaving a requirement-only entry? | **no** | `SecAccessCreateFromOwnerAndACL` accepts a prompt-free ACL, but the keychain service re-derives a `cdhash` entry for the creating process on write | alternative | `run-extraction.sh`, EVIDENCE §4.2 |
| F18 | Does an SE key require user interaction? | **no, unless a presence gate is requested** | `gate=none` and `gate=privateusage` both sign with no interaction; the presence flags are opt-in | recommended | `run-se.sh` |
| F19 | Is the data-protection keychain scoped by code requirement? | **no** | `kSecAttrAccess` is documented macOS-only under *legacy* item attributes; the modern path uses `kSecAttrAccessGroup` | recommended | SDK headers, decoded profiles |
| F20 | Can MDM establish CA trust, and a certificate's trusted-application list, without a dialog? | **yes** | `trustd` skips its authorization when the caller carries `com.apple.trust-settings.user`/`.admin`, which the profile installer does; the Certificate payload carries `kSecTrustSettings*` keys and an `addlTrustedApps` list, and `CertificateService` builds those ACLs itself | alternative | decoded `trustd` and `CertificateService`, Apple payload documentation |

The `path` column says which design a finding bears on. The findings that shape this one are:

- **F8, F9, F18 and F19.** An SE key cannot express a code-identity policy at all, so its scope is
  a team access group rather than a pin; a persistent one requires an Apple-issued restricted
  entitlement; and it imposes no presence gate and carries no ACL prompt to defeat.
- **F7 and F13.** The two controls this design rests on: hardened runtime for the binaries that
  declare the group, and a management plane that bounds an administrator.

The remaining rows — F1–F6, F10–F12, F14–F17 and F20 — measure the alternative documented in
`ALT-ACL-PATH.md`. They are retained here because they are the negative results behind the
recommendation, F16 and F17 in particular: the ACL neither prevents extraction nor omits the
prompt.

---

## 3. The role of the Apple Developer account

The account is a precondition, not an option. It is also the only reason the account is needed at
all: the account itself grants nothing, but it is the only route to a provisioning profile, and a
provisioning profile is the only way to be granted a restricted entitlement.

### 3.1 The signing certificate

Signing a binary answers the question "who certified this code?". The certificate in this design
is a Developer ID certificate, and the private key remains under local control; Apple never has
access to it. Decoding an installed application shows the shape (`run-profile.sh`):

```
Authority=Developer ID Application: AgileBits Inc. (2BUA8C4S2C)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=2BUA8C4S2C
```

The certificate is not what scopes the key. The `keychain-access-groups` entitlement is granted by
the provisioning profile, and AMFI verifies the profile, the Apple-anchored chain and the signing
certificate together (§3.3, §4). Obtaining a Developer ID certificate is what makes that profile
possible; the certificate on its own carries no right to the key.

### 3.2 Restricted versus unrestricted entitlements

The entitlement mechanism is independent of CA identity in the general case: a code-requirement
evaluator will accept a privately operated CA as an anchor. What a private CA cannot do is satisfy
validation performed inside Apple's own code, because AMFI and Gatekeeper anchor to Apple and
disregard the user's trust settings. Measured:

```
non-restricted entitlement (com.apple.security.cs.disable-library-validation),
  signed by a private CA                  -> runs
restricted entitlement (keychain-access-groups),
  signed by a private CA                  -> SIGKILL at launch
```

AMFI's stated reason is `Unable to retrieve certificate chain`. Adding the CA to the user
trust store does not alter this, because AMFI's anchor set is not the user's trust settings.

The dividing line is therefore not "signed versus unsigned" but **restricted versus
unrestricted entitlements**. `keychain-access-groups` is restricted, which is why the account is a
precondition (§1.1 step 4). A design that claims no restricted entitlement can be built without
one; that is the alternative in `ALT-ACL-PATH.md`.

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

---

## 4. PKI structure

This design involves **no privately operated CA**. The signing leaf is a Developer ID certificate
issued by Apple, and the team identity that scopes the key is the Team ID prefix on the access
group, granted by the provisioning profile rather than by any certificate field:

```
signing leaf (Developer ID Application)
  |
  +-- Developer ID Certification Authority
        |
        +-- Apple Root CA
```

Three properties follow.

- **The chain is Apple's, so the restricted entitlement is accepted.** AMFI validates the
  Apple-anchored chain, the signing certificate and the profile together (§3.3).
- **The scope is team-level and stable.** The access group is anchored to the team, so reissuing
  the leaf, or rebuilding the binary, changes nothing about which binaries reach the key (§5.1).
- **There is no CA key to protect, and no trust setting to establish.** Nothing on this path is
  signed by a key this organisation holds, and the platform already trusts Apple's chain, so no
  user or system trust modification is involved.

`OU` on the leaf carries the team identity and is what Apple's own designated requirements read.
This design does not depend on that field. The alternative that pins on `OU`, and the enterprise
root and intermediate hierarchy supporting it, are in `ALT-ACL-PATH.md` §3.

---

## 5. Key scoping

### 5.1 Team access group

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
rotation requires no action, at the cost of per-binary granularity. The group is invalidated only
by leaving the team. (The alternative's pin forms, which are invalidated by certificate renewal or
by rebuilding, are tabulated in `ALT-ACL-PATH.md` §3.)

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

An SE key belongs in the **data-protection keychain**. `kSecAttrAccess`, the attribute that
carries a CSSM ACL, is a legacy file-keychain attribute; the modern path scopes items by
entitlement access group instead (F19). That is the property this design depends on:

- **No ACL, therefore no prompt.** There is no ACL entry and so no `KeychainPromptAclSubject`
  behind the key, which is why §1.2's third exposure does not apply here.
- **Scoped to the team**, matching §5.1.
- **The material never leaves the SEP**, so there is nothing for a container-level read to
  recover.
- **The account is a precondition**, because the entitlement is restricted (§3.2).

The keychain is not optional: an item requested as persistent against the legacy file keychain
degrades silently to a software key (§6.1), so both hardware assertions belong in the signer's
startup path.

### 6.3 Controls required on the recommended path

**Hardened runtime with library validation.** Measured:

```
BINARY                             INJECTED CODE                     PROCESS RESULT
signed, no runtime                 signed 256 bytes -> obtained key  GRANTED
signed --options runtime           not loaded (injection blocked)    GRANTED
```

The injected library is unsigned and chains to no CA. Injected into a binary signed without the
hardened runtime, it signs successfully with the group's key. The same binary signed with
`--options runtime` retains its own access while refusing the foreign library, because the
hardened runtime makes dyld ignore `DYLD_INSERT_LIBRARIES` and enables library validation.
Neither `com.apple.security.cs.allow-dyld-environment-variables` nor
`...disable-library-validation` should be added.

Because there is no per-binary pin behind it, this is not defence in depth on this path: it is the
primary control. A binary that declares the access group and is signed without the hardened runtime
lets anything it loads use the key. Enforce the flags in the build pipeline (§1.1 step 3).

### 6.4 What constrains an administrator

An administrator cannot take this key: it is generated in the Secure Enclave and never leaves it,
including under root. An administrator also cannot author a new binary that reaches it, because a
binary claiming the access group must carry a profile from the team (§3.2, F9). What remains in
scope is the machine itself, and this is why §1.1 step 5 is not optional — supervision,
restrictions and a recovery lock are the controls that bound an administrator, not the key's
access control.

The boundary is the enrolment, not the administrator bit. On a supervised, managed Mac an
administrator cannot remove the management plane:

| control | effect on an administrator | source |
|---|---|---|
| Supervision | "A supervised device can't be unenrolled by the user. On Mac computers, this prevents unenrollment from System Settings as well as from the `profiles` command-line tool." | Apple Platform Deployment, *Automated Device Enrollment* |
| Non-removable enrolment profile | Automated Device Enrollment offers "the option to prevent the user from removing the device management service's enrollment profile" | same |
| Recovery lock | settable **only** by MDM; without it "they can't access the recovery environment, including the Startup Options screen" | same, *Startup security* |
| Boot-policy changes | on Apple silicon, policy changes require restarting into recoveryOS by holding the power button, "so that malware can't trigger the signal, only a human with physical access can" — which the recovery lock gates | same |
| MDM restrictions | can prevent an administrator "from creating new users in Users & Groups", prevent changing account settings, prevent manually installing configuration profiles, and require an administrator password to install or update apps | same, *Restrictions for Mac* |
| Bootstrap token | escrowed to MDM at first secure-token login; enables supervision, silent Erase All Content and Settings, and authorizing software updates | same, *Use secure and bootstrap tokens* |

The first row determines the outcome: removing an endpoint agent or changing a local
configuration achieves nothing durable, because the device remains managed. "The user has `sudo`"
and "the user can leave the management plane" are different statements.

These claims come from vendor documentation rather than measurement, because the machine used for
this work is not MDM-enrolled (`profiles status -type enrollment` reports "MDM enrollment: No") and
cannot exhibit the behaviour described. `EVIDENCE.md` §6.4 sets out the quotations and the same
separation. The alternative path is defeated by a local administrator wherever this plane is
absent, which is one of the reasons it is not the recommendation (F4, F14; `ALT-ACL-PATH.md` §5.3).

---

## 7. Limitations

Items not established about the recommended design. All three could not be measured for want of an
Apple Developer account; the items that are specific to the alternative are in `ALT-ACL-PATH.md`
§6.

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

## Appendix A. Sources

**Measured locally.** Everything in `EVIDENCE.md` marked `(measured)`, on macOS 26.6.2 (build
25G83), arm64: keychain ACL behaviour, code-requirement evaluation, entitlement rejection by
AMFI, code injection, ACL prompt behaviour, key extraction, and the permission bits and
authorization rules governing the System keychain.

**Decoded from artifacts.** The provisioning-profile structure in §3.3 and §5.1 was extracted
from installed applications with `run-profile.sh` and `security cms -D`. The payload and
trust-setting behaviour in F6 and F20 was decoded from the system binaries that implement it —
`/usr/libexec/trustd` for the entitlement that gates a trust-settings write, and
`ConfigurationProfiles.framework/XPCServices/CertificateService.xpc` for the payload keys, the
trust values applied, and the ACL-construction gap described in `ALT-ACL-PATH.md` §5.1.

**Documented by the vendor.** The claims in §6.4 come from vendor documentation rather than
measurement, because the machine used for this work is not MDM-enrolled
(`profiles status -type enrollment` reports "MDM enrollment: No") and cannot exhibit the
behaviour described.

| topic | source |
|---|---|
| Supervision prevents unenrolment; Automated Device Enrollment options; supervised restrictions | Apple, *Apple Platform Deployment* — "Automated Device Enrollment and device management", "Restrictions for Mac", "Restrictions for supervised devices" |
| Recovery lock, startup security, Apple silicon boot-policy gating | Apple, *Apple Platform Deployment* — "Startup security" |
| Secure token, bootstrap token, volume ownership | Apple, *Apple Platform Deployment* — "Use secure token, bootstrap token, and volume ownership in deployments" |
| Endpoint privilege management model; macOS authorization request matching; agent protection | BeyondTrust, *Endpoint Privilege Management for Windows and Mac* — "Application definitions and types (macOS)", "Policy editor utilities", "Uninstall EPM clients and adapters" (cited in `ALT-ACL-PATH.md` §5.3) |
| Access-control flag semantics | `Security/SecAccessControl.h`; `Security/SecItem.h` for the legacy-versus-data-protection attribute distinction |
| Certificate and trust payload keys; unattended trust establishment | Apple, *Device Management* — `com.apple.security.root` and `com.apple.security.pkcs12` payload documentation; corroborated by decoding `trustd` and `CertificateService` |

`tools/fetch_apple_doc.py` and `tools/fetch_readme_doc.py` retrieve and extract the text of those
documentation pages, so the quotations in §6.4 can be re-derived rather than taken on trust.

---

## Appendix B. Document map

| document | contents |
|---|---|
| `README.md` | the recommended design and the reasoning behind it |
| `ALT-ACL-PATH.md` | the alternative design, what constrains it, and its unresolved items |
| `EVIDENCE.md` | the measurements: result matrices, log excerpts, negative results, platform notes, and the end-to-end run order |
| `pki/` | certificate authority and leaf certificate material, with the OpenSSL configurations used to generate it |
| `tools/` | source for the test utilities |
| `bin/` | built utilities and the signed test clients |
| `work/` | keychains, PKCS#12 archives, and pinned-requirement records |
| `run-*.sh` | the reproduction scripts, tabulated in §2 |
| `tools/fetch_apple_doc.py`, `tools/fetch_readme_doc.py` | retrieve and extract the vendor documentation cited in Appendix A |
