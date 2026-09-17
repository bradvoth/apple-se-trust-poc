# Alternative path: a keychain ACL pinned to a code requirement

**This document is not the recommendation.** `README.md` specifies the design that is
recommended — a Secure Enclave key scoped by a team access group — and stands without this
document. This one records the alternative that was investigated for the case where an Apple
Developer account is unavailable. It is kept because it is reachable in that case, and because the
measurements taken against it are the negative results that support the recommendation, but it is
not developed alongside the recommendation and nothing in `README.md` depends on it.

Read `README.md` first. Findings are tabulated once, in `README.md` §2, and are cited here by ID;
the measurements behind them are in `EVIDENCE.md`. Both classes of evidence are used, as in
`README.md`: **measured** results are reproduced by a script in this repository, and
**documented or decoded** results come from vendor documentation or from artifacts such as
provisioning profiles.

All measurements were taken on macOS 26.6.2 (build 25G83), arm64, OpenSSL 3.6.4, command line
tools only.

### Terminology (in addition to `README.md`)

| term | meaning |
|---|---|
| **legacy file keychain** | the login/System keychain; scoped by a CSSM ACL carrying a code requirement |
| **pin** | a code requirement in a legacy keychain ACL naming the code permitted to use a key |

---

## 1. The design, where no Apple Developer account is available

Where an Apple Developer account is unavailable, a key in the **legacy file keychain** can be
pinned to a code requirement instead:

1. **Pin the key's ACL to a requirement naming the permitted signers** — a binary directly, or a
   team identity on the leaf certificate. One entry names a set of binaries and refuses others
   (§4.1, measured). This works with a privately operated CA and no account.
2. **Create the key with its final ACL, in the System keychain, during installation or via MDM**,
   because the write is gated by an authorization that root alone does not satisfy and no MDM
   payload key can set a keychain ACL (F5, F6).
3. **Accept two residual exposures that the Secure Enclave design does not have:** the key
   material is recoverable from the keychain container by anyone who can open it, including root
   via `/var/db/SystemKey`; and the ACL entry always carries a prompt alternative that grants
   access to a caller presenting the keychain password, which cannot be suppressed (§4.2,
   measured).

Two controls from `README.md` are required on this path as well, and one of them carries more
weight here:

- **Hardened runtime with library validation** (`README.md` §6.3). A code-identity pin is
  ineffective against injected code without it (F7, EVIDENCE §7). The recommended design has no
  per-binary pin, so the control is primary there; here it is defence in depth behind the pin.
- **The management plane** (`README.md` §1.1 step 5, §6.4). A local administrator can satisfy
  `system.keychain.modify` and rewrite the ACL, and can recover the key material from the
  container, so on this path the management plane is the only control that bounds an
  administrator at all (F4, F13, F14; §5.3).

The account is still not required for the pin itself: signing with a Developer ID certificate does
not require a provisioning profile, and a Developer ID `launchd` background service inspected on
this machine carries no entitlements at all, because it claims no restricted entitlement. A
profile is required only when a restricted entitlement is claimed. For this path the account is
needed for notarization and for Gatekeeper on machines outside administrative control, not for the
pin.

## 2. Trust settings for the private CA

Trust settings are the one part of this path that **cannot be established unattended from the
command line, but can be established unattended through MDM.**

Locally, establishing a trust setting for a CA raises an authorization dialog (Touch ID or the
login password) **every time it changes**, including the first time — measured.
`trust-settings-import` prompts on any real modification too, and no command-line option avoids
it. On an unmanaged machine, trust must therefore be established once, interactively, and the CA
must not be regenerated afterwards, because that invalidates the trust and prompts again. The
scripts in this repository refuse to modify trust settings unless `POC_ALLOW_TRUST_CHANGE=1` is
set, so an unattended run fails with an explanation instead of hanging on a dialog.

The dialog is not intrinsic to the operation. It is the fallback that `trustd` takes when the
caller lacks the `com.apple.trust-settings.user` (or `.admin`) entitlement: absent the entitlement
it fails `AuthorizationCopyRights`, which is what raises the dialog. A payload installer holds the
entitlement and therefore sets trust silently. The Certificate payload (`com.apple.security.root`,
and the trust block of `com.apple.security.pkcs12`) carries exactly the `kSecTrustSettingsPolicy`,
`kSecTrustSettingsResult` and `kSecTrustSettingsAllowedError` values that the local call sets, so
the same trust state is reachable from a profile with no user present (F20). **Deploying the CA by
profile is the supported method for this step.**

Two constraints apply. The profile path requires MDM or supervised local profile installation, and
it installs trust rather than a keychain ACL: it does not remove the need for §1 step 1 or the
§1 step 2 constraint. The recommended design involves no user trust settings at all, so this
section applies only here.

## 3. PKI structure

```
Enterprise Root CA                 self-signed, pathlen:1, held offline
  |
  +-- Team A Intermediate CA       pathlen:0, held by team A
  |     +-- signing leaf            OU=TEAMA
  |
  +-- Team B Intermediate CA       pathlen:0, held by team B
        +-- signing leaf            OU=TEAMB
```

The enterprise root signs team intermediates only and remains offline; each team CA signs only its
own leaves. `pathlen:1` on the root and `pathlen:0` on each team CA prevent a team CA from creating
further CAs, which bounds the damage from a compromised team CA. This is the **only** X.509-layer
constraint available here, for the reason given in F11.

The team identity appears on the leaf certificate, in the `OU`, and that is what the pin names:

```
identifier "com.example.signer" and certificate leaf[subject.OU] = "TEAMA"
```

It is also what Apple's own designated requirements read. A code requirement needs an anchor, so
this path needs either a Developer ID certificate pinned through `OU`, or a privately operated CA
— the latter only where per-application granularity or a leaf-hash pin is wanted, since a root
under local control is stable indefinitely (EVIDENCE §9.4). Where a Developer ID certificate is
used, the same leaf serves both the `OU` pin and the account mechanics in `README.md` §3.

The hierarchy above is this path's structure. The recommended design does not replace a team CA
with an Apple-issued one; it removes the CA from that design altogether (`README.md` §4).

The pin forms, compared by what invalidates them:

| scope | invalidated by |
|---|---|
| `certificate leaf = H"…"` | certificate renewal, or any rebuild with a new certificate |
| `certificate leaf[subject.OU]` | leaving the team |

Team-level pins survive certificate and binary rotation, which is why either form is preferable to
a leaf hash. The only pin form that does not survive renewal is `certificate leaf = H"…"`
(EVIDENCE §9.4), which is the form to avoid.

## 4. Key scoping

### 4.1 Code requirement

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

The ACL gates key **operations**: the authorizations attached to an entry are `ACLAuthorizationSign`,
`Decrypt`, `Derive`, `ExportClear` and similar. There is no tag for content, context, frequency or
requester identity, so any code the requirement admits may sign arbitrary bytes with the key, as
often as it likes, unrecorded. That is a property of what the ACL expresses, not a defect of it.

### 4.2 The two exposures this path carries

Both are measured, and neither is present on the Secure Enclave design.

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
`/var/db/SystemKey`, or anyone who can open the keychain with its password, obtains the key. A
Secure Enclave key is generated in and never leaves the SEP, so that route does not exist.

**The ACL entry always retains a prompt alternative, and it cannot be removed.** The stored entry
is a threshold subject with two alternatives, from the `securityd` log:

```
ThresholdAclSubject(1 of 2)[
    CodeSignatureAclSubject[requirement: identifier "…" and certificate 1 = H"…"]
][
    KeychainPromptAclSubject(flags: 0x0, desc:pin-teamA)
]
```

"1 of 2" means the requirement matching **or** the user approving satisfies the entry. The prompt
demands the **keychain password**, not a bare click, measured (`run-prompt-approval.sh`):

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
prompt-free ACL at the CSSM level does not survive being attached to a key — the keychain service
re-derives a `cdhash` entry for the creating process on write, and that entry also grants
`ExportClear` (F17, EVIDENCE §4.2).

The consequence is that the pin is a boundary against *silent* access, not against a caller that
can present a dialog to someone holding the keychain password. The recommended design has no ACL,
so it has no prompt to defeat (F19).

## 5. Deployment

### 5.1 The System keychain, and what can set an ACL

The System keychain is the correct location for a machine-wide key, and its protection is real
(measured): `system-keychain-2.db` is `0600 root:wheel`, `/var/db/SystemKey` is `0400 root`, and
the store is not writable by a non-admin. Alteration of an item's access is separately gated:

```
system.keychain.modify:  allow-root        = false
                         authenticate-user = true
                         group             = admin
```

uid 0 is not sufficient, so a privilege-management tool cannot *silently* rewrite the ACL. It does
not follow that an administrator is unable to alter it — see §5.3. This is also why the key should
be created with its final ACL during installation or via MDM, where the authorisation is already
satisfied, rather than corrected afterwards from a root agent.

No MDM payload key can set a *keychain item* ACL or partition list (F6), so for the ACL-pinned key
MDM installs the identity and the ACL is whatever the installing code chose. The profile machinery
does build keychain ACLs — `CertificateService` calls `SecAccessCreate` and
`SecACLCreateWithSimpleContents` for imported identities — but only to attach the certificate's
trusted-application list, and only from an `addlTrustedApps` array of bundle identifiers or
app-group identifiers. There is no requirement-based option anywhere in that path: the SPI this
repository depends on (`SecTrustedApplicationCreateFromRequirement`) is never called by it. A
profile can therefore pin a *certificate* to named applications, but it cannot express the signer
requirement, and it cannot set an item's ACL. That gap is the reason privilege-management tooling
is reached for at all, and it has a direct consequence:

> **The privilege-management policy becomes part of the trusted computing base.** The tool that
> installs the ACL is the tool that can remove it. If the allowlist permits an end user to run
> anything capable of calling `SecKeychainItemSetAccess` — `security`, a generic installer, or any
> equivalent — the ACL is bypassable and the control is ineffective. The allowlist must be narrow,
> managed by MDM, and audited. An endpoint agent on macOS can match on the authorization request
> that `SecKeychainItemSetAccess` depends on and deny it (§5.3).

### 5.2 Installing an ACL from code

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

### 5.3 What constrains an administrator on this path

The keychain ACL, considered alone, is defeated by an administrator who can satisfy
`system.keychain.modify` (measured, §5.1). On a file keychain, root or an equivalent reader of
`/var/db/SystemKey` can additionally recover the key material directly. Those are properties of
*this control on an unmanaged machine*.

An administrator on a supervised, managed Mac cannot remove the management plane, and the
management plane can gate the very authorization an ACL change requires. The boundary is the
enrolment, not the administrator bit. `README.md` §6.4 tabulates the controls that establish that
boundary; they are device-level and apply here unchanged.

**Endpoint agents close the gap identified in §5.1.** The ACL is gated by an authorization right
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

## 6. Limitations specific to this path

Items not established here. The first two could not be measured for want of administrator rights;
the last is a documentation gap. The items that are not established about the recommended design
are in `README.md` §7.

1. **Whether the System-keychain use prompt demands administrator credentials.** For a file
   keychain the prompt asks for that keychain's password and supplying it grants access
   (measured, §4.2); the prompt does not accept a bare confirmation. It follows that the System
   keychain equivalent should demand administrator credentials. Untested, because it requires
   administrator rights. Procedure: §6.1.

2. **Whether `anchor trusted` functions inside a keychain ACL (F12).** It matched under
   `SecStaticCodeCheckValidity` but denied every caller when stored in an ACL. The probable cause
   is trust domain: the CAs are trusted in the user domain and `securityd` runs as root, so it may
   consult only the admin and system trust settings. Establishing this requires `sudo`. Until it
   is resolved, explicit `certificate leaf` pins should be preferred, since they require no trust
   evaluation to decide.

3. **Whether the agent-protection feature of an endpoint privilege management product covers
   macOS** (§5.3). Affects how the agent resists removal, not whether removal is useful, because
   supervision prevents unenrolment independently.

### 6.1 Procedures for the unmeasured items

To determine whether the System-keychain use-prompt is admin-gated, on a machine where
administrator rights are held:

```bash
sudo security add-generic-password -a acldemo -s acldemo -w secret \
     -k /Library/Keychains/System.keychain
# Pin the item's ACL to a code requirement, then run a non-matching binary while
# logged in as a NON-admin user, with keychain UI enabled (POC_ALLOW_UI=1):
#   denied outright          -> hard enforcement for non-admins (desirable outcome)
#   admin credential prompt  -> acceptable, since non-admins cannot satisfy it
#   ordinary user prompt     -> the limitation in §4.2 applies in the System keychain too
```

To resolve F12:

```bash
sudo security add-trusted-cert -d -r trustRoot -p codeSign \
     -k /Library/Keychains/System.keychain pki/ent/ent-root.crt
./run-tiered.sh && ./run-acl-tiered.sh    # does the anchor-trusted row match?
```

## 7. Findings and reproduction

The findings this path rests on are F1–F6, F10–F12 and F14–F17, together with F20 for the
trust-settings route and F7 and F13 for the two controls it shares with the recommended design;
each is marked `alternative` or `both` in `README.md` §2.

They are reproduced by `run-matrix.sh`, `run-aclstruct.sh`, `run-prompt-approval.sh`,
`run-extraction.sh`, `run-reqmatrix.sh`, `run-tiered.sh`, `run-acl-tiered.sh`,
`run-nameconstraints.sh` and `run-profile.sh`, with `run-injection.sh` for F7. The measurements
themselves are in `EVIDENCE.md` §1–§6 and §10.
