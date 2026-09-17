# Evidence

Measurements supporting `README.md`. That document states what should be built and why;
this one records the results, including negative results and platform behaviour that
constrains the design.

All measurements were taken on macOS 26.6.2 (build 25G83), arm64, OpenSSL 3.6.4, with
command line tools only. None required `sudo`; the two items that do are listed in
`README.md` §7 and are not treated as established anywhere below.

Results marked `(measured)`, and result blocks introduced by `Measured`, are reproduced by
the named script. Every script listed under §12 is expected to pass from a clean machine.

Sections are ordered so that later ones extend or qualify earlier ones. Findings referenced as
F1–F19 are tabulated in `README.md` §2, each marked with its basis.

Two classes of evidence appear below and they are not equivalent. **Measured** results are
reproduced by the scripts listed under §12. **Documented or decoded** results come from vendor
documentation or from artifacts such as provisioning profiles, because the behaviour could not
be exercised without an Apple Developer account or, in some cases, without `sudo`; each such
subsection says so explicitly.

---

## 1. Method

The scenario is a client binary that needs to sign data with a private key held in a
keychain. Access is decided by the key's ACL, which is pinned to a code requirement. One
binary is built five ways, and one set of keys is pinned to several different
requirements; the result matrix is the cross product of the two.

```
pocclient-unsigned    no signature
pocclient-adhoc       ad-hoc signature, no certificate
pocclient-signedA     signed by "POC Software Signing A", issued by POC Private Root CA 1
pocclient-signedB     signed by "POC Software Signing B", issued by POC Private Root CA 1
pocclient-signedC     signed by "Rogue Software Signing C", issued by POC Rogue Root CA 2
```

Both CAs are trusted for code signing, so `signedC` represents "trusted, but not by the
pinned signer".

| key | pinned requirement |
|---|---|
| `pin-root-ca1` | `identifier "com.poc.client" and certificate root = H"<CA1>"` |
| `pin-leaf-a` | `identifier "com.poc.client" and certificate leaf = H"<Signing A>"` |
| `pin-leaf-b` | `identifier "com.poc.client" and certificate leaf = H"<Signing B>"` |
| `anchor-trusted` | `identifier "com.poc.client" and anchor trusted` |
| `identifier-only` | `identifier "com.poc.client"` |
| `deny-all` | `identifier "com.poc.client" and certificate leaf = H"0000…"` (can never match) |

---

## 2. Access matrix (F1, F2)

Keychain UI disabled, so every result is a plain allow or deny with no prompt.
Reproduced by `./run-matrix.sh`.

| caller | pin-root-ca1 | pin-leaf-a | pin-leaf-b | anchor-trusted | identifier-only | deny-all |
|---|---|---|---|---|---|---|
| unsigned | deny `-25293` | deny | deny | deny | deny | deny |
| adhoc | deny | deny | deny | deny | **GRANTED** | deny |
| signedA | **GRANTED** | **GRANTED** | deny | deny | **GRANTED** | deny |
| signedB | **GRANTED** | deny | **GRANTED** | deny | **GRANTED** | deny |
| signedC | deny | deny | deny | deny | **GRANTED** | deny |

`-25293` is `CSSMERR_CSP_OPERATION_AUTH_DENIED`. Refusal occurs at
`SecKeyCreateSignature`. The key reference remains retrievable, because lookup and use
are distinct ACL rights, but the key is unusable.

Observations:

- Pinning is precise. A and B share a CA, so a root pin admits both while a leaf pin
  admits exactly one. The requirement is evaluated per call against the caller's actual
  signature.
- A trusted but unpinned signer is refused. `signedC` chains to a CA trusted for code
  signing and obtains nothing against any pin.
- Unsigned and ad-hoc code is refused, even though `adhoc` satisfies `identifier`. The
  `identifier-only` column is the control demonstrating that `identifier` is
  self-asserted and confers no protection on its own (F1).

The requirement evaluator, independent of the keychain, agrees. Reproduced by
`./run-reqmatrix.sh`:

```
requirement                  unsigned adhoc signedA signedB signedC
pin-root-ca1                 .        .     MATCH   MATCH   .
pin-leaf-a (Signing A)       .        .     MATCH   .       .
anchor trusted               .        .     MATCH   MATCH   MATCH
anchor apple                 .        .     .       .       .
identifier only              .        MATCH MATCH   MATCH   MATCH
pin CA1 by subject CN        .        .     MATCH   MATCH   .
```

### 2.1 Note on `anchor trusted` (F12)

`anchor trusted` matches every signed caller under `SecStaticCodeCheckValidity`. The same
requirement stored in a keychain ACL denies every caller. The two evaluators have been
observed to disagree, which is the reason the tiered-PKI matrices in §10 were confirmed
against real ACLs rather than the evaluator alone. See `README.md` §7 for the unresolved
cause and the procedure to settle it.

---

## 3. ACL construction (F1)

`SecAccessCreate` and `SecKeychainItemSetAccess` accept a list of
`SecTrustedApplicationRef`. The route from a code requirement to one of those is exported
but not declared in the SDK:

```objc
// Declared in Apple's open source SecTrustedApplicationPriv.h; exported from
// Security.framework; absent from the public SDK headers.
extern OSStatus SecTrustedApplicationCreateFromRequirement(
        const char *description, SecRequirementRef requirement,
        SecTrustedApplicationRef *app);

SecRequirementRef req = NULL;
SecRequirementCreateWithString(
    CFSTR("identifier \"com.poc.client\" and certificate root = H\"…\""),
    kSecCSDefaultFlags, &req);

SecTrustedApplicationRef app = NULL;
SecTrustedApplicationCreateFromRequirement("pinned", req, &app);

SecAccessRef access = NULL;
SecAccessCreate(CFSTR("pinned"), (__bridge CFArrayRef)@[ (__bridge id)app ], &access);

NSDictionary *params = @{
    (__bridge id)kSecAttrKeyType:       (__bridge id)kSecAttrKeyTypeRSA,
    (__bridge id)kSecAttrKeySizeInBits: @2048,
    (__bridge id)kSecAttrIsPermanent:   @YES,
    (__bridge id)kSecAttrLabel:         @"pinned-key",
    (__bridge id)kSecAttrAccess:        (__bridge id)access,
    (__bridge id)kSecPrivateKeyAttrs:   @{ (__bridge id)kSecAttrAccess: (__bridge id)access },
};
SecKeyCreateRandomKey((__bridge CFDictionaryRef)params, NULL);
```

The requirement persists into the stored item and is retrievable with
`SecTrustedApplicationCopyRequirement`, so it is a stable, inspectable property rather
than an ephemeral one. `tools/pocsetup.m` implements this as `mkkeyreq`, `tappreq` and
`dumpacl`.

Three platform behaviours constrain this construction:

**`SecTrustedApplicationCreateFromPath` produces a path-based entry only.** For an
Apple-signed binary such as `/bin/ls`, the external representation is the literal path
string and the recorded requirement is `(none)`. An ACL built with
`security add-generic-password -T` or `SecAccessCreate(desc, @[ pathApp ])` therefore
performs *path* pinning, which any process running from that path satisfies.
`SecTrustedApplicationCreateFromRequirement` is required for signer pinning.

**A private-CA chain must be trusted or `codesign` refuses to sign.** Before the CA was
trusted, signing failed with `errSecInternalComponent` and `SecTrustEvaluateIfNecessary`
logged `leaf MissingIntermediate`. Two conditions were required: the root certificate
present in a keychain that trustd searches (the login keychain works; a side keychain does
not), and the CA trusted for the code-signing policy. Both were satisfied in the user
domain without `sudo`:

```
security add-certificates   -k ~/Library/Keychains/login.keychain-db pki/ca1/ca.crt
security add-trusted-cert -r trustRoot -p codeSign -k ~/Library/Keychains/login.keychain-db pki/ca1/ca.crt
```

`security find-identity` reports the identity as valid once this is in place.

**Any change to the trust store raises an authorization dialog.** Measured directly: with a
fresh throwaway CA, a *first-time* `security add-trusted-cert` blocks on

```
security: You are making changes to your Certificate Trust Settings.
          Touch ID or enter your password to allow this.
```

and does not return until the dialog is answered. An earlier revision of this file claimed a
first-time addition does not prompt; that was wrong, and it caused a scripted run to hang
waiting for Touch ID.

`security trust-settings-import` is silent only when the imported list is **identical** to the
current one; a real modification through it prompts in the same way. There is therefore no
unattended way to change trust settings, and `lib-trust.sh` now refuses to attempt one unless
`POC_ALLOW_TRUST_CHANGE=1` is set, so a script fails fast and explains rather than blocking on a
GUI dialog.

---

## 4. The ACL always retains a prompt fallback (F3)

`SecACLCreateWithSimpleContents` does not store the requirement as the entry's only
subject. It stores a threshold subject with two alternatives. As reported by `securityd`
(`./run-aclstruct.sh`):

```
AclEntry[tag:]AUTH[24]AUTH[115] SUBJECT[
    ThresholdAclSubject(1 of 2)[
        CodeSignatureAclSubject[legacyHash:0000…][path:poc-requirement]
            [requirement:identifier "com.poc.client" and certificate root = H"84aa9f2f…"]
    ][
        KeychainPromptAclSubject(flags: 0x0, desc:pin-root-ca1)
    ]
]
```

"1 of 2" means that matching the requirement **or** obtaining user approval satisfies the
entry. With UI enabled, `pocclient-unsigned`, `pocclient-adhoc`, `pocclient-signedB`
against `pin-leaf-a`, and `pocclient-signedC` against `pin-root-ca1` all block awaiting a
SecurityAgent dialog. With UI disabled, which is what
`SecKeychainSetUserInteractionAllowed(false)` effects and what the §2 matrix uses, the
same calls return `-25293` immediately.

The consequence depends on the threat model:

- where no user is present to prompt, the pin holds;
- against code able to place a dialog before the user, the pin is a delay rather than a
  boundary, because the user is the root of trust and can always be asked. The prompt
  does not distinguish the pinned signer from an unsigned binary.

No supported mechanism suppresses the prompt. `SecKeychainPromptSelector` provides bits
for requiring a passphrase and for prompting on unsigned or invalid signatures, but no
"never prompt" bit, and a value of `0` still produces the `KeychainPromptAclSubject`
shown above.

### 4.1 What approving the prompt does (measured)

Whether approval actually hands over the key had not been established, and the claim
"the pin restricts silent access only" depends on it. `./run-prompt-approval.sh` settles it.

The test pins a key to **signedA's leaf certificate only** and then runs `signedB`, which
fails the requirement. The script asserts both halves of that premise with
`pocsetup checkreq` before running, because an earlier version of it pinned the CA1 root —
which `signedB` also chains to — and the test then passed vacuously, the caller succeeding on
the requirement rather than on the prompt.

The dialog, verbatim:

```
pocclient-signedB wants to sign using key "prompt-approval-test" in your keychain.
To allow this
enter the "poc-test" keychain password.
Password:
                                            buttons:  Always Allow | Deny | Allow
```

Approving requires **the keychain password**, not a bare click; clicking `Allow` with the
field empty leaves the caller blocked. Supplying the password and choosing `Allow` grants the
key, and the non-matching caller then completes `SecKeyCreateSignature`:

```
created key 'prompt-approval-test' pinned to signedA's leaf certificate
  dialog appeared after ~100ms
  filled password and clicked (one-time): Allow
  client exited; output:
      SecKeyCreateSignature   -> OK, 256 byte signature
    RESULT: GRANTED
  OUTCOME: *** APPROVAL GRANTED ACCESS ***
```

`Always Allow` is the same button set's third option and additionally persists the caller
into the ACL, which is a stored modification rather than a one-time grant; the test
deliberately prefers one-time `Allow` so that it observes the approval path without altering
stored state.

Two conclusions follow. The ACL is **not** a hard boundary against a caller able to present a
dialog to someone who holds the keychain password, and on a workstation that password is
normally the logged-in user's own. It **is** a boundary against a caller that cannot obtain
that credential, or that has no user present to prompt. The credential
requirement also means the equivalent prompt in the System keychain should demand
administrator credentials, which is unmeasured (`README.md` §7 item 1).

The prompt path belongs to the ACL entry, so it applies to whoever that entry names: the
approval route is a property of the entry, not of a particular caller, and cannot be avoided by
changing which binary the entry names (`README.md` §6.5).

### 4.2 A mitigation that does not work

Recorded so that it is not attempted again. The ACL subject can be constructed at the CSSM
level so that the entry contains only a `CodeSignatureAclSubject`, with the layout taken
from `CodeSignatureAclSubject::toList` (signature-type wordid, 20-byte legacy hash,
NUL-terminated path, requirement blob). `SecAccessCreateFromOwnerAndACL` accepts this and
returns a single-entry access object containing no prompt subject.

It does not survive attachment to a real key. `SecKeyCreateRandomKey` fails with `-67702`,
because the CSP will not generate a key into an ACL that does not authorize the generating
process. Routing through `SecKeychainItemSetAccess` returns `errSecSuccess` but leaves the
stored ACL holding a `cdhash` entry for the creating process instead of the supplied
requirement; reading it back with `SecKeychainItemCopyAccess` shows the substitution. The
keychain service re-derives ACL entries for the creating process on write. Reproduce with
`./bin/pocsetup mkkeycssm <keychain> <label> '<requirement>'`.

The ACL is therefore best understood as *user-mediated* rather than *policy-enforced*. Hard
enforcement that survives a user being persuaded to approve requires the key to reside
somewhere the untrusted process cannot query at all.

---

### 4.3 Does a code-identity pin also protect the key material? (F16)

No, and the two questions are independent. `./run-extraction.sh` separates them. The probe is
unsigned, so it matches no requirement in the key's ACL:

```
1. lookup key ref          : 0 No error.
2. use it (sign)           : DENIED (-25293)
3. take it (copy raw key)  : DENIED (-25293)
4. ACL entries on this item: 2
     [0] ACLAuthorizationDecrypt,ACLAuthorizationSign
     [1] ACLAuthorizationChangeACL
```

Extraction is refused because **no ACL entry authorizes it** — there is no `ExportClear` entry
at all — not because the requirement rejected the caller. That distinction matters, because it
means the refusal is a property of how the ACL was constructed rather than of pinning.

It is a property that has to be built in deliberately. `SecAccessCreate`'s default ACL grants:

```
[0] ACLAuthorizationEncrypt
[1] ACLAuthorizationDecrypt,ACLAuthorizationDerive,ACLAuthorizationExportClear,
    ACLAuthorizationExportWrapped,ACLAuthorizationMAC,ACLAuthorizationSign
```

`ExportClear` and `ExportWrapped` are present by default. The keys in this repository escape that
only because `mkkeyreq` strips the defaults and adds a Sign/Decrypt entry explicitly
(`README.md` §6.3). A key built without that step silently grants export, and a code-identity pin
does not change it.

Even with export rights absent, the key material remains in the keychain container, and a
container-level read does not consult the ACL at all: the user's own keychain password, or root
reading `/var/db/SystemKey`, yields the key. This is the exposure a Secure Enclave key removes —
the material is generated in and never leaves the SEP — and it is an argument about where the key
lives, not about export permissions.

## 5. The derived designated requirement is not a usable pin

For the same CA and identifier, macOS derives different designated-requirement shapes:

```
pocclient-signedA  identifier "com.poc.client" and certificate root = H"84aa9f2f…"   (CA1)
pocclient-signedB  identifier "com.poc.client" and certificate root = H"84aa9f2f…"   (CA1)
pocclient-signedC  identifier "com.poc.client" and certificate leaf = H"e046f6eb…"   (leaf C)
```

`84aa9f2f…` is CA1 and `e046f6eb…` is leaf C, confirmed by SHA-1 over the DER encoding. A
and B share a designated requirement keyed on the root, because their certificates carry
no `subjectAltName`, `OU` or team identifier for macOS to discriminate on; C falls back to
the leaf.

The ACL is evaluated against this derived requirement, so an unpinned private-CA
certificate yields a pin that was neither chosen nor predictable. Where a specific signer
is intended, the pin must be stated explicitly.

---

## 6. Enterprise deployment: System keychain and privilege management (F4, F5, F6, F13, F14)

### 6.1 Protection of a System keychain item

Measured on the test machine:

```
/Library/Keychains/System.keychain        root:wheel  0644   (legacy store)
/Library/Keychains/system-keychain-2.db   root:wheel  0600   (modern store)
/var/db/SystemKey                         root:wheel  0400   (unlock secret)
System Integrity Protection ............. enabled
```

A non-admin cannot write the store, and cannot read the modern store at all. Alteration of
an item's access is separately gated by the `system.keychain.modify` authorization right:

```xml
<key>allow-root</key>        <false/>
<key>authenticate-user</key> <true/>
<key>class</key>             <string>user</string>
<key>group</key>             <string>admin</string>
<key>shared</key>            <true/>
```

That is: an admin-group user must authenticate, and root alone is not authorized. The ACL
change is checked against the item's `CHANGE_ACL` entry
(`CSSM_AUTHORIZATION_CHANGE_ACL`), not against file permissions, so holding the correct uid
is not sufficient.

### 6.2 Consequences for privilege-management tooling

1. **A root agent cannot silently rewrite the ACL.** `allow-root=false` combined with
   `authenticate-user` means that running the command as root is not sufficient; the
   authorization must be satisfied. A "run a script to correct the ACL later" approach
   therefore requires an approval step, or must execute where the authorization already
   exists, or the agent must hold the entitlement.

2. **Creating the item with its final ACL is the clean path.** The installer or
   MDM-initiated flow already holds the admin authorization, and the ACL is written
   atomically with the key.

3. **No MDM configuration profile can set a keychain ACL.** The payload key definitions in
   `ManagedConfiguration.framework` expose nothing for keychain ACLs or partition lists.
   MDM installs the identity; the ACL is whatever the installing code decided. This is a
   gap in the management tooling and the reason privilege-management products are reached
   for.

4. **The privilege-management policy becomes part of the trusted computing base.** If the
   allowlist permits an end user to run any command able to rewrite the ACL — `security`,
   `sudo` generally, an installer, or anything able to call `SecKeychainItemSetAccess` —
   the ACL is bypassable and the control is ineffective. The allowlist must be narrow,
   managed by MDM, and audited, and must not include `security`.

### 6.3 Tamper-resistance tiers

This table describes the keychain item **on an unmanaged machine**. It was the basis of an
earlier claim that a local administrator cannot be constrained at all, which was wrong; see
§6.4, and `README.md` §6.2 for the corrected model.

| actor | outcome for the keychain item itself |
|---|---|
| non-admin user | **blocked.** Cannot write the store (`0600`), cannot satisfy `system.keychain.modify` (requires the admin group), cannot read the modern store. |
| local admin | **not blocked.** Can authenticate against `system.keychain.modify`, rewrite the ACL, then use or export the key. |
| root, or anything able to read `/var/db/SystemKey` | **not blocked.** Can recover the key material directly rather than passing through the ACL. |

Pinning is therefore a real boundary against ordinary users and no boundary against an
administrator who is able to satisfy `system.keychain.modify` freely. What that table does
**not** show is the mechanism that constrains the administrator: it is not the ACL, it is the
management plane, and §6.4 sets it out.

### 6.4 What constrains an administrator (documented, not measured)

The development machine used for this work is not MDM-enrolled:

```
$ profiles status -type enrollment
Enrolled via DEP: No
MDM enrollment: No
```

It therefore cannot exhibit the behaviour described here, and the claims in this subsection
rest on vendor documentation rather than on measurement. They are separated from the measured
findings deliberately. Scripts `tools/fetch_apple_doc.py` and `tools/fetch_readme_doc.py`
reproduce the extractions.

**Supervision prevents unenrolment.** Apple's deployment guide, on Automated Device
Enrollment:

> "A supervised device can't be unenrolled by the user. On Mac computers, this prevents
> unenrollment from System Settings as well as from the profiles command-line tool."

and, on the enrolment profile itself, that organisations have "the option to prevent the user
from removing the device management service's enrollment profile".

This is the decisive fact. An administrator who removes an endpoint agent or rewrites an ACL
does not thereby leave the management plane; the device remains supervised and its
configuration is reasserted. Removing an agent is therefore not equivalent to unenrolling,
and a `sudo`-capable user is not necessarily a user who can escape management.

**The recovery lock gates recoveryOS, and is set only by MDM.** Apple's *Startup security*
page, on the recoveryOS password:

> "Unless the user enters the recoveryOS password, they can't access the recovery
> environment, including the Startup Options screen. You can set a recoveryOS password only
> using a device management service, and for the service to update or remove an existing
> password, you also need to provide the current password. … unenrolling a Mac that has a set
> recoveryOS password from that service also removes the password."

The restoration path is via DFU, which the same page notes "cryptographically renders the
previous data on the Mac inaccessible", so it is not a route to the key.

**Boot-policy changes require physical presence.** On Apple silicon, changing a security
policy requires restarting into recoveryOS by holding the power button, explicitly "so that
malware can't trigger the signal, only a human with physical access can" — and recoveryOS is
what the recovery lock gates.

**Restrictions can bind administrators.** The Mac restrictions list includes preventing "a
user with the role of administrator from creating new users in Users & Groups", preventing
changes to account settings, preventing manual installation of configuration profiles, and
requiring an administrator password to install or update apps.

**The bootstrap token keeps the device manageable.** It is escrowed to the MDM service at the
first secure-token login and enables supervision, silent Erase All Content and Settings, and
authorizing software updates.

**An endpoint agent can gate the authorization the ACL change depends on.** This is the point
that connects the agent to the keychain mechanism of §6.1–6.2. The ACL write is gated by
`system.keychain.modify`, an Authorization Services right. BeyondTrust's macOS application
definitions documentation states:

> "This applies to anything in macOS that has a padlock on the dialog box or where the system
> requires authorization to change something. … This matching criteria allows you to target
> any authorization request by matching the Auth Request URI, allowing you to target that
> specific Auth Request URI and apply your own controls."

and the same product documents a general rule that "blocks users from modifying local
privileged group memberships", described as preventing "real administrators … from adding,
removing, or modifying a privileged account".

The corrected conclusion: a privilege-management product **can** enforce protection against a
local administrator, by gating the authorization request that the ACL change requires, and
the ACL is a control the management plane protects rather than a control that stands alone.

**Two dependencies.** First, the agent's own integrity: BeyondTrust documents agent protection
"to prevent admin users from tampering with the product, including stopping the services
running or deleting its files from an endpoint", with a protection table that includes
blocking uninstalls — but describes enablement in Windows registry terms and the unlock-token
utility as "available for Windows OS computers only", while documenting a macOS uninstall
script run with `sudo`. **macOS coverage of agent protection is therefore not established**,
and the distinction between "the agent resists removal" and "removal is pointless" should be
drawn deliberately. Second, the enrolment's integrity: because the ACL's durability derives
from the management plane, control of the MDM tenant is in scope for the threat model of the
key.

Neither was measured. Both are reasoning from documentation, and are labelled as such.


The question of whether the *use* prompt for a System-keychain item is admin-gated is
unresolved and is the highest-value remaining measurement; see `README.md` §7 and
Appendix A.

---

## 7. Code injection into a permitted binary (F7)

Independently of the keychain, the ACL binds to the process's code identity, and a macOS
code signature does not cover dynamically loaded libraries. An actor able to influence the
environment of a permitted binary can execute inside it and inherit its key access.
Measured (`./run-injection.sh`):

```
BINARY                             INJECTED CODE                     PROCESS RESULT
pocclient-signedA (no runtime)     signed 256 bytes -> obtained key  GRANTED
pocclient-hardA (hardened runtime) not loaded (injection blocked)    GRANTED
```

`bin/libinject.dylib` is unsigned and chains to no CA. Injected into the plainly signed
binary it signs successfully with the pinned key. The same binary signed with
`--options runtime` retains its own access while refusing the foreign library, because the
hardened runtime makes dyld ignore `DYLD_INSERT_LIBRARIES` and enables library validation.

Signing the client with the hardened runtime and library validation is therefore required.
It is required for notarization in any case, so it imposes no additional cost in a normal
build pipeline. Do not add `com.apple.security.cs.allow-dyld-environment-variables` or
`com.apple.security.cs.disable-library-validation` to that binary. Without the hardened
runtime the pin certifies which binary is running, not what code is running within that
process.

---

## 8. Secure Enclave (F8, F9, F18, F19)

A Secure Enclave key cannot express a code-identity policy at all, so the keychain ACL
mechanism of §3–§4 is unavailable for it: there is no per-binary pin, and scope comes from a
team access group instead (§8.4). The key can be made non-extractable, including against root,
and requires no user interaction unless a presence gate is requested (§8.3). Reaching that
capability requires a restricted entitlement, which requires an Apple-issued certificate chain.

Reproduced by `./run-se.sh`. No step required administrator rights, and no biometric gate
was exercised, since doing so places a Touch ID prompt on screen.

### 8.1 A persistent SE key requires an entitlement that cannot be self-issued (F9)

| requested | result |
|---|---|
| persistent, data protection keychain | **`-34018` `errSecMissingEntitlement`** |
| persistent, keychain left at default | **`-34018`** |
| persistent, legacy file keychain | reported success; see §8.2 |
| ephemeral, nothing persisted | genuine SE key (`tkid = com.apple.setoken`), non-extractable |

`-34018` is `errSecMissingEntitlement`. The data protection keychain is gated by
`keychain-access-groups`, a restricted entitlement, and AMFI will not accept a restricted
entitlement on a signature it cannot chain to Apple:

```
amfid:  Adhoc signed app with restricted entitlements detected
amfid:  The file is adhoc signed but contains restricted entitlements    (-424)
amfid:  Restricted entitlements not validated, bailing out.
        Error: Unable to retrieve certificate chain                      (-427)
kernel: Code has restricted entitlements, but the validation of its code signature failed.
kernel: code signature validation failed fatally
```

The binary is terminated at launch by SIGKILL in both cases of interest:

```
pocse-cert-noent   exit=1     error -34018      (private CA, no entitlement)
pocse-ent-adhoc    exit=137   killed at launch  (entitlement, ad-hoc signed)
pocse-ent-cert     exit=137   killed at launch  (entitlement, private CA)
```

The entitlement route therefore requires a provisioning profile, hence an Apple-issued
certificate chain, hence a Developer account. Ad-hoc signing is explicitly rejected and a
private CA is explicitly rejected (`Unable to retrieve certificate chain`). No
configuration of trust settings changes this, because AMFI's anchor set is not the user's
trust settings.

### 8.2 Silent downgrade to a software key

Requesting a persistent SE key while directing the operation at the legacy file keychain
produces no error, but the resulting key is a software key:

```
persistent, legacy file keychain   VERDICT: SOFTWARE KEY (SE not used)
  kSecAttrTokenID: (absent)
  SecKeyCopyExternalRepresentation: SUCCEEDED -> key material is extractable
```

A genuine SE key reports `tkid = com.apple.setoken` and refuses export (`extr = 0`;
`SecKeyCopyExternalRepresentation` fails with `-4`).

A review concluding "the code requests `kSecAttrTokenIDSecureEnclave`, so the key is in
hardware" would be wrong in this case. Deployments should assert on two properties at
startup — that `kSecAttrTokenID` is present, and that export is refused — because
otherwise the downgrade is undetectable.

### 8.3 An SE key needs no user interaction unless a gate is requested (F18)

Only these flags impose user interaction:

```
= 1u << 0   UserPresence          = 1u << 1   BiometryAny
= 1u << 3   BiometryCurrentSet    = 1u << 4   DevicePasscode
= 1u << 5   Companion
```

`kSecAccessControlPrivateKeyUsage` is documented as "create access control for private key
operations (i.e. sign operation)" — a marker about how the key is used, not a demand for a human.
Measured, both unattended:

```
gate=none           VERDICT: SECURE ENCLAVE  SIGN OK -> no user interaction required
gate=privateusage   VERDICT: SECURE ENCLAVE  SIGN OK -> no user interaction required
```

The presence gates serve the opposite use case: SE keys backing operations a human authorises.
They are capabilities, not a tax on SE keys.

### 8.4 Scoping: team access group rather than code requirement (F19)

The data-protection keychain is scoped by entitlement, not by a code requirement in a CSSM ACL:

```
legacy file keychain  ->  kSecAttrAccess       (macOS only; a code requirement)
data protection kc    ->  kSecAttrAccessGroup   (a team access group; restricted entitlement)
kSecAttrAccessControl ->  data-protection path  (protection class + optional presence gate)
```

`kSecAttrAccess` is documented macOS-only under *legacy* item attributes, and
`kSecAttrAccessGroup` applies "also macOS if `kSecUseDataProtectionKeychain` is set". A
`SecAccessRef` carrying a code requirement, passed alongside `kSecAttrAccessControl`, is accepted
without error and appears nowhere in the resulting key (`constraints: { dacl = 1; }`, §8.5). The
mechanism is therefore inapplicable rather than merely undocumented.

Scope comes from the access group, decoded from installed applications
(`./run-profile.sh`): the profile grants a **prefix** and the binary declares **concrete groups**
beneath it:

```
profile grants:   "2BUA8C4S2C.*"
binary declares:  2BUA8C4S2C.com.example.webauthn
                  2BUA8C4S2C.com.example.hwkey
```

**Basis.** This is from decoded provisioning profiles and SDK headers, not from measurement: a
persistent data-protection item cannot be created without the entitlement. Creating even a
generic password on that path returns `-34018`:

```
1. add data-protection item      : -34018
   (cannot create one without the entitlement)
```

The two properties the design depends on — that binaries sharing a group reach the same key, and
that a foreign team cannot declare the prefix — are therefore unverified. `README.md` §7.1 gives
the test order.

### 8.5 SE access control has no code-identity field (F8)

The available gates are `UserPresence`, `BiometryAny`, `BiometryCurrentSet`,
`DevicePasscode`, `Companion`/`Watch`, `ApplicationPassword`, `PrivateKeyUsage`, the
`Or`/`And` combinators, and a protection class. There is no code requirement and no signer
pin.

Passing a `SecAccessRef` that carries a code requirement alongside
`kSecAttrAccessControl` is accepted without error and appears nowhere in the resulting
key:

```
constraints: { dacl = 1; }
accc = <SecAccessControlRef: aku;dacl(true)>
```

Whether such an ACL would gate use could not be tested, since that requires a *persistent*
SE key, which requires the entitlement. The data protection keychain does not use CSSM
ACLs at all; it scopes access by entitlement access group. The mechanism is therefore
almost certainly inapplicable rather than merely undocumented, and "an SE key pinned to a
code signer" should be treated as unsupported.

An SE key with no presence gate (`gate=none`) signs with no user interaction, measured.
"No gate" therefore does not mean "no access"; it means that whatever can reach the key
can use it.

### 8.6 Comparison of the two key models

| | file-keychain key with code-requirement ACL | Secure Enclave key |
|---|---|---|
| scope | one binary, or a set named by a requirement | team |
| survives binary rotation | yes | yes |
| survives certificate renewal | only if pinned by team, not by leaf hash | yes |
| requires a human per operation | no | no, unless a presence gate is requested |
| prompt alternative defeatable | **yes** — via the keychain password (§4.1) | none; no ACL (§8.4) |
| export right | absent **only if** the defaults are stripped (§4.3) | not applicable; material never leaves the SEP |
| extractable by root | **yes** (`/var/db/SystemKey`) | **no** |
| requires an Apple Developer account | **no** | **yes** |

Neither set of properties strictly dominates, but they do not fail symmetrically either. The ACL
path carries three exposures the Secure Enclave path does not: the material is container-readable,
the prompt alternative is always present and cannot be suppressed, and export is only absent if
the ACL was constructed to omit it. What the ACL path offers in exchange is per-binary
granularity and independence from an Apple account.

For an unattended signer that accepts team-level granularity, the Secure Enclave path removes all
three exposures, which is why it is the recommendation (`README.md` §1.1). The ACL path remains
the answer when an account is unavailable.

---

## 9. Developer account mechanics

### 9.1 Two independent trust roots

Signing answers "who certified this code?", and two answers can coexist. In both cases the
private key remains under local control. Obtaining a Developer ID certificate is
structurally identical to operating a private CA:

```
private CA:    leaf  ->  POC Private Root CA 1                                  (locally signed)
Developer ID:  leaf  ->  Developer ID Certification Authority  ->  Apple Root CA (Apple-signed)
```

The distinction is which CA key is held by whom, and therefore whose validation the
signature satisfies. `./run-profile.sh` decodes an installed application to demonstrate the
shape:

```
Authority=Developer ID Application: AgileBits Inc. (2BUA8C4S2C)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=2BUA8C4S2C
```

The correspondence with this repository's test PKI is exact:

| this repository | Apple equivalent |
|---|---|
| `POC Private Root CA 1` | `Apple Root CA` |
| (leaves issued directly) | `Developer ID Certification Authority` |
| `signerA` / `signerB` leaves | `Developer ID Application: AgileBits Inc. (2BUA8C4S2C)` |
| `OU=POC1` on the leaf | the Team ID `2BUA8C4S2C` |
| a code requirement in the ACL | `embedded.provisionprofile` |
| the pin `certificate root = H"…"` | Apple's own DR: `anchor apple generic and certificate leaf[subject.OU] = "…"` |

### 9.2 The boundary is restricted versus unrestricted entitlements

Every mechanism in §2 and §3 works with a privately operated CA and no Developer account,
because the keychain ACL evaluates a code requirement against the caller's signature and a
private CA is a valid anchor for that purpose. A private PKI is sufficient for the
per-binary ACL pin, for `codesign` verification, and for any trust enforced internally.

A private PKI cannot satisfy validation performed inside Apple's code, because AMFI and
Gatekeeper anchor to Apple and disregard local trust settings. Measured:

```
NON-restricted entitlement (com.apple.security.cs.disable-library-validation),
  signed by a private CA                  -> runs
RESTRICTED entitlement (keychain-access-groups),
  signed by a private CA                  -> SIGKILL at launch
```

The boundary is not "signed versus unsigned" but the restricted/unrestricted distinction.
Ordinary entitlements are available with a private CA; only restricted entitlements require
an Apple-issued chain, and `keychain-access-groups` is one of them.

### 9.3 Provisioning profiles

A profile is Apple's signed statement that a team may claim specified entitlements using
specified certificates. Decoded from an installed application:

```
"TeamIdentifier"     => [ "2BUA8C4S2C" ]
"Entitlements" => {
    "com.apple.developer.team-identifier" => "2BUA8C4S2C"
    "keychain-access-groups" => [ "2BUA8C4S2C.*" ]
}
DeveloperCertificates listed: 2
```

AMFI checks that the signature chains to Apple, that the signing certificate appears in
`DeveloperCertificates`, and that the profile grants the claimed entitlement.

Two consequences affect the design:

1. **`keychain-access-groups` is team-prefixed.** On the data-protection keychain, access
   is scoped to the team rather than to one binary. Every application the team signs can
   claim a group under the prefix, and no other team can claim it. This is the closest
   available equivalent to a signer pin on the SE path, and it is coarser than a per-binary
   ACL pin. It is also the same boundary Apple's own designated requirements use.

2. **The two keychains have mutually exclusive authorization models**, which is the reason
   the SE cannot express what the ACL expresses:

   ```
   legacy file keychain  ->  kSecAttrAccess       (code requirement; no entitlement required)
   data protection kc    ->  kSecAttrAccessGroup  (team access group; restricted entitlement)
   ```

   `kSecAttrAccess` is documented as macOS-only and appears only under the legacy item
   attributes; `kSecAttrAccessGroup` applies "also macOS if
   `kSecUseDataProtectionKeychain` is set". These are the authorization models of two
   different keychains, which is the mechanism behind F8.

### 9.4 Pinning that survives certificate renewal

Apple's designated requirement for a Developer ID application illustrates the intended idiom:

```
anchor apple generic and identifier "com.agilebits.1password"
and certificate leaf[subject.OU] = "2BUA8C4S2C"
```

It pins the team through `OU` rather than through a certificate hash, because Developer ID
leaf certificates are reissued on renewal and a hash pin would break at each rotation. The
same idiom applies to a privately operated PKI. An `OU` was added to the leaf certificates
in this repository to make the comparison concrete, with A and B sharing `OU=POC1` and C
using `OU=POC2`:

```
pin team/OU POC1 (Apple-style)   unsigned .  adhoc .  signedA MATCH  signedB MATCH  signedC .
pin team/OU POC2                 unsigned .  adhoc .  signedA .      signedB .      signedC MATCH
```

| pin form | survives renewal | granularity |
|---|---|---|
| `certificate root = H"…"` | yes, while the root is unchanged | whole CA |
| `certificate root[subject.CN] = "…"` | yes | whole CA |
| `certificate leaf[subject.OU] = "…"` | yes | one team |
| `certificate leaf = H"…"` | **no** | one certificate |

The trade-off favours a locally operated PKI: because the root is under local control, a
root-hash pin is stable indefinitely, whereas Apple's chain obliges a team-ID pin to
survive rotation. For granularity finer than team level, a locally operated CA can issue a
distinct certificate per application.

---

## 10. Three-tier PKI and team isolation (F10, F11)

Structure under test, implemented by `./make-pki-tiered.sh` and exercised by
`./run-tiered.sh` and `./run-acl-tiered.sh`:

```
POC Enterprise Root            (self-signed, pathlen:1)
  +-- POC Team A Intermediate  (pathlen:0)  ->  teamA1, teamA2
  +-- POC Team B Intermediate  (pathlen:0)  ->  teamB1
```

This provides a single enterprise trust anchor and a per-team CA held only by that team's
operators, so that one team's PKI cannot be used to mint another team's identities.
`pathlen:1` on the root and `pathlen:0` on each team CA prevent a team CA from creating
further CAs.

### 10.1 `certificate root` denotes the enterprise root (F10)

With a three-deep chain, `certificate root` denotes the enterprise root rather than the team
CA. A requirement of `certificate root = H"…"` therefore admits every team, which is
precisely the inclusion that a team hierarchy is intended to prevent. macOS's derived
designated requirement has the same shape, so all three team binaries report an identical
requirement:

```
pocclient-teamA1  identifier "com.poc.client" and certificate root = H"09b51485…"
pocclient-teamA2  identifier "com.poc.client" and certificate root = H"09b51485…"
pocclient-teamB1  identifier "com.poc.client" and certificate root = H"09b51485…"
```

`09b51485…` is the enterprise root, so an unqualified pin admits all three.

Certificate numbering in a three-tier chain:

| requirement term | denotes |
|---|---|
| `certificate leaf` (= `certificate 0`) | the signing certificate |
| `certificate 1` | the team intermediate |
| `certificate 2` (= `certificate root`) | the enterprise root |

Requirement forms evaluated against each team binary (`./run-tiered.sh`):

```
requirement                             teamA1   teamA2   teamB1
certificate root = enterprise root      MATCH    MATCH    MATCH      admits every team
certificate root = team A               .        .        .          matches nothing
certificate 1 = team A                  MATCH    MATCH    .
certificate 1 = team B                  .        .        MATCH
certificate 2 = enterprise root         MATCH    MATCH    MATCH
certificate 1 CN = Team A               MATCH    MATCH    .
certificate 1 CN = Team B               .        .        MATCH
certificate leaf OU = TEAMA             MATCH    MATCH    .
certificate leaf OU = TEAMB             .        .        MATCH
anchor apple generic                    .        .        .
anchor trusted                          MATCH    MATCH    MATCH
```

The second row is a failure in the opposite direction: naming the team CA through
`certificate root` matches nothing, because `root` denotes the last certificate in the
chain. A pin that silently matches nothing is as damaging as one that matches everything,
and it is not evident on review.

Confirmed against real keychain ACLs rather than the requirement evaluator alone
(`./run-acl-tiered.sh`), since the two have been observed to disagree:

```
caller   pin-teamA-via-cert1     pin-teamA-via-OU        pin-enterprise-root
teamA1   GRANTED                 GRANTED                 GRANTED
teamA2   GRANTED                 GRANTED                 GRANTED
teamB1   deny-use                deny-use                GRANTED
```

The third column admits team B when the intent was to restrict to team A. Team isolation in
a three-tier hierarchy therefore requires a `certificate 1` pin, by hash or by
`[subject.CN]`, or a team-identifier pin on the leaf via `certificate leaf[subject.OU]`.

### 10.2 Name constraints are unavailable (F11)

Constraining each team CA with X.509 `nameConstraints`, so that it can issue only into its
own DN branch, does not work with Apple's DN ordering. `./run-nameconstraints.sh` shows the
result:

```
                 openssl                    macOS verify-cert
apple_ok      REJECTED (subtree violation)   REJECTED    correct leaf, CN first
apple_bad     REJECTED (subtree violation)   REJECTED
ou_first_ok   accepted                       accepted    same certificate, OU first
ou_first_bad  REJECTED (subtree violation)   REJECTED
```

A permitted `dirName` subtree must be a prefix of the subject's RDN sequence. Apple places
`CN` first and the team identifier (`OU`) second, so a constraint on `OU` can never be an
ancestor of such a subject and every leaf fails, correct ones included. Reordering the
subject so that `OU` leads makes the constraint functional, and macOS enforces it correctly
in that arrangement.

Two conclusions follow: macOS does enforce name constraints for the code-signing policy, and
the enforcement tests structural prefix only, not the semantic role of the `OU`. The
obstruction is Apple's DN layout rather than the platform's implementation.

The practical consequence is that name constraints should be treated as unavailable, and
the `certificate 1` pin is the control that isolates a team. A team CA is not prevented at
the X.509 layer from issuing into another team's naming; that must be controlled
operationally, through custody of the team CA key.

---

## 11. Platform notes

Each of the following produced a misleading result rather than an evident error. They are
recorded because each can waste substantial time, and because several of them make a
correct configuration appear broken or a broken one appear correct.

- **`security` resolves a relative keychain path under `~/Library/Keychains`, not the
  working directory.** Use absolute paths. A keychain created in the wrong location is
  indistinguishable from an empty keychain.
- **`codesign --keychain <path>` requires the keychain to also be in the search list.**
  Without it, codesign reports `"<identity>: no identity found"`. With `--entitlements` it
  can fall back to an **ad-hoc** signature and exit `0`, which silently invalidates an
  entitlement test, since AMFI rejects an ad-hoc binary for a different reason than the one
  under test. Assert the resulting `Authority=` line. The scripts here add to the search
  list (`poc_keychain_add`) rather than replacing it, so that both PKI flows can be run in
  either order.
- **`codesign -dvvv` writes to stderr, not stdout.**
- **`codesign -dvvv … | grep -q` fails under `set -o pipefail`.** `grep -q` exits at the
  first match, `codesign` receives SIGPIPE, and the pipeline reports `141`, so a valid
  signature reads as a failure. Redirect to a file and search the file, or use `case`.
- **`security delete-certificate -c <name>` requires a unique match.** Repeated
  `make-pki.sh` executions leave several certificate generations sharing a common name, at
  which point every deletion fails as ambiguous. Delete by SHA-1 instead.
- **ANY change to the trust store raises a Touch ID / password dialog**, including a
  first-time `add-trusted-cert`. `trust-settings-import` is silent only when the list is
  unchanged. There is no unattended path, so scripts must refuse rather than attempt it.
- **A private-CA chain must be trusted or `codesign` refuses to sign**, reporting
  `errSecInternalComponent` with a `leaf MissingIntermediate` log entry. Two conditions are
  required: the root present in a keychain that trustd searches (the login keychain works; a
  side keychain does not), and the CA trusted for the `codeSign` policy. For a three-deep
  chain the intermediates must also be findable.
- **`codesign` requires `codesign:` in the private key's partition list**, or it fails with
  `errSecInternalComponent`:
  `security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k <pw> <keychain>`.
- **A modern `SecItemCopyMatching` ignores `kSecUseKeychain`.** Use `kSecMatchSearchList`,
  or place the keychain in the search list. Otherwise the call returns `errSecItemNotFound`,
  which is indistinguishable from an ACL denial and directs attention to the requirement
  rather than the query.
- **`SecTrustedApplicationCreateFromPath` produces a path-based entry only**, including for
  Apple-signed binaries. `security … -T` and `SecAccessCreate(desc, @[ pathApp ])`
  consequently perform path pinning, which any process running from that path satisfies.
- **`security` has no `delete-key` command**, which is why `bin/rmkeys` exists, to remove
  keys created by the Secure Enclave experiments.
- **An asymmetric key is two keychain items, public and private, sharing one label.** A
  lookup by label alone can therefore return the *public* key, whose ACL is the permissive
  default, and an ACL inspection then reports no requirement pin even though the private key
  carries one. `pocsetup dumpacl` did exactly this and briefly appeared to show that a
  correctly pinned key was unrestricted. Filter on `kSecAttrKeyClass = kSecAttrKeyClassPrivate`
  when inspecting the ACL that governs signing. The client in this repository already did so,
  which is why the access matrix stayed correct while the inspection tool was wrong.

---

## 12. Reproduction

Both flows require their steps to be run in order.

```
./teardown.sh        # clean machine (optional; see the ordering note below)
./build.sh           # build the test utilities into bin/
./make-pki.sh        # self-signed CAs and code-signing leaves
./setup-trust.sh     # trust the CAs in the user domain; create the signing keychain
./make-keys.sh       # create the ACL-pinned test keys
./build-binaries.sh  # build and sign the client five ways
./run-matrix.sh      # keychain access matrix (F1, F2)
./run-reqmatrix.sh   # the same requirements evaluated without the keychain (F12)
./run-aclstruct.sh   # stored ACL subject structure, from the securityd log (F3)
./run-extraction.sh  # use versus extraction of the key material (F16)
./run-prompt-approval.sh  # what approving the keychain prompt actually requires and grants
./run-injection.sh   # code injection, plain versus hardened (F7)
./run-se.sh          # Secure Enclave: entitlements, gates, silent downgrade (F8, F9)
./run-profile.sh     # an installed application's Developer ID chain and profile
./teardown.sh        # remove everything this repository added to the machine
```

The three-tier hierarchy is a separate flow, because it requires its own root and keychain:

```
./make-pki-tiered.sh        # enterprise root, Team A and Team B intermediates, leaves
./setup-trust-tiered.sh     # trust the enterprise root; import the team leaves
./build-binaries-tiered.sh  # sign the client once per team
./run-tiered.sh             # which requirement form isolates a team (F10)
./run-acl-tiered.sh         # the same, against real keychain item ACLs (F10)
./run-nameconstraints.sh    # whether X.509 name constraints are usable (F11)
```

Either flow may be run in either order. The scripts add their keychain to the search list
rather than replacing it, because `codesign --keychain <path>` on its own reports "no
identity found" when the keychain is absent from the list.

Ordering within a flow is significant. Trust settings are keyed to the certificate, so
re-running `make-pki.sh` after `setup-trust.sh` invalidates them: the CA retains its subject
name but acquires a new key, and `security verify-cert` no longer accepts the leaves.
`setup-trust.sh` detects this, removes its own stale trust entries and re-trusts, so either
order converges. Trust entries cannot be removed by certificate path once the certificate is
gone, which is why the trust list is edited directly (`lib-trust.sh`) rather than through
`security remove-trusted-cert`.

Layout:

| path | contents |
|---|---|
| `pki/` | CA and leaf certificate material with the OpenSSL configurations used to generate it |
| `tools/` | source for the test utilities (`pocsetup.m`, `pocclient.m`, `pocse.m`, `pocexport.m`, `libinject.m`, `rmkeys.m`) |
| `bin/` | built utilities, the injected test library, and the signed test clients |
| `work/` | keychains, PKCS#12 archives, and pinned-requirement records |
| `lib-trust.sh` | shared trust-settings and keychain-search-list helpers |

The Secure Enclave experiments that targeted the legacy keychain created real software
keys, a consequence of the silent downgrade described in §8.2. They have been removed;
`bin/rmkeys <label>` exists for that purpose, since `security` provides no `delete-key`
command. Re-running those experiments creates further keys, which should likewise be
removed afterwards.
