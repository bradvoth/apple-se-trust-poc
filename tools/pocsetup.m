// pocsetup.m - POC tooling for keychain ACL / code-requirement experiments.
// Uses the legacy (file-keychain) Security APIs, which are deprecated but still
// functional on macOS 26 and are the only ones that expose item ACLs.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <Security/cssmtype.h>
#include <Security/cssmapple.h>

// --- SPI (exported from Security.framework, declared in Apple's open source
//     SecTrustedApplicationPriv.h; not present in the public SDK headers) ---
extern OSStatus SecTrustedApplicationCreateFromRequirement(const char *description,
                                                           SecRequirementRef requirement,
                                                           SecTrustedApplicationRef *app);
extern OSStatus SecTrustedApplicationCopyRequirement(SecTrustedApplicationRef appRef,
                                                     SecRequirementRef *requirement);
extern OSStatus SecTrustedApplicationCreateApplicationGroup(const char *groupName,
                                                            SecCertificateRef anchor,
                                                            SecTrustedApplicationRef *app);
extern OSStatus SecTrustedApplicationCopyExternalRepresentation(SecTrustedApplicationRef appRef,
                                                                CFDataRef *externalRef);
extern OSStatus SecTrustedApplicationCreateWithExternalRepresentation(CFDataRef externalRef,
                                                                      SecTrustedApplicationRef *appRef);

static void hexdump(const char *tag, CFDataRef d) {
    const UInt8 *b = CFDataGetBytePtr(d);
    CFIndex n = CFDataGetLength(d);
    printf("%s (%ld bytes):\n", tag, (long)n);
    for (CFIndex i = 0; i < n; i += 16) {
        printf("  %04lx  ", (long)i);
        for (CFIndex j = i; j < i + 16 && j < n; j++) printf("%02x ", b[j]);
        for (CFIndex j = i; j < i + 16 && j < n; j++) printf("%c", (b[j] >= 32 && b[j] < 127) ? b[j] : '.');
        printf("\n");
    }
}

static void showTAppRequirement(SecTrustedApplicationRef app);

// The running process's own cdhash, as lowercase hex. Plain C: this file is ObjC, not ObjC++.
static void cdhashString(SecCodeRef code, char *out, size_t outLen) {
    out[0] = 0;
    CFDictionaryRef info = NULL;
    if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) != errSecSuccess || !info)
        return;
    CFDataRef u = (CFDataRef)CFDictionaryGetValue(info, kSecCodeInfoUnique);
    if (u) {
        const UInt8 *b = CFDataGetBytePtr(u);
        size_t n = 0;
        for (CFIndex i = 0; i < CFDataGetLength(u) && n + 3 < outLen; i++)
            n += (size_t)snprintf(out + n, outLen - n, "%02x", b[i]);
    }
    CFRelease(info);
}


// Try to interpret a blob as a code requirement and print it in text form.
static void showAsRequirement(CFDataRef d) {    SecRequirementRef req = NULL;
    OSStatus st = SecRequirementCreateWithData(d, kSecCSDefaultFlags, &req);
    if (st == errSecSuccess && req) {
        CFStringRef s = NULL;
        if (SecRequirementCopyString(req, kSecCSDefaultFlags, &s) == errSecSuccess && s) {
            printf("  -> parses as a code requirement: %s\n", [(__bridge NSString *)s UTF8String]);
            CFRelease(s);
        }
        CFRelease(req);
    } else {
        printf("  -> not a code-requirement blob (SecRequirementCreateWithData = %d)\n", (int)st);
    }
}

static void dumpTApp(const char *label, const char *path) {
    printf("\n=== trusted application from %s: %s ===\n", label, path ? path : "(self/NULL)");
    SecTrustedApplicationRef app = NULL;
    OSStatus st = SecTrustedApplicationCreateFromPath(path, &app);
    if (st != errSecSuccess) { printf("  CreateFromPath failed: %d\n", (int)st); return; }
    CFDataRef d = NULL;
    st = SecTrustedApplicationCopyData(app, &d);
    if (st != errSecSuccess) { printf("  CopyData failed: %d\n", (int)st); CFRelease(app); return; }
    hexdump("  external form", d);
    showAsRequirement(d);
    CFRelease(d);
    CFRelease(app);
}

static void cmdDumpTApp(const char *path) {
    dumpTApp("signed-or-unsigned", path);
    dumpTApp("self", NULL);
}

// ---- create a private key whose ACL trusts a list of applications ----
// usage: mkkey <keychain> <label> <tapp-path>...
static int cmdMkKey(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: mkkey <keychain> <label> <path>...\n"); return 2; }
    const char *kcPath = argv[1];
    const char *label  = argv[2];

    SecKeychainRef kc = NULL;
    OSStatus st = SecKeychainOpen(kcPath, &kc);
    if (st != errSecSuccess) { fprintf(stderr, "open keychain %s: %d\n", kcPath, (int)st); return 1; }
    st = SecKeychainUnlock(kc, 0, NULL, 0);   // uses keychain's cached/unlocked state
    printf("unlock(%s) = %d\n", kcPath, (int)st);

    CFMutableArrayRef apps = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (int i = 3; i < argc; i++) {
        SecTrustedApplicationRef a = NULL;
        st = SecTrustedApplicationCreateFromPath(argv[i], &a);
        printf("trusted app <- %s : %d\n", argv[i], (int)st);
        if (st == errSecSuccess) { CFArrayAppendValue(apps, a); CFRelease(a); }
    }

    SecAccessRef access = NULL;
    st = SecAccessCreate(CFSTR("poc-pinned-key"), apps, &access);
    printf("SecAccessCreate = %d (apps=%ld)\n", (int)st, (long)CFArrayGetCount(apps));
    if (st != errSecSuccess) return 1;

    // Show what ended up in the access object before we hand it to the keychain.
    CFArrayRef acls = NULL;
    if (SecAccessCopyACLList(access, &acls) == errSecSuccess) {
        printf("  ACL entries in access object: %ld\n", (long)CFArrayGetCount(acls));
        for (CFIndex i = 0; i < CFArrayGetCount(acls); i++) {
            SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
            CFArrayRef list = NULL; CFStringRef desc = NULL; SecKeychainPromptSelector ps = 0;
            if (SecACLCopyContents(acl, &list, &desc, &ps) == errSecSuccess) {
                printf("    [%ld] desc=%s promptSelector=%u apps=%ld\n", (long)i,
                       desc ? [(__bridge NSString *)desc UTF8String] : "(null)",
                       (unsigned)ps, list ? (long)CFArrayGetCount(list) : -1L);
                if (list) for (CFIndex j = 0; j < CFArrayGetCount(list); j++) {
                    CFDataRef d = NULL;
                    SecTrustedApplicationCopyData((SecTrustedApplicationRef)CFArrayGetValueAtIndex(list, j), &d);
                    if (d) {
                        const UInt8 *bp = CFDataGetBytePtr(d);
                        printf("        app[%ld] %ld bytes, first=0x%02x\n", (long)j, (long)CFDataGetLength(d),
                               CFDataGetLength(d) ? bp[0] : 0);
                        showAsRequirement(d);
                        CFRelease(d);
                    }
                }
                if (list) CFRelease(list);
                if (desc) CFRelease(desc);
            }
        }
        CFRelease(acls);
    }

    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attrs, kSecUseKeychain, kc);
    CFDictionarySetValue(attrs, kSecAttrLabel, CFSTR("poc-pinned-key"));
    CFDictionarySetValue(attrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(attrs, kSecAttrAccess, access);

    CFMutableDictionaryRef priv = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(priv, kSecAttrLabel, (__bridge CFStringRef)[NSString stringWithUTF8String:label]);
    CFDictionarySetValue(priv, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(priv, kSecAttrAccess, access);

    CFMutableDictionaryRef params = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(params, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionarySetValue(params, kSecAttrKeySizeInBits, (__bridge CFNumberRef)@2048);
    CFDictionarySetValue(params, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(params, kSecAttrLabel, (__bridge CFStringRef)[NSString stringWithUTF8String:label]);
    CFDictionarySetValue(params, kSecUseKeychain, kc);
    CFDictionarySetValue(params, kSecAttrAccess, access);
    CFDictionarySetValue(params, kSecPrivateKeyAttrs, priv);

    CFErrorRef err = NULL;
    SecKeyRef key = SecKeyCreateRandomKey(params, &err);
    if (!key) {
        fprintf(stderr, "SecKeyCreateRandomKey failed: %s\n",
                err ? [[(__bridge NSError *)err localizedDescription] UTF8String] : "(no error)");
        return 1;
    }
    printf("key created ok\n");
    CFRelease(key);
    return 0;
}

// ---- dump the ACLs of an existing keychain key ----
// usage: dumpacl <keychain> <label>
static int cmdDumpACL(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: dumpacl <keychain> <label>\n"); return 2; }
    SecKeychainRef kc = NULL;
    if (SecKeychainOpen(argv[1], &kc) != errSecSuccess) { fprintf(stderr, "open failed\n"); return 1; }
    SecKeychainUnlock(kc, 0, NULL, 0);

    NSDictionary *q = @{
        (__bridge id)kSecClass:           (__bridge id)kSecClassKey,
        // An asymmetric key pair is TWO keychain items, a public and a private key, and
        // both carry the same label. Without this filter the lookup can return the public
        // key, whose ACL is the permissive default, and the report then wrongly shows no
        // requirement pin. The private key is the one whose ACL governs signing.
        (__bridge id)kSecAttrKeyClass:    (__bridge id)kSecAttrKeyClassPrivate,
        (__bridge id)kSecAttrLabel:       [NSString stringWithUTF8String:argv[2]],
        // kSecUseKeychain is IGNORED by the modern query path, so a lookup that uses it
        // can silently resolve the label in a different keychain and report that item's
        // ACL instead. Use kSecMatchSearchList, which is honoured.
        (__bridge id)kSecMatchSearchList: @[ (__bridge id)kc ],
        (__bridge id)kSecReturnRef:       @YES,
        (__bridge id)kSecMatchLimit:      (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (st != errSecSuccess) { fprintf(stderr, "SecItemCopyMatching: %d\n", (int)st); return 1; }

    SecKeychainItemRef item = (SecKeychainItemRef)out;
    SecAccessRef access = NULL;
    st = SecKeychainItemCopyAccess(item, &access);
    printf("SecKeychainItemCopyAccess = %d\n", (int)st);
    if (st != errSecSuccess) return 1;

    CFArrayRef acls = NULL;
    SecAccessCopyACLList(access, &acls);
    printf("ACL entries: %ld\n", acls ? (long)CFArrayGetCount(acls) : -1L);
    if (acls) for (CFIndex i = 0; i < CFArrayGetCount(acls); i++) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
        CFArrayRef auths = SecACLCopyAuthorizations(acl);
        CFArrayRef list = NULL; CFStringRef desc = NULL; SecKeychainPromptSelector ps = 0;
        SecACLCopyContents(acl, &list, &desc, &ps);
        printf("  [%ld] desc=%s promptSelector=%u auths=%s apps=%ld\n", (long)i,
               desc ? [(__bridge NSString *)desc UTF8String] : "(null)", (unsigned)ps,
               auths ? [[(__bridge NSArray *)auths componentsJoinedByString:@","] UTF8String] : "(null)",
               list ? (long)CFArrayGetCount(list) : -1L);
        if (list) for (CFIndex j = 0; j < CFArrayGetCount(list); j++) {
            SecTrustedApplicationRef ta = (SecTrustedApplicationRef)CFArrayGetValueAtIndex(list, j);
            CFDataRef d = NULL;
            SecTrustedApplicationCopyData(ta, &d);
            if (d) {
                printf("      app[%ld] %ld bytes\n", (long)j, (long)CFDataGetLength(d));
                showAsRequirement(d);
                CFRelease(d);
            }
            showTAppRequirement(ta);
        }
        if (list) CFRelease(list);
        if (auths) CFRelease(auths);
        if (desc) CFRelease(desc);
    }
    return 0;
}

// ---- print a trusted app's recorded code requirement, if any ----
static void showTAppRequirement(SecTrustedApplicationRef app) {
    SecRequirementRef req = NULL;
    OSStatus st = SecTrustedApplicationCopyRequirement(app, &req);
    if (st != errSecSuccess) { printf("      (CopyRequirement failed: %d)\n", (int)st); return; }
    if (!req) { printf("      requirement: (none - path-based entry)\n"); return; }
    CFStringRef s = NULL;
    if (SecRequirementCopyString(req, kSecCSDefaultFlags, &s) == errSecSuccess && s) {
        printf("      requirement: %s\n", [(__bridge NSString *)s UTF8String]);
        CFRelease(s);
    }
    CFRelease(req);
}

// ---- introspection: build a trusted app from a requirement, and round-trip it ----
// usage: tappreq '<requirement>' [description]
static int cmdTAppReq(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: tappreq <requirement> [description]\n"); return 2; }
    SecRequirementRef req = NULL;
    OSStatus st = SecRequirementCreateWithString((__bridge CFStringRef)[NSString stringWithUTF8String:argv[1]],
                                                 kSecCSDefaultFlags, &req);
    if (st != errSecSuccess) { fprintf(stderr, "bad requirement: %d\n", (int)st); return 1; }

    SecTrustedApplicationRef app = NULL;
    st = SecTrustedApplicationCreateFromRequirement(argc > 2 ? argv[2] : "poc-requirement", req, &app);
    printf("SecTrustedApplicationCreateFromRequirement = %d\n", (int)st);
    if (st != errSecSuccess) return 1;

    CFDataRef ext = NULL;
    if (SecTrustedApplicationCopyExternalRepresentation(app, &ext) == errSecSuccess && ext) {
        hexdump("  external representation", ext);
        // round-trip check
        SecTrustedApplicationRef app2 = NULL;
        OSStatus rt = SecTrustedApplicationCreateWithExternalRepresentation(ext, &app2);
        printf("  round-trip CreateWithExternalRepresentation = %d\n", (int)rt);
        if (rt == errSecSuccess) {
            if (CFEqual(app, app2)) printf("  round-trip equal\n");
            showTAppRequirement(app2);
            CFRelease(app2);
        }
        CFRelease(ext);
    }
    showTAppRequirement(app);
    return 0;
}

// ---- build a strict access object: one ACL, one requirement-based trusted app,
//      no prompting at all for anyone else ----
static SecAccessRef makeRequirementAccess(CFStringRef descriptor, CFStringRef reqString) {
    SecRequirementRef req = NULL;
    if (SecRequirementCreateWithString(reqString, kSecCSDefaultFlags, &req) != errSecSuccess) {
        fprintf(stderr, "bad requirement string\n"); return NULL;
    }
    SecTrustedApplicationRef app = NULL;
    OSStatus st = SecTrustedApplicationCreateFromRequirement("poc-requirement", req, &app);
    if (st != errSecSuccess) { fprintf(stderr, "CreateFromRequirement: %d\n", (int)st); return NULL; }

    // Start from a plain access object and strip every default ACL entry, so the
    // requirement entry is the only way in.
    SecAccessRef access = NULL;
    st = SecAccessCreate(descriptor, NULL, &access);
    if (st != errSecSuccess) { fprintf(stderr, "SecAccessCreate: %d\n", (int)st); return NULL; }
    CFArrayRef existing = NULL;
    if (SecAccessCopyACLList(access, &existing) == errSecSuccess) {
        for (CFIndex i = 0; i < CFArrayGetCount(existing); i++)
            printf("  removing default ACL[%ld]: %d\n", (long)i,
                   (int)SecACLRemove((SecACLRef)CFArrayGetValueAtIndex(existing, i)));
        CFRelease(existing);
    }
    SecACLRef acl = NULL;
    st = SecACLCreateWithSimpleContents(access, (__bridge CFArrayRef)@[ (__bridge id)app ],
                                        descriptor, 0 /* never prompt */, &acl);
    printf("  SecACLCreateWithSimpleContents = %d\n", (int)st);
    if (st != errSecSuccess) return NULL;
    st = SecACLUpdateAuthorizations(acl, (__bridge CFArrayRef)@[
            (__bridge id)kSecACLAuthorizationDecrypt,
            (__bridge id)kSecACLAuthorizationSign ]);
    printf("  SecACLUpdateAuthorizations = %d\n", (int)st);

    // Show the access object we are about to hand to the keychain.
    CFArrayRef final = NULL;
    if (SecAccessCopyACLList(access, &final) == errSecSuccess) {
        printf("  final access object: %ld ACL entr%s\n", (long)CFArrayGetCount(final),
               CFArrayGetCount(final) == 1 ? "y" : "ies");
        for (CFIndex i = 0; i < CFArrayGetCount(final); i++) {
            SecACLRef a = (SecACLRef)CFArrayGetValueAtIndex(final, i);
            CFArrayRef apps = NULL; CFStringRef desc = NULL; SecKeychainPromptSelector ps = 0;
            SecACLCopyContents(a, &apps, &desc, &ps);
            CFArrayRef auths = SecACLCopyAuthorizations(a);
            printf("    [%ld] desc='%s' promptSelector=0x%04x auths=%s trustedApps=%ld\n", (long)i,
                   desc ? [(__bridge NSString *)desc UTF8String] : "",
                   (unsigned)ps,
                   auths ? [[(__bridge NSArray *)auths componentsJoinedByString:@","] UTF8String] : "?",
                   apps ? (long)CFArrayGetCount(apps) : -1L);
            if (apps) for (CFIndex j = 0; j < CFArrayGetCount(apps); j++)
                showTAppRequirement((SecTrustedApplicationRef)CFArrayGetValueAtIndex(apps, j));
            if (apps) CFRelease(apps);
            if (auths) CFRelease(auths);
            if (desc) CFRelease(desc);
        }
        CFRelease(final);
    }
    return access;
}

// usage: mkkeyreq <keychain> <label> '<requirement>' [description]
static int cmdMkKeyReq(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: mkkeyreq <keychain> <label> <requirement> [descriptor]\n"); return 2; }
    SecKeychainRef kc = NULL;
    if (SecKeychainOpen(argv[1], &kc) != errSecSuccess) { fprintf(stderr, "open keychain failed\n"); return 1; }
    SecKeychainUnlock(kc, 0, NULL, 0);

    printf("creating key '%s' pinned to requirement:\n  %s\n", argv[2], argv[3]);
    SecAccessRef access = makeRequirementAccess((__bridge CFStringRef)[NSString stringWithUTF8String:argv[2]],
                                                (__bridge CFStringRef)[NSString stringWithUTF8String:argv[3]]);
    if (!access) return 1;

    NSDictionary *params = @{
        (__bridge id)kSecAttrKeyType:       (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeySizeInBits: @2048,
        (__bridge id)kSecAttrIsPermanent:   @YES,
        (__bridge id)kSecAttrLabel:         [NSString stringWithUTF8String:argv[2]],
        (__bridge id)kSecUseKeychain:       (__bridge id)kc,
        (__bridge id)kSecAttrAccess:        (__bridge id)access,
        (__bridge id)kSecPrivateKeyAttrs: @{
            (__bridge id)kSecAttrLabel:       [NSString stringWithUTF8String:argv[2]],
            (__bridge id)kSecAttrIsPermanent: @YES,
            (__bridge id)kSecAttrAccess:      (__bridge id)access,
        },
    };
    CFErrorRef err = NULL;
    SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)params, &err);
    if (!key) {
        fprintf(stderr, "SecKeyCreateRandomKey failed: %s\n",
                err ? [[(__bridge NSError *)err localizedDescription] UTF8String] : "?");
        return 1;
    }
    printf("key created ok\n");
    CFRelease(key);
    return 0;
}

// Build a raw CSSM ACL whose single subject is *only* a code-signing requirement.
// SecACLCreateWithSimpleContents always wraps the caller's requirement in a
// ThresholdAclSubject together with a KeychainPromptAclSubject, which leaves a
// "just ask the user" path open. Hand-building the CSSM_LIST avoids that.
// usage: mkkeycssm <keychain> <label> '<requirement>'
static int cmdMkKeyCssm(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: mkkeycssm <keychain> <label> <requirement>\n"); return 2; }
    SecKeychainRef kc = NULL;
    if (SecKeychainOpen(argv[1], &kc) != errSecSuccess) { fprintf(stderr, "open keychain failed\n"); return 1; }
    SecKeychainUnlock(kc, 0, NULL, 0);

    SecRequirementRef req = NULL;
    OSStatus st = SecRequirementCreateWithString((__bridge CFStringRef)[NSString stringWithUTF8String:argv[3]],
                                                 kSecCSDefaultFlags, &req);
    if (st != errSecSuccess) { fprintf(stderr, "bad requirement: %d\n", (int)st); return 1; }
    CFDataRef reqData = NULL;
    st = SecRequirementCopyData(req, kSecCSDefaultFlags, &reqData);
    if (st != errSecSuccess) { fprintf(stderr, "SecRequirementCopyData: %d\n", (int)st); return 1; }
    printf("requirement %s (%ld bytes of requirement data)\n", argv[3], (long)CFDataGetLength(reqData));

    // Does the requirement already authorise THIS process? SecAccessCreateFromOwnerAndACL
    // appears to substitute a cdhash entry for the creating process on write, so a raw ACL
    // that already admits the creator should survive intact. Determine that rather than
    // assume it, and report which of the two paths is being taken.
    SecCodeRef selfCode = NULL;
    bool selfMatches = false;
    char selfHash[128] = {0};
    if (SecCodeCopySelf(kSecCSDefaultFlags, &selfCode) == errSecSuccess) {
        cdhashString(selfCode, selfHash, sizeof selfHash);
        CFURLRef selfURL = NULL;
        if (SecCodeCopyPath(selfCode, kSecCSDefaultFlags, &selfURL) == errSecSuccess) {
            SecStaticCodeRef sc = NULL;
            if (SecStaticCodeCreateWithPath(selfURL, kSecCSDefaultFlags, &sc) == errSecSuccess) {
                selfMatches = (SecStaticCodeCheckValidity(sc, kSecCSDefaultFlags, req) == errSecSuccess);
                CFRelease(sc);
            }
            CFRelease(selfURL);
        }
        CFRelease(selfCode);
    }
    printf("creator %s the stated requirement; its own cdhash is H\"%s\"\n",
           selfMatches ? "matches" : "does NOT match", selfHash);

    // Element list layout, per CodeSignatureAclSubject::Maker::make():
    //   [1] wordid  = CSSM_ACL_CODE_SIGNATURE_OSX
    //   [2] datum   = 20-byte legacy hash (unused when a requirement is present)
    //   [3] datum   = path, NUL terminated (comment only)
    //   [4] datum   = the SecRequirement blob
    uint32_t sigType = CSSM_ACL_CODE_SIGNATURE_OSX;
    static uint8_t zeroHash[20];
    static char pathBuf[] = "poc-requirement";
    CSSM_DATA d_sigtype = { (CSSM_SIZE)sizeof(uint32_t), (uint8 *)&sigType };
    CSSM_DATA d_hash    = { (CSSM_SIZE)sizeof(zeroHash), zeroHash };
    CSSM_DATA d_path    = { (CSSM_SIZE)sizeof(pathBuf), (uint8 *)pathBuf };
    CSSM_DATA d_req     = { (CSSM_SIZE)CFDataGetLength(reqData), (uint8 *)CFDataGetBytePtr(reqData) };

    CSSM_LIST_ELEMENT e4 = { NULL,   0, CSSM_LIST_ELEMENT_DATUM,  { { 0, NULL } } };
    CSSM_LIST_ELEMENT e3 = { &e4,    0, CSSM_LIST_ELEMENT_DATUM,  { { 0, NULL } } };
    CSSM_LIST_ELEMENT e2 = { &e3,    0, CSSM_LIST_ELEMENT_DATUM,  { { 0, NULL } } };
    CSSM_LIST_ELEMENT e1 = { &e2,    0, CSSM_LIST_ELEMENT_WORDID, { { 0, NULL } } };
    e4.Element.Word = d_req;
    e3.Element.Word = d_path;
    e2.Element.Word = d_hash;
    e1.Element.Word = d_sigtype;
    CSSM_LIST subject = { CSSM_ACL_SUBJECT_TYPE_CODE_SIGNATURE, &e1, &e4 };
    printf("subject list type=0x%08x (CSSM_ACL_SUBJECT_TYPE_CODE_SIGNATURE=0x%08x)\n",
           (unsigned)subject.ListType, (unsigned)CSSM_ACL_SUBJECT_TYPE_CODE_SIGNATURE);

    // Owner: a process subject for the current user, as SecAccessCreateWithOwnerAndACL does.
    CSSM_ACL_PROCESS_SUBJECT_SELECTOR selector = {
        CSSM_ACL_PROCESS_SELECTOR_CURRENT_VERSION,
        CSSM_ACL_MATCH_UID | CSSM_ACL_MATCH_HONOR_ROOT,
        getuid(), getgid()
    };
    CSSM_LIST_ELEMENT o2 = { NULL, 0, CSSM_LIST_ELEMENT_DATUM, { { 0, NULL } } };
    o2.Element.Word.Length = (CSSM_SIZE)sizeof(selector);
    o2.Element.Word.Data   = (uint8 *)&selector;
    CSSM_LIST_ELEMENT o1 = { &o2, CSSM_ACL_SUBJECT_TYPE_PROCESS, CSSM_LIST_ELEMENT_WORDID, { { 0, NULL } } };
    CSSM_ACL_OWNER_PROTOTYPE owner = { { CSSM_LIST_TYPE_UNKNOWN, &o1, &o2 }, false };

    // Exactly one ACL entry: the code-signature subject, and nothing else.
    static CSSM_ACL_AUTHORIZATION_TAG tags[] = {
        CSSM_ACL_AUTHORIZATION_DECRYPT, CSSM_ACL_AUTHORIZATION_SIGN
    };
    CSSM_ACL_ENTRY_INFO entry = {
        { subject, false, { 2, tags }, { { 0, NULL }, { 0, NULL } }, 0 },
        0
    };

    SecAccessRef access = NULL;
    st = SecAccessCreateFromOwnerAndACL(&owner, 1, &entry, &access);
    printf("  SecAccessCreateFromOwnerAndACL = %d\n", (int)st);
    if (st != errSecSuccess || !access) return 1;

    CFArrayRef acls = NULL;
    if (SecAccessCopyACLList(access, &acls) == errSecSuccess && acls) {
        printf("  resulting access object: %ld ACL entr%s\n", (long)CFArrayGetCount(acls),
               CFArrayGetCount(acls) == 1 ? "y" : "ies");
        for (CFIndex i = 0; i < CFArrayGetCount(acls); i++) {
            SecACLRef a = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
            CFArrayRef apps = NULL; CFStringRef desc = NULL; SecKeychainPromptSelector ps = 0;
            SecACLCopyContents(a, &apps, &desc, &ps);
            CFArrayRef auths = SecACLCopyAuthorizations(a);
            printf("    [%ld] desc='%s' promptSelector=0x%04x auths=%s trustedApps=%ld\n", (long)i,
                   desc ? [(__bridge NSString *)desc UTF8String] : "", (unsigned)ps,
                   auths ? [[(__bridge NSArray *)auths componentsJoinedByString:@","] UTF8String] : "?",
                   apps ? (long)CFArrayGetCount(apps) : -1L);
            if (apps) CFRelease(apps);
            if (auths) CFRelease(auths);
            if (desc) CFRelease(desc);
        }
        CFRelease(acls);
    }

    NSDictionary *params = @{
        (__bridge id)kSecAttrKeyType:       (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeySizeInBits: @2048,
        (__bridge id)kSecAttrIsPermanent:   @YES,
        (__bridge id)kSecAttrLabel:         [NSString stringWithUTF8String:argv[2]],
        (__bridge id)kSecUseKeychain:       (__bridge id)kc,
        (__bridge id)kSecPrivateKeyAttrs: @{
            (__bridge id)kSecAttrLabel:       [NSString stringWithUTF8String:argv[2]],
            (__bridge id)kSecAttrIsPermanent: @YES,
        },
    };
    CFErrorRef err = NULL;
    SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)params, &err);
    if (!key) {
        fprintf(stderr, "SecKeyCreateRandomKey failed: %s\n",
                err ? [[(__bridge NSError *)err localizedDescription] UTF8String] : "?");
        return 1;
    }
    printf("key created ok (permissive ACL initially)\n");

    // The CSP refuses to generate a key straight into an ACL that does not
    // authorize the generating process, so create first and swap the
    // restrictive access in afterwards.
    NSDictionary *q = @{
        (__bridge id)kSecClass:           (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrKeyClass:    (__bridge id)kSecAttrKeyClassPrivate,
        (__bridge id)kSecAttrLabel:       [NSString stringWithUTF8String:argv[2]],
        (__bridge id)kSecMatchSearchList: @[ (__bridge id)kc ],
        (__bridge id)kSecReturnRef:       @YES,
        (__bridge id)kSecMatchLimit:      (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef itemRef = NULL;
    st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &itemRef);
    if (st != errSecSuccess) { fprintf(stderr, "lookup for SetAccess: %d\n", (int)st); return 1; }

    st = SecKeychainItemSetAccess((SecKeychainItemRef)itemRef, access);
    printf("  SecKeychainItemSetAccess = %d\n", (int)st);
    if (st != errSecSuccess) return 1;
    printf("restrictive ACL installed\n");

    // Read the item's access back to confirm what actually got stored.
    SecAccessRef back = NULL;
    st = SecKeychainItemCopyAccess((SecKeychainItemRef)itemRef, &back);
    printf("  SecKeychainItemCopyAccess = %d\n", (int)st);
    if (st == errSecSuccess && back) {
        CFArrayRef acls2 = NULL;
        if (SecAccessCopyACLList(back, &acls2) == errSecSuccess && acls2) {
            printf("  stored ACL: %ld entries\n", (long)CFArrayGetCount(acls2));
            for (CFIndex i = 0; i < CFArrayGetCount(acls2); i++) {
                SecACLRef a = (SecACLRef)CFArrayGetValueAtIndex(acls2, i);
                CFArrayRef apps = NULL; CFStringRef desc = NULL; SecKeychainPromptSelector ps = 0;
                SecACLCopyContents(a, &apps, &desc, &ps);
                CFArrayRef auths = SecACLCopyAuthorizations(a);
                printf("    [%ld] prompt=0x%04x auths=%s apps=%ld\n", (long)i, (unsigned)ps,
                       auths ? [[(__bridge NSArray *)auths componentsJoinedByString:@","] UTF8String] : "?",
                       apps ? (long)CFArrayGetCount(apps) : -1L);
                if (apps) for (CFIndex j = 0; j < CFArrayGetCount(apps); j++)
                    showTAppRequirement((SecTrustedApplicationRef)CFArrayGetValueAtIndex(apps, j));
                if (apps) CFRelease(apps);
                if (auths) CFRelease(auths);
                if (desc) CFRelease(desc);
            }
            CFRelease(acls2);
        }
        CFRelease(back);
    }
    return 0;
}

// ---- evaluate a requirement string against a binary's signature ----
// usage: checkreq '<requirement>' <path-to-binary>
static int cmdCheckReq(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: checkreq <requirement> <path>\n"); return 2; }
    SecRequirementRef req = NULL;
    OSStatus st = SecRequirementCreateWithString((__bridge CFStringRef)[NSString stringWithUTF8String:argv[1]],
                                                 kSecCSDefaultFlags, &req);
    if (st != errSecSuccess) { fprintf(stderr, "bad requirement: %d\n", (int)st); return 1; }
    SecStaticCodeRef code = NULL;
    st = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:[NSString stringWithUTF8String:argv[2]]],
                                     kSecCSDefaultFlags, &code);
    if (st != errSecSuccess) { fprintf(stderr, "SecStaticCodeCreateWithPath: %d\n", (int)st); return 1; }
    st = SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, req);
    printf("SecStaticCodeCheckValidity(%s) = %d %s\n", argv[1], (int)st,
           st == errSecSuccess ? "(MATCH)" : "(NO MATCH)");
    return st == errSecSuccess ? 0 : 1;
}

// ---- print a binary's designated requirement ----
static int cmdShowDR(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: showdr <path>\n"); return 2; }
    SecStaticCodeRef code = NULL;
    if (SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:
            [NSString stringWithUTF8String:argv[1]]], kSecCSDefaultFlags, &code) != errSecSuccess) return 1;
    SecRequirementRef dr = NULL;
    OSStatus st = SecCodeCopyDesignatedRequirement(code, kSecCSDefaultFlags, &dr);
    if (st != errSecSuccess) { printf("SecCodeCopyDesignatedRequirement: %d\n", (int)st); return 1; }
    CFStringRef s = NULL;
    SecRequirementCopyString(dr, kSecCSDefaultFlags, &s);
    printf("%s\n", s ? [(__bridge NSString *)s UTF8String] : "(null)");
    return 0;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2) { fprintf(stderr, "subcommands: dumptapp <path> | mkkey | dumpacl | checkreq | showdr\n"); return 2; }
        NSString *cmd = [NSString stringWithUTF8String:argv[1]];
        if ([cmd isEqualToString:@"dumptapp"]) { cmdDumpTApp(argc > 2 ? argv[2] : NULL); return 0; }
        if ([cmd isEqualToString:@"tappreq"])  return cmdTAppReq(argc - 1, argv + 1);
        if ([cmd isEqualToString:@"mkkeyreq"]) return cmdMkKeyReq(argc - 1, argv + 1);
        if ([cmd isEqualToString:@"mkkeycssm"]) return cmdMkKeyCssm(argc - 1, argv + 1);
        if ([cmd isEqualToString:@"mkkey"])    return cmdMkKey(argc - 1, argv + 1);
        if ([cmd isEqualToString:@"dumpacl"])  return cmdDumpACL(argc - 1, argv + 1);
        if ([cmd isEqualToString:@"checkreq"]) return cmdCheckReq(argc - 1, argv + 1);
        if ([cmd isEqualToString:@"showdr"])   return cmdShowDR(argc - 1, argv + 1);
        fprintf(stderr, "unknown subcommand %s\n", argv[1]);
        return 2;
    }
}
