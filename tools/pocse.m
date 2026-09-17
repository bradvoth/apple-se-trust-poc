// pocse.m - Secure Enclave experiments for the signing-key POC.
//
// Questions this answers:
//   1. Can a plain, unsigned CLI create and use a Secure Enclave key?
//   2. Can an SE key's access be restricted by code requirement (like a file
//      keychain ACL), or only by user presence?
//   3. Who can use an SE key that has no user-presence gate?
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdio.h>
#include <string.h>

// SPI, exported but not in the SDK headers.
extern CFDictionaryRef SecAccessControlGetConstraints(SecAccessControlRef ac);
extern bool SecAccessControlIsBound(SecAccessControlRef ac);

static void showErr(const char *what, CFErrorRef err) {
    if (err) printf("    %s error %ld: %s\n", what, (long)CFErrorGetCode(err),
                    [[(__bridge NSError *)err localizedDescription] UTF8String]);
}

static SecAccessControlRef makeAC(const char *gate, CFErrorRef *err) {
    SecAccessControlCreateFlags f = 0;
    if (!strcmp(gate, "none"))      f = 0;
    else if (!strcmp(gate, "presence")) f = kSecAccessControlUserPresence;
    else if (!strcmp(gate, "biometry")) f = kSecAccessControlBiometryAny;
    else if (!strcmp(gate, "passcode")) f = kSecAccessControlDevicePasscode;
    else if (!strcmp(gate, "apppw"))    f = kSecAccessControlApplicationPassword;
    else if (!strcmp(gate, "privateusage")) f = kSecAccessControlPrivateKeyUsage;
    else return NULL;

    // An access control always needs a protection class.
    return SecAccessControlCreateWithFlags(kCFAllocatorDefault,
               kSecAttrAccessibleWhenUnlockedThisDeviceOnly, f, err);
}

// Try to create an SE private key with the given gate and protection approach.
// extraAccess: if non-NULL, a SecAccessRef carrying a code requirement, to test
// whether the Secure Enclave honours code-identity restrictions at all.
static OSStatus createSE(const char *label, const char *gate, SecAccessRef extraAccess,
                         CFErrorRef *outErr, SecKeyRef *outKey) {
    // Leading markers select variants, for probing alternative routes.
    bool ephemeral = false, legacyKC = false, unsetKC = false;
    if (!strncmp(gate, "eph:", 4))    { ephemeral = true; gate += 4; }
    if (!strncmp(gate, "legacy:", 7)) { legacyKC = true; gate += 7; }
    if (!strncmp(gate, "unset:", 6))  { unsetKC = true; gate += 6; }
    if (!strncmp(gate, "ephlegacy:", 10)) { ephemeral = true; legacyKC = true; gate += 10; }
    if (!strncmp(gate, "ephunset:", 9))  { ephemeral = true; unsetKC = true; gate += 9; }

    CFErrorRef err = NULL;
    SecAccessControlRef ac = makeAC(gate, &err);
    if (!ac) { if (outErr) *outErr = err; return errSecParam; }
    printf("  access control created for gate '%s'%s%s\n", gate,
           ephemeral ? " [ephemeral]" : "", legacyKC ? " [legacy keychain]" : "");

    CFDictionaryRef cons = SecAccessControlGetConstraints(ac);
    printf("  constraints: %s\n", cons ? [[(__bridge NSDictionary *)cons description] UTF8String] : "(none)");
    printf("  SecAccessControlIsBound: %s\n", SecAccessControlIsBound(ac) ? "true" : "false");

    NSMutableDictionary *params = [@{
        (__bridge id)kSecAttrKeyType:       (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits: @256,
        (__bridge id)kSecAttrLabel:         [NSString stringWithUTF8String:label],
        (__bridge id)kSecAttrTokenID:       (__bridge id)kSecAttrTokenIDSecureEnclave,
        (__bridge id)kSecAttrAccessControl: (__bridge id)ac,
        (__bridge id)kSecAttrIsPermanent:   ephemeral ? @NO : @YES,
        (__bridge id)kSecPrivateKeyAttrs: @{
            (__bridge id)kSecAttrIsPermanent:   ephemeral ? @NO : @YES,
            (__bridge id)kSecAttrAccessControl: (__bridge id)ac,
        },
    } mutableCopy];
    // Only pin the keychain when the test asks us to; leaving it unset is what a
    // naive caller does, and the default is what we want to characterise.
    if (!unsetKC)
        params[(__bridge id)kSecUseDataProtectionKeychain] = legacyKC ? @NO : @YES;
    if (extraAccess) {
        params[(__bridge id)kSecAttrAccess] = (__bridge id)extraAccess;
        printf("  also passing a SecAccessRef with a code requirement\n");
    }

    CFErrorRef genErr = NULL;
    SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)params, &genErr);
    if (!key) { if (outErr) *outErr = genErr; return errSecInternalError; }

    CFDictionaryRef attrs = SecKeyCopyAttributes(key);
    printf("  created. attributes:\n");
    [(__bridge NSDictionary *)attrs enumerateKeysAndObjectsUsingBlock:
        ^(id k, id v, BOOL *stop) { printf("    %-28s %s\n", [[k description] UTF8String],
                                           [[v description] UTF8String]); }];

    // The decisive check: is this really a Secure Enclave key, or did the API
    // silently fall back to software? SE private keys cannot be exported.
    CFDataRef tokenID = CFDictionaryGetValue(attrs, kSecAttrTokenID);
    printf("  kSecAttrTokenID: %s\n",
           tokenID ? [[(__bridge id)tokenID description] UTF8String] : "(absent)");
    CFErrorRef extErr = NULL;
    CFDataRef raw = SecKeyCopyExternalRepresentation(key, &extErr);
    printf("  SecKeyCopyExternalRepresentation: %s",
           raw ? "SUCCEEDED -> this is a SOFTWARE key, not Secure Enclave"
               : "refused -> key material is not extractable");
    if (!raw && extErr) printf(" (%ld)", (long)CFErrorGetCode(extErr));
    printf("\n  VERDICT: %s\n", raw ? "SOFTWARE KEY (SE not used)"
                                     : (tokenID ? "SECURE ENCLAVE" : "NOT EXPORTABLE, but no SE token id"));
    if (raw) CFRelease(raw);
    if (outKey) *outKey = (SecKeyRef)CFRetain(key);   // ephemeral keys are not findable by lookup
    CFRelease(key);
    return errSecSuccess;
}

// Look up an SE key and try to sign with it.
static int useSE(const char *label, bool quiet) {
    NSDictionary *q = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrLabel:   [NSString stringWithUTF8String:label],
        (__bridge id)kSecUseDataProtectionKeychain: @YES,
        (__bridge id)kSecReturnRef:   @YES,
        (__bridge id)kSecMatchLimit:  (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (st != errSecSuccess) {
        if (!quiet) printf("  lookup: %d -> KEY NOT VISIBLE\n", (int)st);
        return 1;
    }
    SecKeyRef key = (SecKeyRef)out;
    CFErrorRef err = NULL;
    CFDataRef sig = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        (__bridge CFDataRef)[@"se-test" dataUsingEncoding:NSUTF8StringEncoding], &err);
    if (!sig) {
        printf("  lookup: ok, but SIGNING FAILED");
        if (err) printf(" -> error %ld: %s", (long)CFErrorGetCode(err),
                        [[(__bridge NSError *)err localizedDescription] UTF8String]);
        printf("\n  RESULT: PRESENT BUT UNUSABLE (gate not satisfied)\n");
        return 2;
    }
    printf("  signature: ok, %ld bytes\n", (long)CFDataGetLength(sig));
    printf("  RESULT: USED THE KEY\n");
    return 0;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2) { fprintf(stderr, "usage: pocse <mk|use|probe|mkreq|export> ...\n"); return 2; }
        NSString *c = [NSString stringWithUTF8String:argv[1]];

        if ([c isEqualToString:@"mkuse"]) {         // mkuse <label> <gate> - create then immediately use
            if (argc < 4) { fprintf(stderr, "mkuse <label> <gate>\n"); return 2; }
            CFErrorRef err = NULL;
            // Ephemeral, so it exists only for this process and can be used here.
            char buf[64]; snprintf(buf, sizeof buf, "eph:%s", argv[3]);
            SecKeyRef key = NULL;
            OSStatus st = createSE(argv[2], buf, NULL, &err, &key);
            if (st != errSecSuccess || !key) { printf("create failed: %d\n", (int)st); return 1; }
            printf("  now attempting to SIGN with it...\n");
            fflush(stdout);
            CFErrorRef serr = NULL;
            CFDataRef sig = SecKeyCreateSignature(key,
                kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                (__bridge CFDataRef)[@"gate-test" dataUsingEncoding:NSUTF8StringEncoding], &serr);
            if (!sig) {
                printf("  SIGN FAILED: error %ld %s\n", serr ? (long)CFErrorGetCode(serr) : -1L,
                       serr ? [[(__bridge NSError *)serr localizedDescription] UTF8String] : "");
                return 2;
            }
            printf("  SIGN OK, %ld bytes -> no user interaction required\n", (long)CFDataGetLength(sig));
            return 0;
        }
        if ([c isEqualToString:@"mk"]) {           // mk <label> <gate>
            if (argc < 4) { fprintf(stderr, "mk <label> <gate>\n"); return 2; }
            printf("creating SE key '%s' gate=%s\n", argv[2], argv[3]);
            CFErrorRef err = NULL;
            OSStatus st = createSE(argv[2], argv[3], NULL, &err, NULL);
            printf("result: %d\n", (int)st);
            showErr("create", err);
            return st == errSecSuccess ? 0 : 1;
        }
        if ([c isEqualToString:@"use"]) {          // use <label>
            if (argc < 3) { fprintf(stderr, "use <label>\n"); return 2; }
            printf("using SE key '%s'\n", argv[2]);
            return useSE(argv[2], false);
        }
        if ([c isEqualToString:@"export"]) {       // export <label>  - can we get the private key out?
            if (argc < 3) { fprintf(stderr, "export <label>\n"); return 2; }
            NSDictionary *q = @{
                (__bridge id)kSecClass:       (__bridge id)kSecClassKey,
                (__bridge id)kSecAttrLabel:   [NSString stringWithUTF8String:argv[2]],
                (__bridge id)kSecUseDataProtectionKeychain: @YES,
                (__bridge id)kSecReturnData:  @YES,
                (__bridge id)kSecReturnRef:   @YES,
                (__bridge id)kSecMatchLimit:  (__bridge id)kSecMatchLimitOne,
            };
            CFTypeRef out = NULL;
            OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
            printf("fetching raw key data: %d (%s) -> %s\n", (int)st,
                   st == errSecSuccess ? "returned something" : "no raw private key",
                   st == errSecSuccess ? "EXTRACTABLE" : "NOT EXTRACTABLE");
            if (st == errSecSuccess && out) {
                SecKeyRef k = (SecKeyRef)CFRetain(out);
                CFDataRef d = SecKeyCopyExternalRepresentation(k, NULL);
                printf("SecKeyCopyExternalRepresentation: %s\n", d ? "SUCCEEDED" : "refused");
                if (d) CFRelease(d);
                CFRelease(k);
            }
            return 0;
        }
        if ([c isEqualToString:@"mkreq"]) {        // mkreq <label> - SE key + code-requirement SecAccess
            if (argc < 3) { fprintf(stderr, "mkreq <label>\n"); return 2; }
            // Build a SecAccess pinned to our signed client, exactly as the file-keychain
            // POC does, and see whether the Secure Enclave path accepts it at all.
            SecRequirementRef req = NULL;
            SecRequirementCreateWithString(CFSTR("identifier \"com.poc.client\""),
                                           kSecCSDefaultFlags, &req);
            extern OSStatus SecTrustedApplicationCreateFromRequirement(const char *, SecRequirementRef,
                                                                      SecTrustedApplicationRef *);
            SecTrustedApplicationRef app = NULL;
            OSStatus st = SecTrustedApplicationCreateFromRequirement("poc", req, &app);
            printf("TrustedApplicationCreateFromRequirement: %d\n", (int)st);
            SecAccessRef access = NULL;
            st = SecAccessCreate(CFSTR("poc"), (__bridge CFArrayRef)@[ (__bridge id)app ], &access);
            printf("SecAccessCreate: %d\n", (int)st);

            printf("attempting an EPHEMERAL SE key (no entitlement needed) carrying:\n");
            printf("  kSecAttrAccessControl (a protection class)\n");
            printf("  kSecAttrAccess        (a SecAccess with a code requirement)\n");
            CFErrorRef err = NULL;
            OSStatus cs = createSE(argv[2], "eph:none", access, &err, NULL);
            printf("result: %d\n", (int)cs);
            showErr("create", err);
            return cs == errSecSuccess ? 0 : 1;
        }
        fprintf(stderr, "unknown subcommand %s\n", argv[1]);
        return 2;
    }
}
