// pocexport.m - attempt to EXTRACT the private key material, as distinct from using it.
//
// The ACL is a set of operation-specific authorizations (Sign, Decrypt, ExportClear, ...).
// A pin that authorizes only Sign/Decrypt does not by itself prevent ExportClear if some
// other ACL entry on the same item authorizes it. This tool reports each step separately so
// the two questions -- "may I use it?" and "may I take it?" -- are answered independently.
//
// usage: pocexport <keychain-path> <label>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdio.h>

static const char *errstr(OSStatus st) {
    CFStringRef m = SecCopyErrorMessageString(st, NULL);
    static char buf[512];
    snprintf(buf, sizeof buf, "%s",
             m ? [(__bridge NSString *)m UTF8String] : "?");
    if (m) CFRelease(m);
    return buf;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 3) { fprintf(stderr, "usage: %s <keychain> <label>\n", argv[0]); return 2; }

        SecKeychainSetUserInteractionAllowed(false);

        SecKeychainRef kc = NULL;
        OSStatus st = SecKeychainOpen(argv[1], &kc);
        if (st != errSecSuccess) { printf("open: %d %s\n", (int)st, errstr(st)); return 1; }

        NSDictionary *q = @{
            (__bridge id)kSecClass:           (__bridge id)kSecClassKey,
            (__bridge id)kSecAttrKeyClass:    (__bridge id)kSecAttrKeyClassPrivate,
            (__bridge id)kSecAttrLabel:       [NSString stringWithUTF8String:argv[2]],
            (__bridge id)kSecMatchSearchList: @[ (__bridge id)kc ],
            (__bridge id)kSecReturnRef:       @YES,
            (__bridge id)kSecMatchLimit:      (__bridge id)kSecMatchLimitOne,
        };
        CFTypeRef out = NULL;
        st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
        printf("  1. lookup key ref            : %d %s\n", (int)st, errstr(st));
        if (st != errSecSuccess) return 1;
        SecKeyRef key = (SecKeyRef)out;

        // Question 1: may this process USE the key?
        CFErrorRef useErr = NULL;
        CFDataRef sig = SecKeyCreateSignature(key, kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
            (__bridge CFDataRef)[@"x" dataUsingEncoding:NSUTF8StringEncoding], &useErr);
        printf("  2. use it (sign)             : %s\n",
               sig ? "PERMITTED" : [[NSString stringWithFormat:@"DENIED (%ld)",
                                     useErr ? (long)CFErrorGetCode(useErr) : -1L] UTF8String]);
        if (sig) CFRelease(sig);

        // Question 2: may this process TAKE the key material?
        CFErrorRef exErr = NULL;
        CFDataRef raw = SecKeyCopyExternalRepresentation(key, &exErr);
        printf("  3. take it (copy raw key)    : %s\n",
               raw ? "PERMITTED *** private key material extracted ***"
                   : [[NSString stringWithFormat:@"DENIED (%ld)",
                       exErr ? (long)CFErrorGetCode(exErr) : -1L] UTF8String]);
        if (raw) {
            printf("     extracted %ld bytes\n", (long)CFDataGetLength(raw));
            CFRelease(raw);
        }

        // Question 3: is there an ACL entry that authorizes export at all?
        SecAccessRef access = NULL;
        if (SecKeychainItemCopyAccess((SecKeychainItemRef)key, &access) == errSecSuccess) {
            CFArrayRef acls = NULL;
            if (SecAccessCopyACLList(access, &acls) == errSecSuccess && acls) {
                printf("  4. ACL entries on this item  : %ld\n", (long)CFArrayGetCount(acls));
                for (CFIndex i = 0; i < CFArrayGetCount(acls); i++) {
                    CFArrayRef auths = SecACLCopyAuthorizations(
                        (SecACLRef)CFArrayGetValueAtIndex(acls, i));
                    printf("       [%ld] %s\n", (long)i,
                           auths ? [[(__bridge NSArray *)auths
                                     componentsJoinedByString:@","] UTF8String] : "?");
                    int exportAuth = 0;
                    if (auths) for (CFIndex j = 0; j < CFArrayGetCount(auths); j++) {
                        NSString *a = (__bridge NSString *)CFArrayGetValueAtIndex(auths, j);
                        if ([a containsString:@"Export"]) exportAuth = 1;
                    }
                    if (exportAuth) printf("           ^^ AUTHORIZES EXPORT\n");
                    if (auths) CFRelease(auths);
                }
                CFRelease(acls);
            }
            CFRelease(access);
        }
        return 0;
    }
}
