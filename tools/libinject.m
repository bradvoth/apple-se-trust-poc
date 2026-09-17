// libinject.m - "attacker" payload. Unsigned, not from our CA. It runs inside the
// address space of whatever process loads it and tries to use the pinned key.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdio.h>

__attribute__((constructor))
static void injected(void) {
    @autoreleasepool {
        const char *kcPath = getenv("POC_KC");
        const char *label  = getenv("POC_LABEL");
        if (!kcPath || !label) return;

        fprintf(stderr, "[inject] running inside %s (uid %d)\n", getprogname(), getuid());
        fprintf(stderr, "[inject] this dylib is unsigned and not from our CA\n");

        SecKeychainRef kc = NULL;
        if (SecKeychainOpen(kcPath, &kc) != errSecSuccess) { fprintf(stderr, "[inject] open failed\n"); return; }

        NSDictionary *q = @{
            (__bridge id)kSecClass:           (__bridge id)kSecClassKey,
            (__bridge id)kSecAttrKeyClass:    (__bridge id)kSecAttrKeyClassPrivate,
            (__bridge id)kSecAttrLabel:       [NSString stringWithUTF8String:label],
            (__bridge id)kSecMatchSearchList: @[ (__bridge id)kc ],
            (__bridge id)kSecReturnRef:       @YES,
            (__bridge id)kSecMatchLimit:      (__bridge id)kSecMatchLimitOne,
        };
        CFTypeRef out = NULL;
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
        if (st != errSecSuccess) { fprintf(stderr, "[inject] lookup: %d -> NO KEY\n", (int)st); return; }

        CFErrorRef err = NULL;
        CFDataRef sig = SecKeyCreateSignature((SecKeyRef)out,
            kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
            (__bridge CFDataRef)[@"injected" dataUsingEncoding:NSUTF8StringEncoding], &err);
        if (!sig) {
            fprintf(stderr, "[inject] signature: %ld -> DENIED\n", err ? (long)CFErrorGetCode(err) : -1L);
            return;
        }
        fprintf(stderr, "[inject] SIGNED %ld bytes -> INJECTED CODE GOT THE KEY\n", (long)CFDataGetLength(sig));
    }
}
