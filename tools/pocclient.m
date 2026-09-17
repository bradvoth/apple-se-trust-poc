// pocclient.m - a dummy "signer daemon" that tries to use a private key from a keychain.
// Its own code signature is what the keychain ACL is evaluated against.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdio.h>

static void report(const char *what, OSStatus st) {
    CFStringRef msg = SecCopyErrorMessageString(st, NULL);
    printf("  %-22s -> %d (%s)\n", what, (int)st, msg ? [(__bridge NSString *)msg UTF8String] : "?");
    if (msg) CFRelease(msg);
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 3) { fprintf(stderr, "usage: %s <keychain-path> <key-label>\n", argv[0]); return 2; }
        OSStatus st;

        // Suppress every keychain dialog so the result is a plain allow/deny.
        // Set POC_ALLOW_UI=1 to let the SecurityAgent prompts appear instead.
        if (!getenv("POC_ALLOW_UI")) {
            OSStatus uiSt = SecKeychainSetUserInteractionAllowed(false);
            printf("  user interaction disabled: %d\n", (int)uiSt);
        }

        SecKeychainRef kc = NULL;
        st = SecKeychainOpen(argv[1], &kc);
        if (st != errSecSuccess) { report("SecKeychainOpen", st); return 1; }

        NSDictionary *q = @{
            (__bridge id)kSecClass:             (__bridge id)kSecClassKey,
            (__bridge id)kSecAttrKeyClass:      (__bridge id)kSecAttrKeyClassPrivate,
            (__bridge id)kSecAttrLabel:         [NSString stringWithUTF8String:argv[2]],
            (__bridge id)kSecMatchSearchList:   @[ (__bridge id)kc ],
            (__bridge id)kSecMatchLimit:        (__bridge id)kSecMatchLimitOne,
            (__bridge id)kSecReturnRef:         @YES,
        };
        CFTypeRef out = NULL;
        st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
        report("SecItemCopyMatching", st);
        if (st != errSecSuccess) { printf("RESULT: DENIED_LOOKUP\n"); return 1; }

        SecKeyRef key = (SecKeyRef)out;
        NSData *payload = [@"poc-payload" dataUsingEncoding:NSUTF8StringEncoding];
        CFErrorRef err = NULL;
        CFDataRef sig = SecKeyCreateSignature(key, kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
                                              (__bridge CFDataRef)payload, &err);
        if (!sig) {
            NSInteger code = err ? CFErrorGetCode(err) : 0;
            printf("  %-22s -> %ld (%s)\n", "SecKeyCreateSignature", (long)code,
                   err ? [[(__bridge NSError *)err localizedDescription] UTF8String] : "?");
            printf("RESULT: DENIED_USE\n");
            return 1;
        }
        printf("  SecKeyCreateSignature   -> OK, %ld byte signature\n", (long)CFDataGetLength(sig));
        printf("RESULT: GRANTED\n");
        return 0;
    }
}
