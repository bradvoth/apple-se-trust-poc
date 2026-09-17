// rmkeys.m - delete keychain keys by label. `security` has no delete-key command,
// so this exists to clean up keys created by the Secure Enclave probes.
// usage: rmkeys <label> [label ...]
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdio.h>

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc < 2) { fprintf(stderr, "usage: rmkeys <label> [label ...]\n"); return 2; }
        int deleted = 0;
        for (int i = 1; i < argc; i++) {
            NSString *label = [NSString stringWithUTF8String:argv[i]];
            // No kSecUseDataProtectionKeychain: these probes wrote legacy file-keychain
            // items, so search the legacy keychains in the default search list.
            NSDictionary *q = @{
                (__bridge id)kSecClass:      (__bridge id)kSecClassKey,
                (__bridge id)kSecAttrLabel:  label,
                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
            };
            OSStatus st = SecItemDelete((__bridge CFDictionaryRef)q);
            if (st == errSecSuccess)      { printf("  deleted  %s\n", argv[i]); deleted++; }
            else if (st == errSecItemNotFound) { printf("  absent   %s\n", argv[i]); }
            else                          { printf("  FAILED   %s (%d)\n", argv[i], (int)st); }
        }
        printf("%d deleted\n", deleted);
        return 0;
    }
}
