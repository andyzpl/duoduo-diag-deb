#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <dlfcn.h>

static NSString * const DDLogPath = @"/var/mobile/Documents/duoduo_diag.log";
static NSDateFormatter *DDFormatter(void) {
    static NSDateFormatter *f;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        f = [[NSDateFormatter alloc] init];
        f.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    });
    return f;
}

static void DDAppend(NSString *line) {
    NSString *stamped = [NSString stringWithFormat:@"[%@] %@\n", [DDFormatter() stringFromDate:[NSDate date]], line];
    NSData *data = [stamped dataUsingEncoding:NSUTF8StringEncoding];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:DDLogPath]) {
        [fm createFileAtPath:DDLogPath contents:data attributes:@{NSFileProtectionKey: NSFileProtectionNone}];
    } else {
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:DDLogPath];
        if (fh) {
            [fh seekToEndOfFile];
            [fh writeData:data];
            [fh closeFile];
        }
    }
    NSLog(@"[DuoduoDiag] %@", line);
}

static NSString *DDDictDescription(id obj) {
    if (!obj) return @"(nil)";
    NSString *s = [obj description];
    return s.length > 4000 ? [[s substringToIndex:4000] stringByAppendingString:@"...(truncated)"] : s;
}

static void DDumpEnvironment(void) {
    DDAppend(@"===== DUODUO DIAGNOSTIC SNAPSHOT =====");
    NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
    DDAppend([NSString stringWithFormat:@"BUNDLE_ID=%@", info[@"CFBundleIdentifier"] ?: @"?"]);
    DDAppend([NSString stringWithFormat:@"VERSION=%@ BUILD=%@", info[@"CFBundleShortVersionString"] ?: @"?", info[@"CFBundleVersion"] ?: @"?"]);
    DDAppend([NSString stringWithFormat:@"EXECUTABLE=%@", info[@"CFBundleExecutable"] ?: @"?"]);
    NSArray *volKeys = @[@"volantis.buildMode", @"volantis.subtype", @"volantis.internalNo", @"volantis.v_commitId"];
    for (NSString *k in volKeys) {
        DDAppend([NSString stringWithFormat:@"INFO[%@]=%@", k, info[k] ?: @"(absent)"]);
    }
    DDAppend([NSString stringWithFormat:@"URL_SCHEMES=%@", DDDictDescription(info[@"CFBundleURLTypes"])]);
    DDAppend([NSString stringWithFormat:@"QUERY_SCHEMES=%@", DDDictDescription(info[@"LSApplicationQueriesSchemes"])]);

    /* iOS SDK does not expose SecCode API in headers; resolve at runtime via dlsym */
    typedef int (*SecCodeCopySelf_t)(unsigned int, void **);
    typedef int (*SecCodeCopySigningInformation_t)(void *, unsigned int, CFDictionaryRef *);
    SecCodeCopySelf_t pCopySelf = (SecCodeCopySelf_t)dlsym(RTLD_DEFAULT, "SecCodeCopySelf");
    SecCodeCopySigningInformation_t pCopyInfo = (SecCodeCopySigningInformation_t)dlsym(RTLD_DEFAULT, "SecCodeCopySigningInformation");
    if (pCopySelf && pCopyInfo) {
        void *code = NULL;
        if (pCopySelf(0, &code) == 0 && code) {
            CFDictionaryRef ent = NULL;
            /* kSecCSSigningInformationTypeEntitlements = 6 */
            if (pCopyInfo(code, 6, &ent) == 0 && ent) {
                DDAppend([NSString stringWithFormat:@"ENTITLEMENTS=%@", DDDictDescription((__bridge id)ent)]);
                CFRelease(ent);
            } else {
                DDAppend(@"ENTITLEMENTS=(read failed)");
            }
            CFDictionaryRef sig = NULL;
            /* kSecCSSigningInformationTypeName = 10 */
            if (pCopyInfo(code, 10, &sig) == 0 && sig) {
                DDAppend([NSString stringWithFormat:@"SIGNING_NAME=%@", DDDictDescription((__bridge id)sig)]);
                CFRelease(sig);
            }
        }
    } else {
        DDAppend(@"SecCode API unavailable at runtime (dlsym failed)");
    }

    int jailbreak = 0;
    const char *paths[] = {"/Applications/Cydia.app", "/private/var/lib/apt", "/var/jb", "/Library/MobileSubstrate/MobileSubstrate.dylib"};
    for (int i = 0; i < 4; i++) {
        if (access(paths[i], F_OK) == 0) { jailbreak = 1; DDAppend([NSString stringWithFormat:@"JB_MARKER_FOUND=%s", paths[i]]); }
    }
    DDAppend([NSString stringWithFormat:@"JB_LIKELY=%d", jailbreak]);

    NSString *frida = [NSString stringWithFormat:@"/proc/%d/maps", getpid()];
    if ([[NSFileManager defaultManager] fileExistsAtPath:frida]) {
        NSString *maps = [NSString stringWithContentsOfFile:frida encoding:NSUTF8StringEncoding error:nil];
        BOOL hasFrida = [maps rangeOfString:@"frida-agent" options:NSCaseInsensitiveSearch].location != NSNotFound;
        DDAppend([NSString stringWithFormat:@"FRIDA_AGENT_IN_MAPS=%d", hasFrida]);
    }
    DDAppend(@"===== END SNAPSHOT =====\n");
}

%hook UIApplication
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    DDAppend(@"HOOK: UIApplication didFinishLaunchingWithOptions");
    DDumpEnvironment();
    return %orig;
}
%end

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    NSMutableArray *parts = [NSMutableArray array];
    for (u_int i = 0; i < namelen && i < 8; i++) [parts addObject:@(name[i]).stringValue];
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    DDAppend([NSString stringWithFormat:@"CALL sysctl name=[%@] ret=%d", [parts componentsJoinedByString:@","], ret]);
    return ret;
}

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    DDAppend([NSString stringWithFormat:@"CALL sysctlbyname name=%s ret=%d", name ?: "(null)", ret]);
    return ret;
}

%ctor {
    DDAppend(@"===== TWEAK LOADED =====");
    DDAppend([NSString stringWithFormat:@"PID=%d PROC=%@", getpid(), [[NSProcessInfo processInfo] processName]]);
    MSHookFunction((void *)sysctl, (void *)my_sysctl, (void **)&orig_sysctl);
    MSHookFunction((void *)sysctlbyname, (void *)my_sysctlbyname, (void **)&orig_sysctlbyname);
    DDAppend(@"HOOKED: sysctl, sysctlbyname");
    DDumpEnvironment();
}
