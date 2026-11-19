#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <unistd.h>
#import <stdlib.h>
#import <mach/mach.h>
#import <dlfcn.h>

/* dyld image enumeration (declared manually to avoid SDK header drift) */
extern uint32_t _dyld_image_count(void);
extern const char *_dyld_get_image_name(uint32_t index);
extern const void *_dyld_get_image_header(uint32_t index);

/* minimal Mach-O 64 structs */
#define DD_MH_MAGIC_64      0xfeedfacf
#define DD_LC_ENCRYPT_64    0x2c
struct dd_load_command { uint32_t cmd; uint32_t cmdsize; };
struct dd_crypt_cmd { uint32_t cmd; uint32_t cmdsize; uint32_t cryptoff; uint32_t cryptsize; uint32_t cryptid; uint32_t pad; };
struct dd_mach_header_64 {
    uint32_t magic; int cputype; int cpusubtype; uint32_t filetype;
    uint32_t ncmds; uint32_t sizeofcmds; uint32_t flags; uint32_t reserved;
};

static NSString * const DDLogPath      = @"/var/mobile/Documents/duoduo_diag.log";
static NSString * const DDVerifyPath   = @"/var/mobile/Documents/duoduo_official_check.txt";
static BOOL DDInSelfCheck = NO;

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

static void DDWriteReport(NSString *report) {
    NSData *data = [report dataUsingEncoding:NSUTF8StringEncoding];
    [data writeToFile:DDVerifyPath atomically:YES];
    [[NSFileManager defaultManager] setAttributes:@{NSFileProtectionKey: NSFileProtectionNone}
                                     ofItemAtPath:DDVerifyPath error:nil];
}

static NSString *DDDictDescription(id obj) {
    if (!obj) return @"(nil)";
    NSString *s = [obj description];
    return s.length > 4000 ? [[s substringToIndex:4000] stringByAppendingString:@"...(truncated)"] : s;
}

/* ---------- detection primitives ---------- */

static int DDCryptidOfMainImage(void) {
    const struct dd_mach_header_64 *mh = (const struct dd_mach_header_64 *)_dyld_get_image_header(0);
    if (!mh || mh->magic != DD_MH_MAGIC_64) return -1;
    uintptr_t p = (uintptr_t)mh + sizeof(struct dd_mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct dd_load_command *lc = (const struct dd_load_command *)p;
        if (lc->cmd == DD_LC_ENCRYPT_64) {
            const struct dd_crypt_cmd *ec = (const struct dd_crypt_cmd *)p;
            return ec->cryptid;
        }
        p += lc->cmdsize;
    }
    return -2; /* no LC_ENCRYPTION_INFO_64 at all */
}

static NSDictionary *DDCodeSigningInfo(void) {
    typedef int (*SecCodeCopySelf_t)(unsigned int, void **);
    typedef int (*SecCodeCopySigningInformation_t)(void *, unsigned int, CFDictionaryRef *);
    SecCodeCopySelf_t selfFn = (SecCodeCopySelf_t)dlsym(RTLD_DEFAULT, "SecCodeCopySelf");
    SecCodeCopySigningInformation_t infoFn = (SecCodeCopySigningInformation_t)dlsym(RTLD_DEFAULT, "SecCodeCopySigningInformation");
    if (!selfFn || !infoFn) return nil;
    void *code = NULL;
    if (selfFn(0, &code) != 0 || !code) return nil;
    CFDictionaryRef info = NULL;
    int rc = infoFn(code, 0, &info);
    if (rc != 0 || !info) { if (code) CFRelease(code); return nil; }
    NSDictionary *d = [(__bridge NSDictionary *)info copy];
    CFRelease(info);
    CFRelease(code);
    return d;
}

static int DDSignatureValidity(void) {
    typedef int (*SecCodeCopySelf_t)(unsigned int, void **);
    typedef int (*SecCodeCheckValidity_t)(void *, unsigned int, void *);
    SecCodeCopySelf_t selfFn = (SecCodeCopySelf_t)dlsym(RTLD_DEFAULT, "SecCodeCopySelf");
    SecCodeCheckValidity_t chkFn = (SecCodeCheckValidity_t)dlsym(RTLD_DEFAULT, "SecCodeCheckValidity");
    if (!selfFn || !chkFn) return -99;
    void *code = NULL;
    if (selfFn(0, &code) != 0 || !code) return -98;
    int rc = chkFn(code, 0, NULL);
    CFRelease(code);
    return rc; /* 0 = signature valid */
}

static NSArray *DDInjectedImages(void) {
    NSMutableArray *res = [NSMutableArray array];
    NSString *bundle = [[NSBundle mainBundle] bundlePath] ?: @"";
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *c = _dyld_get_image_name(i);
        if (!c) continue;
        NSString *s = [NSString stringWithUTF8String:c];
        if ([s hasPrefix:@"/usr/lib/"] || [s hasPrefix:@"/usr/"] ||
            [s hasPrefix:@"/System/"] || [s hasPrefix:@"/private/preboot/"]) continue;
        if (bundle.length && [s hasPrefix:bundle]) continue; /* own bundled frameworks */
        [res addObject:s];
    }
    return res;
}

static NSArray *DDJailbreakMarkers(void) {
    NSMutableArray *res = [NSMutableArray array];
    const char *paths[] = {
        "/var/jb", "/Applications/Cydia.app", "/private/var/lib/apt",
        "/Library/MobileSubstrate/MobileSubstrate.dylib", "/usr/lib/TweakLoader.dylib",
        "/var/lib/dpkg/status", "/private/var/lib/dpkg/status", "/bin/bash"
    };
    for (int i = 0; i < (int)(sizeof(paths)/sizeof(paths[0])); i++) {
        if (access(paths[i], F_OK) == 0) [res addObject:[NSString stringWithUTF8String:paths[i]]];
    }
    return res;
}

static void DDumpOfficialCheck(void) {
    DDInSelfCheck = YES;
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"===== OFFICIAL APP CHECK =====\n"];

    NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
    [r appendFormat:@"BUNDLE_ID=%@\n", info[@"CFBundleIdentifier"] ?: @"(null)"];
    [r appendFormat:@"VERSION=%@ BUILD=%@\n", info[@"CFBundleShortVersionString"] ?: @"?", info[@"CFBundleVersion"] ?: @"?"];
    [r appendFormat:@"EXECUTABLE_PATH=%@\n", [[NSBundle mainBundle] executablePath] ?: @"?"];

    int cryptid = DDCryptidOfMainImage();
    NSString *cryptDesc = cryptid == 1 ? @"encrypted (official App Store)"
                        : cryptid == 0 ? @"DECRYPTED -> not official"
                        : (cryptid == -2 ? @"no encryption command" : @"unknown");
    [r appendFormat:@"CRYPTID=%d (%@)\n", cryptid, cryptDesc];

    int sig = DDSignatureValidity();
    NSString *sigDesc = sig == 0 ? @"valid" : ((sig == -99 || sig == -98) ? @"API unavailable" : @"INVALID -> not official");
    [r appendFormat:@"SIGNATURE_VALIDITY=%d (%@)\n", sig, sigDesc];

    NSDictionary *sinfo = DDCodeSigningInfo();
    [r appendFormat:@"SIGNING_TEAM=%@\n", sinfo[@"teamid"] ?: @"(null)"];
    [r appendFormat:@"SIGNING_IDENTIFIER=%@\n", sinfo[@"identifier"] ?: @"(null)"];
    [r appendFormat:@"ENTITLEMENTS=%@\n", DDDictDescription(sinfo[@"entitlements"])];

    NSArray *injected = DDInjectedImages();
    [r appendFormat:@"INJECTED_DYLIBS_COUNT=%lu\n", (unsigned long)injected.count];
    for (NSString *s in injected) [r appendFormat:@"  INJECTED=%@\n", s];

    NSArray *jb = DDJailbreakMarkers();
    [r appendFormat:@"JB_MARKERS_COUNT=%lu\n", (unsigned long)jb.count];
    for (NSString *s in jb) [r appendFormat:@"  JB=%@\n", s];

    const char *ins = getenv("DYLD_INSERT_LIBRARIES");
    [r appendFormat:@"DYLD_INSERT_LIBRARIES=%s\n", ins ? ins : "(null)"];

    NSMutableArray *reasons = [NSMutableArray array];
    if (cryptid == 0) [reasons addObject:@"main binary decrypted (cryptid=0)"];
    if (cryptid == -2) [reasons addObject:@"no encryption load command"];
    if (sig > 0) [reasons addObject:[NSString stringWithFormat:@"code signature invalid (ret=%d)", sig]];
    if (injected.count) [reasons addObject:[NSString stringWithFormat:@"%lu non-system dylib(s) loaded", (unsigned long)injected.count]];
    if (jb.count) [reasons addObject:[NSString stringWithFormat:@"%lu jailbreak marker(s)", (unsigned long)jb.count]];
    if (ins && *ins) [reasons addObject:@"DYLD_INSERT_LIBRARIES set"];

    [r appendFormat:@"VERDICT=%@\n", reasons.count ? @"NOT_OFFICIAL" : @"OFFICIAL"];
    [r appendFormat:@"REASON_COUNT=%lu\n", (unsigned long)reasons.count];
    for (NSString *s in reasons) [r appendFormat:@"  REASON=%@\n", s];
    [r appendString:@"===== END OFFICIAL APP CHECK =====\n"];

    DDWriteReport(r);
    DDInSelfCheck = NO;
    DDAppend([NSString stringWithFormat:@"OFFICIAL CHECK => %@ (reasons=%lu) -> %@",
              reasons.count ? @"NOT_OFFICIAL" : @"OFFICIAL", (unsigned long)reasons.count, DDVerifyPath]);
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
    NSDictionary *sinfo = DDCodeSigningInfo();
    if (sinfo) {
        DDAppend([NSString stringWithFormat:@"ENTITLEMENTS=%@", DDDictDescription(sinfo[@"entitlements"])]);
        DDAppend([NSString stringWithFormat:@"SIGNING_NAME=%@", DDDictDescription(sinfo[@"identifier"])]);
        DDAppend([NSString stringWithFormat:@"SIGNING_TEAM=%@", sinfo[@"teamid"] ?: @"(null)"]);
    } else {
        DDAppend(@"SecCode API unavailable at runtime (dlsym failed)");
    }
    DDAppend([NSString stringWithFormat:@"SIGNATURE_VALIDITY=%d", DDSignatureValidity()]);

    DDAppend([NSString stringWithFormat:@"NATIVE_CRYPTID=%d", DDCryptidOfMainImage()]);
    NSArray *injected = DDInjectedImages();
    DDAppend([NSString stringWithFormat:@"INJECTED_DYLIBS_COUNT=%lu", (unsigned long)injected.count]);
    for (NSString *s in injected) DDAppend([NSString stringWithFormat:@"  INJECTED=%@", s]);

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

/* ---------- hooks ---------- */

%hook UIApplication
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    DDAppend(@"HOOK: UIApplication didFinishLaunchingWithOptions");
    DDumpEnvironment();
    DDumpOfficialCheck();
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

/* observe whether the app itself performs integrity checks */
static int (*orig_CheckValidity)(void *, unsigned int, void *);
static int my_CheckValidity(void *code, unsigned int flags, void *req) {
    int ret = orig_CheckValidity(code, flags, req);
    if (!DDInSelfCheck) DDAppend([NSString stringWithFormat:@"APP_CALL SecCodeCheckValidity flags=%u ret=%d", flags, ret]);
    return ret;
}

static int (*orig_CopySigningInfo)(void *, unsigned int, CFDictionaryRef *);
static int my_CopySigningInfo(void *code, unsigned int flags, CFDictionaryRef *info) {
    int ret = orig_CopySigningInfo(code, flags, info);
    if (!DDInSelfCheck) DDAppend([NSString stringWithFormat:@"APP_CALL SecCodeCopySigningInformation flags=%u ret=%d", flags, ret]);
    return ret;
}

%ctor {
    DDAppend(@"===== TWEAK LOADED =====");
    DDAppend([NSString stringWithFormat:@"PID=%d PROC=%@", getpid(), [[NSProcessInfo processInfo] processName]]);
    MSHookFunction((void *)sysctl, (void *)my_sysctl, (void **)&orig_sysctl);
    MSHookFunction((void *)sysctlbyname, (void *)my_sysctlbyname, (void **)&orig_sysctlbyname);
    DDAppend(@"HOOKED: sysctl, sysctlbyname");

    void *pCheck = dlsym(RTLD_DEFAULT, "SecCodeCheckValidity");
    void *pInfo  = dlsym(RTLD_DEFAULT, "SecCodeCopySigningInformation");
    if (pCheck) {
        MSHookFunction(pCheck, (void *)my_CheckValidity, (void **)&orig_CheckValidity);
        DDAppend(@"HOOKED: SecCodeCheckValidity");
    }
    if (pInfo) {
        MSHookFunction(pInfo, (void *)my_CopySigningInfo, (void **)&orig_CopySigningInfo);
        DDAppend(@"HOOKED: SecCodeCopySigningInformation");
    }

    DDumpEnvironment();
    DDumpOfficialCheck();
}
