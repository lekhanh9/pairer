#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <sys/socket.h>
#import <sys/mman.h>
#import <netinet/in.h>
#import <dlfcn.h>
#import <os/log.h>
#import <Security/Security.h>

// MobileSubstrate / ElleKit Hook Function Pointer
typedef void (*MSHookFunction_t)(void *symbol, void *hook, void **old);
static MSHookFunction_t MSHookFunction_p = NULL;
static uint8_t *g_usb_connected_ptr = NULL;

static void log_to_file(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    os_log(OS_LOG_DEFAULT, "%{public}s", buf);
    FILE *f = fopen("/tmp/lockdown_ssl.log", "a");
    if (f) {
        fprintf(f, "%s\n", buf);
        fclose(f);
    }
}

#pragma mark - Hook 1: Bypass peer_is_safe (getsockopt)
static int (*orig_getsockopt)(int socket, int level, int option_name, void *restrict option_value, socklen_t *restrict option_len) = NULL;

static int my_getsockopt(int socket, int level, int option_name, void *restrict option_value, socklen_t *restrict option_len) {
    if (level == 6 /* IPPROTO_TCP */ && option_name == 0x204 /* TCP_CONNECTION_INFO / peer PID */) {
        if (option_value && option_len && *option_len >= sizeof(uint32_t)) {
            *(uint32_t *)option_value = 0; // Luôn trả về PID 0 (kernel / an toàn)
            return 0;
        }
    }
    if (orig_getsockopt) {
        return orig_getsockopt(socket, level, option_name, option_value, option_len);
    }
    return 0;
}

#pragma mark - Hook 2: Bypass USB check (get_transport_type)
static int (*orig_get_transport_type)(void *conn) = NULL;

static int my_get_transport_type(void *conn) {
    int orig = orig_get_transport_type ? orig_get_transport_type(conn) : 4;
    log_to_file("[LockdownPairing] get_transport_type(%p) called, orig=%d -> returning 1 (USB)", conn, orig);
    if (conn) {
        *(uint64_t *)((uintptr_t)conn + 0x20) = 0;
    }
    if (g_usb_connected_ptr) {
        *g_usb_connected_ptr = 1;
    }
    return 1; // Always return 1 (USB)
}

#pragma mark - Hook 3: RemotePairingGetUSBConnectedHostTrustState
static BOOL (*orig_RemotePairingGetUSBConnectedHostTrustState)(void **outError) = NULL;

static BOOL my_RemotePairingGetUSBConnectedHostTrustState(void **outError) {
    log_to_file("[LockdownPairing] RemotePairingGetUSBConnectedHostTrustState called -> returning YES!");
    if (outError) *outError = nil;
    return YES;
}

#pragma mark - Hook 4: handle_pair
static int (*orig_handle_pair)(void *session, void *req, void *req_name, int is_wireless, void *arg4) = NULL;

static int my_handle_pair(void *session, void *req, void *req_name, int is_wireless, void *arg4) {
    log_to_file("[LockdownPairing] handle_pair called! session=%p, req=%p, is_wireless=%d", session, req, is_wireless);
    if (session) {
        *(uint64_t *)((uintptr_t)session + 0x20) = 0;
    }
    if (g_usb_connected_ptr) {
        *g_usb_connected_ptr = 1;
    }
    return orig_handle_pair(session, req, req_name, 0, arg4);
}

#pragma mark - Hook 5: Always Enable Wifi Connections
static int (*orig_check_bool_pref)(void *a0, void *a1, void *a2) = NULL;

static int my_check_bool_pref(void *a0, void *a1, void *a2) {
    log_to_file("[LockdownPairing] check_bool_pref called for key %p -> returning 1 (ENABLED)", a1);
    return 1; // Always allow WiFi / VPN connections!
}

#pragma mark - Hook 6: SSLHandshake Hook by Direct GOT Patching
static OSStatus (*orig_ssl_handshake)(SSLContextRef ctx) = NULL;

static OSStatus my_ssl_handshake(SSLContextRef ctx) {
    OSStatus res = orig_ssl_handshake(ctx);
    log_to_file("[LockdownPairing] GOT my_ssl_handshake(%p) returned %d (0x%x)", ctx, (int)res, (unsigned int)res);
    return res;
}

static BOOL (*orig_trust_eval)(SecTrustRef trust, CFErrorRef *error) = NULL;

static BOOL my_trust_eval(SecTrustRef trust, CFErrorRef *error) {
    BOOL ok = orig_trust_eval ? orig_trust_eval(trust, error) : YES;
    log_to_file("[LockdownPairing] GOT my_trust_eval(%p) returned %d, forcing YES", trust, ok);
    if (error) *error = NULL;
    return YES;
}

#pragma mark - Hook 8: load_pair_record (ensure DeviceCertificate is present)
static NSDictionary *(*orig_load_pair_record)(CFStringRef host_id) = NULL;

static NSDictionary *my_load_pair_record(CFStringRef host_id) {
    NSDictionary *dict = orig_load_pair_record ? orig_load_pair_record(host_id) : nil;
    log_to_file("[LockdownPairing] load_pair_record(%@) -> %p", host_id, dict);
    if (dict) {
        NSMutableDictionary *m = [dict mutableCopy];
        if (!m[@"DeviceCertificate"]) {
            NSDictionary *pf = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Documents/pairingFile.plist"];
            if (!pf) {
                pf = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Documents/PairingFile_Lockdown.plist"];
            }
            if (pf && pf[@"DeviceCertificate"]) {
                log_to_file("[LockdownPairing] Injected real DeviceCertificate from pairingFile.plist!");
                m[@"DeviceCertificate"] = pf[@"DeviceCertificate"];
            }
        }
        return m;
    }
    return dict;
}

#pragma mark - Hook 9: decode_pem (handle missing trailing newlines)
static CFDataRef (*orig_decode_pem)(CFDataRef pem, const char *tag) = NULL;

static CFDataRef my_decode_pem(CFDataRef pem, const char *tag) {
    CFDataRef ret = orig_decode_pem ? orig_decode_pem(pem, tag) : NULL;
    if (!ret && pem && tag) {
        const UInt8 *bytes = CFDataGetBytePtr(pem);
        CFIndex len = CFDataGetLength(pem);
        if (bytes && len > 0) {
            NSMutableData *fixed = [NSMutableData dataWithBytes:bytes length:len];
            [fixed appendBytes:"\n" length:1];
            ret = orig_decode_pem((__bridge CFDataRef)fixed, tag);
        }
    }
    return ret;
}

static uint32_t get_lockdownd_image_index(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "lockdownd")) {
            return i;
        }
    }
    return 0;
}

static void resolve_mshook(void) {
    void *h = dlopen("@loader_path/../libellekit.dylib", RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        h = dlopen("/private/var/containers/Bundle/Application/.jbroot-2DFCCA5606EEBA1F/usr/lib/libellekit.dylib", RTLD_NOW | RTLD_GLOBAL);
    }
    if (h) {
        MSHookFunction_p = (MSHookFunction_t)dlsym(h, "MSHookFunction");
        log_to_file("[LockdownPairing] Resolved MSHookFunction from handle %p -> %p", h, MSHookFunction_p);
    }

    if (!MSHookFunction_p) {
        MSHookFunction_p = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    }
}

static void patch_got(void *addr, void *new_val, void **old_val) {
    uintptr_t page = (uintptr_t)addr & ~0x3fff;
    mprotect((void *)page, 0x4000, PROT_READ | PROT_WRITE);
    if (old_val) *old_val = *(void **)addr;
    *(void **)addr = new_val;
    mprotect((void *)page, 0x4000, PROT_READ);
}

__attribute__((constructor))
static void init(void) {
    log_to_file("[LockdownPairing] Initializing tweak inside lockdownd (PID: %d)...", getpid());

    resolve_mshook();
    if (!MSHookFunction_p) {
        log_to_file("[LockdownPairing] FATAL: MSHookFunction could not be resolved!");
        return;
    }

    uint32_t img_idx = get_lockdownd_image_index();
    intptr_t slide = _dyld_get_image_vmaddr_slide(img_idx);
    log_to_file("[LockdownPairing] lockdownd image index: %u, slide: 0x%lx", img_idx, (long)slide);

    // Force g_usb_connected = 1 (at 0x10010d880 + slide)
    g_usb_connected_ptr = (uint8_t *)(0x10010d880 + slide);
    *g_usb_connected_ptr = 1;

    // Hook 1: getsockopt qua direct GOT patch tại 0x1000ecc10 + slide
    void *got_getsockopt = (void *)(0x1000ecc10 + slide);
    patch_got(got_getsockopt, (void *)&my_getsockopt, (void **)&orig_getsockopt);
    log_to_file("[LockdownPairing] Patched GOT getsockopt at %p: new=%p", got_getsockopt, my_getsockopt);

    // Hook 2: get_transport_type at 0x100002ec0 + slide
    void *target_transport = (void *)(0x100002ec0 + slide);
    MSHookFunction_p(target_transport, (void *)&my_get_transport_type, (void **)&orig_get_transport_type);
    log_to_file("[LockdownPairing] Hooked get_transport_type at %p successfully!", target_transport);

    // Hook 3: RemotePairingGetUSBConnectedHostTrustState
    void *hRPD = dlopen("/System/Library/PrivateFrameworks/RemotePairingDevice.framework/RemotePairingDevice", RTLD_NOW | RTLD_GLOBAL);
    void *target_rpd = dlsym(hRPD ? hRPD : RTLD_DEFAULT, "RemotePairingGetUSBConnectedHostTrustState");
    if (target_rpd) {
        MSHookFunction_p(target_rpd, (void *)&my_RemotePairingGetUSBConnectedHostTrustState, (void **)&orig_RemotePairingGetUSBConnectedHostTrustState);
        log_to_file("[LockdownPairing] Hooked RemotePairingGetUSBConnectedHostTrustState successfully!");
    }

    // Hook 4: handle_pair at 0x100028d5c + slide
    void *target_hp = (void *)(0x100028d5c + slide);
    MSHookFunction_p(target_hp, (void *)&my_handle_pair, (void **)&orig_handle_pair);
    log_to_file("[LockdownPairing] Hooked handle_pair at %p successfully!", target_hp);

    // Hook 5: check_bool_pref at 0x10000da24 + slide
    void *target_pref = (void *)(0x10000da24 + slide);
    MSHookFunction_p(target_pref, (void *)&my_check_bool_pref, (void **)&orig_check_bool_pref);
    log_to_file("[LockdownPairing] Hooked check_bool_pref at %p successfully!", target_pref);

    // Hook 6: GOT patch for SSLHandshake (0x1000ec788 + slide)
    void *got_ssl_hs = (void *)(0x1000ec788 + slide);
    patch_got(got_ssl_hs, (void *)&my_ssl_handshake, (void **)&orig_ssl_handshake);
    log_to_file("[LockdownPairing] Patched GOT SSLHandshake: orig=%p, new=%p", orig_ssl_handshake, my_ssl_handshake);

    // Hook 7: GOT patch for SecTrustEvaluateWithError (0x1000ec868 + slide)
    void *got_trust = (void *)(0x1000ec868 + slide);
    patch_got(got_trust, (void *)&my_trust_eval, (void **)&orig_trust_eval);
    log_to_file("[LockdownPairing] Patched GOT SecTrustEvaluateWithError: orig=%p, new=%p", orig_trust_eval, my_trust_eval);

    // Hook 8: load_pair_record at 0x1000140a0 + slide
    void *target_lpr = (void *)(0x1000140a0 + slide);
    MSHookFunction_p(target_lpr, (void *)&my_load_pair_record, (void **)&orig_load_pair_record);
    log_to_file("[LockdownPairing] Hooked load_pair_record at %p successfully!", target_lpr);

    // Hook 9: decode_pem at 0x10000e6e4 + slide
    void *target_dp = (void *)(0x10000e6e4 + slide);
    MSHookFunction_p(target_dp, (void *)&my_decode_pem, (void **)&orig_decode_pem);
    log_to_file("[LockdownPairing] Hooked decode_pem at %p successfully!", target_dp);
}
