#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <dlfcn.h>
#import <unistd.h>
#import <sys/stat.h>
#import <spawn.h>

static void restart_lockdownd(void) {
    pid_t pid;
    const char *argv1[] = {"launchctl", "kickstart", "-k", "system/com.apple.mobile.lockdown", NULL};
    if (posix_spawnp(&pid, "launchctl", NULL, NULL, (char *const *)argv1, NULL) == 0) {
        int status;
        waitpid(pid, &status, 0);
        return;
    }
    const char *argv2[] = {"killall", "-9", "lockdownd", NULL};
    if (posix_spawnp(&pid, "killall", NULL, NULL, (char *const *)argv2, NULL) == 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}

#pragma mark - Dynamic Bootstrap Resolution
static inline NSString *GetBootstrapRoot(void) {
    static NSString *root;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // 1. checker /private/var/containers/Bundle/Application/.jbroot-* (roothide install root)
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray<NSString *> *bundleApps = [fm contentsOfDirectoryAtPath:@"/private/var/containers/Bundle/Application" error:nil];
        for (NSString *item in bundleApps) {
            if ([item hasPrefix:@".jbroot-"]) {
                root = [@"/private/var/containers/Bundle/Application" stringByAppendingPathComponent:item];
                break;
            }
        }
        // 2. checker /var/jb (rootless)
        if (!root && [fm fileExistsAtPath:@"/var/jb"]) {
            root = @"/var/jb";
        }
        if (!root) root = @"";
    });
    return root;
}

#pragma mark - OpenSSL Dynamic Function Pointers
typedef void BIGNUM;
typedef void RSA;
typedef void EVP_PKEY;
typedef void EVP_MD;
typedef void X509;
typedef void X509_EXTENSION;
typedef struct {
    X509 *issuer_cert;
    X509 *subject_cert;
    void *crl;
    void *db_meth;
    void *db;
} X509V3_CTX;
typedef void BIO;
typedef void BIO_METHOD;
typedef void ASN1_INTEGER;
typedef void ASN1_TIME;

static BIGNUM* (*p_BN_new)(void) = NULL;
static int (*p_BN_set_word)(BIGNUM *a, unsigned long w) = NULL;
static void (*p_BN_free)(BIGNUM *a) = NULL;

static RSA* (*p_RSA_new)(void) = NULL;
static int (*p_RSA_generate_key_ex)(RSA *rsa, int bits, BIGNUM *e, void *cb) = NULL;
static void (*p_RSA_free)(RSA *r) = NULL;

static EVP_PKEY* (*p_EVP_PKEY_new)(void) = NULL;
static int (*p_EVP_PKEY_assign)(EVP_PKEY *pkey, int type, void *key) = NULL;
static void (*p_EVP_PKEY_free)(EVP_PKEY *key) = NULL;
#define EVP_PKEY_RSA 6
#define EVP_PKEY_assign_RSA(pkey,rsa) p_EVP_PKEY_assign((pkey),EVP_PKEY_RSA,(char *)(rsa))

static const EVP_MD* (*p_EVP_sha256)(void) = NULL;

static X509* (*p_X509_new)(void) = NULL;
static void (*p_X509_free)(X509 *a) = NULL;
static int (*p_X509_set_version)(X509 *x, long version) = NULL;
static int (*p_X509_set_pubkey)(X509 *x, EVP_PKEY *pkey) = NULL;
static int (*p_X509_sign)(X509 *x, EVP_PKEY *pkey, const EVP_MD *md) = NULL;
static ASN1_INTEGER* (*p_ASN1_INTEGER_new)(void) = NULL;
static int (*p_ASN1_INTEGER_set)(ASN1_INTEGER *a, long v) = NULL;
static void (*p_ASN1_INTEGER_free)(ASN1_INTEGER *a) = NULL;
static int (*p_X509_set_serialNumber)(X509 *x, ASN1_INTEGER *serial) = NULL;

static ASN1_TIME* (*p_ASN1_TIME_new)(void) = NULL;
static ASN1_TIME* (*p_ASN1_TIME_set)(ASN1_TIME *s, time_t t) = NULL;
static void (*p_ASN1_TIME_free)(ASN1_TIME *a) = NULL;
static int (*p_X509_set1_notBefore)(X509 *x, const ASN1_TIME *tm) = NULL;
static int (*p_X509_set1_notAfter)(X509 *x, const ASN1_TIME *tm) = NULL;

static void (*p_X509V3_set_ctx)(X509V3_CTX *ctx, X509 *issuer, X509 *subj, void *req, void *crl, int flags) = NULL;
static X509_EXTENSION* (*p_X509V3_EXT_conf_nid)(void *conf, X509V3_CTX *ctx, int ext_nid, const char *value) = NULL;
static int (*p_X509_add_ext)(X509 *x, X509_EXTENSION *ex, int loc) = NULL;
static void (*p_X509_EXTENSION_free)(X509_EXTENSION *a) = NULL;

static const BIO_METHOD* (*p_BIO_s_mem)(void) = NULL;
static BIO* (*p_BIO_new)(const BIO_METHOD *type) = NULL;
static BIO* (*p_BIO_new_mem_buf)(const void *buf, int len) = NULL;
static int (*p_BIO_free)(BIO *a) = NULL;
static long (*p_BIO_ctrl)(BIO *bp, int cmd, long larg, void *parg) = NULL;
#define BIO_get_mem_data(b,pp) p_BIO_ctrl(b,3,0,(char *)(pp))

static int (*p_PEM_write_bio_X509)(BIO *bp, X509 *x) = NULL;
static int (*p_PEM_write_bio_PrivateKey)(BIO *bp, EVP_PKEY *x, const void *enc, unsigned char *kstr, int klen, void *cb, void *u) = NULL;
static RSA* (*p_PEM_read_bio_RSAPublicKey)(BIO *bp, RSA **rsa, void *cb, void *u) = NULL;

static BOOL init_openssl(void) {
    NSString *root = GetBootstrapRoot();
    NSArray<NSString *> *candidates = @[
        [root stringByAppendingPathComponent:@"usr/lib/libcrypto.3.dylib"],
        [root stringByAppendingPathComponent:@"usr/lib/libcrypto.dylib"],
        @"/usr/lib/libcrypto.3.dylib",
        @"/usr/lib/libcrypto.dylib"
    ];

    void *h = NULL;
    for (NSString *path in candidates) {
        h = dlopen([path UTF8String], RTLD_NOW | RTLD_GLOBAL);
        if (h) {
            printf("[*] Loaded OpenSSL from: %s\n", [path UTF8String]);
            break;
        } else {
            // printf("[*] Failed to load %s: %s\n", [path UTF8String], dlerror());
        }
    }
    if (!h) {
        h = dlopen("libcrypto.3.dylib", RTLD_NOW | RTLD_GLOBAL);
        if (h) printf("[*] Loaded OpenSSL from default search path\n");
    }
    if (!h) {
        printf("[-] dlopen all candidates failed. Last error: %s\n", dlerror());
        printf("[*] Bootstrap root was: %s\n", [root UTF8String]);
        return NO;
    }

    p_BN_new = (BIGNUM* (*)(void))dlsym(h, "BN_new");
    p_BN_set_word = (int (*)(BIGNUM*, unsigned long))dlsym(h, "BN_set_word");
    p_BN_free = (void (*)(BIGNUM*))dlsym(h, "BN_free");

    p_RSA_new = (RSA* (*)(void))dlsym(h, "RSA_new");
    p_RSA_generate_key_ex = (int (*)(RSA*, int, BIGNUM*, void*))dlsym(h, "RSA_generate_key_ex");
    p_RSA_free = (void (*)(RSA*))dlsym(h, "RSA_free");

    p_EVP_PKEY_new = (EVP_PKEY* (*)(void))dlsym(h, "EVP_PKEY_new");
    p_EVP_PKEY_assign = (int (*)(EVP_PKEY*, int, void*))dlsym(h, "EVP_PKEY_assign");
    p_EVP_PKEY_free = (void (*)(EVP_PKEY*))dlsym(h, "EVP_PKEY_free");
    p_EVP_sha256 = (const EVP_MD* (*)(void))dlsym(h, "EVP_sha256");

    p_X509_new = (X509* (*)(void))dlsym(h, "X509_new");
    p_X509_free = (void (*)(X509*))dlsym(h, "X509_free");
    p_X509_set_version = (int (*)(X509*, long))dlsym(h, "X509_set_version");
    p_X509_set_pubkey = (int (*)(X509*, EVP_PKEY*))dlsym(h, "X509_set_pubkey");
    p_X509_sign = (int (*)(X509*, EVP_PKEY*, const EVP_MD*))dlsym(h, "X509_sign");

    p_ASN1_INTEGER_new = (ASN1_INTEGER* (*)(void))dlsym(h, "ASN1_INTEGER_new");
    p_ASN1_INTEGER_set = (int (*)(ASN1_INTEGER*, long))dlsym(h, "ASN1_INTEGER_set");
    p_ASN1_INTEGER_free = (void (*)(ASN1_INTEGER*))dlsym(h, "ASN1_INTEGER_free");
    p_X509_set_serialNumber = (int (*)(X509*, ASN1_INTEGER*))dlsym(h, "X509_set_serialNumber");

    p_ASN1_TIME_new = (ASN1_TIME* (*)(void))dlsym(h, "ASN1_TIME_new");
    p_ASN1_TIME_set = (ASN1_TIME* (*)(ASN1_TIME*, time_t))dlsym(h, "ASN1_TIME_set");
    p_ASN1_TIME_free = (void (*)(ASN1_TIME*))dlsym(h, "ASN1_TIME_free");
    p_X509_set1_notBefore = (int (*)(X509*, const ASN1_TIME*))dlsym(h, "X509_set1_notBefore");
    p_X509_set1_notAfter = (int (*)(X509*, const ASN1_TIME*))dlsym(h, "X509_set1_notAfter");

    p_X509V3_set_ctx = (void (*)(X509V3_CTX*, X509*, X509*, void*, void*, int))dlsym(h, "X509V3_set_ctx");
    p_X509V3_EXT_conf_nid = (X509_EXTENSION* (*)(void*, X509V3_CTX*, int, const char*))dlsym(h, "X509V3_EXT_conf_nid");
    p_X509_add_ext = (int (*)(X509*, X509_EXTENSION*, int))dlsym(h, "X509_add_ext");
    p_X509_EXTENSION_free = (void (*)(X509_EXTENSION*))dlsym(h, "X509_EXTENSION_free");

    p_BIO_s_mem = (const BIO_METHOD* (*)(void))dlsym(h, "BIO_s_mem");
    p_BIO_new = (BIO* (*)(const BIO_METHOD*))dlsym(h, "BIO_new");
    p_BIO_new_mem_buf = (BIO* (*)(const void*, int))dlsym(h, "BIO_new_mem_buf");
    p_BIO_free = (int (*)(BIO*))dlsym(h, "BIO_free");
    p_BIO_ctrl = (long (*)(BIO*, int, long, void*))dlsym(h, "BIO_ctrl");

    p_PEM_write_bio_X509 = (int (*)(BIO*, X509*))dlsym(h, "PEM_write_bio_X509");
    p_PEM_write_bio_PrivateKey = (int (*)(BIO*, EVP_PKEY*, const void*, unsigned char*, int, void*, void*))dlsym(h, "PEM_write_bio_PrivateKey");
    p_PEM_read_bio_RSAPublicKey = (RSA* (*)(BIO*, RSA**, void*, void*))dlsym(h, "PEM_read_bio_RSAPublicKey");

    return (p_RSA_generate_key_ex && p_X509_sign && p_PEM_write_bio_X509);
}

static void add_ext_helper(X509 *cert, int nid, const char *val) {
    if (!p_X509V3_EXT_conf_nid || !p_X509_add_ext) return;
    X509V3_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (p_X509V3_set_ctx) p_X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    X509_EXTENSION *ex = p_X509V3_EXT_conf_nid(NULL, &ctx, nid, val);
    if (ex) {
        p_X509_add_ext(cert, ex, -1);
        p_X509_EXTENSION_free(ex);
    }
}

static NSData *bio_to_data(BIO *bio) {
    char *buf = NULL;
    long len = BIO_get_mem_data(bio, &buf);
    if (len <= 0 || !buf) return nil;
    NSMutableData *d = [NSMutableData dataWithBytes:buf length:len];
    if (((const char *)d.bytes)[len - 1] != '\n') {
        [d appendBytes:"\n" length:1];
    }
    return d;
}

#pragma mark - Socket Helper
static ssize_t read_all(int fd, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t r = read(fd, (char *)buf + total, len - total);
        if (r <= 0) {
            if (r < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            return -1;
        }
        total += r;
    }
    return total;
}

static BOOL send_plist(int fd, NSDictionary *dict) {
    NSError *err = nil;
    NSData *xml = [NSPropertyListSerialization dataWithPropertyList:dict format:NSPropertyListXMLFormat_v1_0 options:0 error:&err];
    if (!xml) return NO;
    uint32_t len_be = htonl((uint32_t)xml.length);
    if (write(fd, &len_be, 4) != 4) return NO;
    if (write(fd, xml.bytes, xml.length) != (ssize_t)xml.length) return NO;
    return YES;
}

static NSDictionary *recv_plist(int fd) {
    uint32_t len_be = 0;
    if (read_all(fd, &len_be, 4) != 4) return nil;
    uint32_t len = ntohl(len_be);
    if (len == 0 || len > 10 * 1024 * 1024) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:len];
    if (read_all(fd, data.mutableBytes, len) != (ssize_t)len) return nil;
    return [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:nil];
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        signal(SIGPIPE, SIG_IGN);

        NSString *prefPath = @"/var/mobile/Library/Preferences/com.lockdown.localpairing.plist";

        if (argc > 1) {
            NSString *arg = [NSString stringWithUTF8String:argv[1]];
            if ([arg isEqualToString:@"off"] || [arg isEqualToString:@"--off"] || [arg isEqualToString:@"disable"]) {
                [@{ @"enabled": @NO } writeToFile:prefPath atomically:YES];
                chmod([prefPath UTF8String], 0644);
                restart_lockdownd();
                printf("[+] Lockdown pairing hook disabled.\n");
                printf("[*] Restored stock Apple lockdownd behavior and USB security.\n");
                return 0;
            } else if ([arg isEqualToString:@"on"] || [arg isEqualToString:@"--on"] || [arg isEqualToString:@"enable"]) {
                [@{ @"enabled": @YES } writeToFile:prefPath atomically:YES];
                chmod([prefPath UTF8String], 0644);
                restart_lockdownd();
                printf("[+] Lockdown pairing hook enabled.\n");
                return 0;
            } else if ([arg isEqualToString:@"status"] || [arg isEqualToString:@"--status"]) {
                NSDictionary *pref = [NSDictionary dictionaryWithContentsOfFile:prefPath];
                BOOL isEnabled = (pref && pref[@"enabled"] != nil) ? [pref[@"enabled"] boolValue] : YES;
                printf("Lockdown pairing hook: %s\n", isEnabled ? "enabled" : "disabled");
                return 0;
            } else if ([arg isEqualToString:@"-h"] || [arg isEqualToString:@"--help"] || [arg isEqualToString:@"help"]) {
                printf("Usage: pair-local [command]\n\n");
                printf("Commands:\n");
                printf("  (none)   Pair locally and inject pairing record into SideStore / LiveContainer\n");
                printf("  on       Enable tweak hook\n");
                printf("  off      Disable tweak hook (restores stock Apple lockdownd)\n");
                printf("  status   Show current tweak status\n\n");
                return 0;
            }
        }

        // Ensure hook is enabled before pairing
        NSDictionary *curPref = [NSDictionary dictionaryWithContentsOfFile:prefPath];
        if (curPref && curPref[@"enabled"] != nil && ![curPref[@"enabled"] boolValue]) {
            printf("[*] Tweak is currently disabled. Temporarily enabling for pairing...\n");
            [@{ @"enabled": @YES } writeToFile:prefPath atomically:YES];
            chmod([prefPath UTF8String], 0644);
            restart_lockdownd();
            usleep(500000);
        }

        printf("====================================================\n");
        printf("Lockdown Local Pairing Tool\n");
        printf("====================================================\n");

        if (!init_openssl()) {
            printf("[-] Failed to load OpenSSL (libcrypto.3.dylib).\n");
            return 1;
        }

        printf("[*] Connecting to lockdownd (127.0.0.1:62078)...\n");
        int fd = -1;
        NSDictionary *resp = nil;
        for (int attempt = 1; attempt <= 5; attempt++) {
            if (fd >= 0) close(fd);
            fd = socket(AF_INET, SOCK_STREAM, 0);

            struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(62078);
            addr.sin_addr.s_addr = inet_addr("127.0.0.1");

            if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                send_plist(fd, @{@"Request": @"QueryType"});
                resp = recv_plist(fd);
                if (resp && resp[@"Type"]) {
                    break;
                }
            }
            usleep(300000);
        }

        if (!resp || !resp[@"Type"]) {
            printf("[-] Failed to connect to lockdownd.\n");
            if (fd >= 0) close(fd);
            return 1;
        }
        printf("[+] Connected to lockdownd (%s).\n", [resp[@"Type"] UTF8String]);

        // 2. Query device info
        send_plist(fd, @{@"Request": @"GetValue", @"Key": @"UniqueDeviceID"});
        NSDictionary *respUDID = recv_plist(fd);
        NSString *udid = respUDID[@"Value"] ?: @"22f82ce5bd377b75035be2458585bbfbb8d189ca";
        printf("[+] Device UDID: %s\n", [udid UTF8String]);

        send_plist(fd, @{@"Request": @"GetValue", @"Key": @"WiFiAddress"});
        NSDictionary *respMAC = recv_plist(fd);
        NSString *wifiMAC = respMAC[@"Value"] ?: @"7c:9a:1d:43:50:83";
        printf("[+] Wi-Fi MAC: %s\n", [wifiMAC UTF8String]);

        // 3. Sinh Root CA & Host Certificate theo chuẩn libimobiledevice
        printf("[*] Generating RSA 2048-bit keys and X.509 v3 certificates...\n");

        BIGNUM *e = p_BN_new();
        p_BN_set_word(e, 65537);

        // Root keypair
        RSA *root_rsa = p_RSA_new();
        p_RSA_generate_key_ex(root_rsa, 2048, e, NULL);
        EVP_PKEY *root_pkey = p_EVP_PKEY_new();
        EVP_PKEY_assign_RSA(root_pkey, root_rsa);

        // Host keypair
        RSA *host_rsa = p_RSA_new();
        p_RSA_generate_key_ex(host_rsa, 2048, e, NULL);
        EVP_PKEY *host_pkey = p_EVP_PKEY_new();
        EVP_PKEY_assign_RSA(host_pkey, host_rsa);
        p_BN_free(e);

        time_t now = time(NULL);
        time_t ten_years = now + (60 * 60 * 24 * 365 * 10);

        // 3.1. Root Certificate
        X509 *root_cert = p_X509_new();
        p_X509_set_version(root_cert, 2); // v3
        ASN1_INTEGER *sn_root = p_ASN1_INTEGER_new();
        p_ASN1_INTEGER_set(sn_root, 0);
        p_X509_set_serialNumber(root_cert, sn_root);
        p_ASN1_INTEGER_free(sn_root);

        ASN1_TIME *tm_before = p_ASN1_TIME_new();
        p_ASN1_TIME_set(tm_before, now);
        p_X509_set1_notBefore(root_cert, tm_before);
        ASN1_TIME *tm_after = p_ASN1_TIME_new();
        p_ASN1_TIME_set(tm_after, ten_years);
        p_X509_set1_notAfter(root_cert, tm_after);

        p_X509_set_pubkey(root_cert, root_pkey);
        add_ext_helper(root_cert, 87 /* basicConstraints */, "critical,CA:TRUE");
        p_X509_sign(root_cert, root_pkey, p_EVP_sha256());

        // 3.2. Host Certificate
        X509 *host_cert = p_X509_new();
        p_X509_set_version(host_cert, 2);
        ASN1_INTEGER *sn_host = p_ASN1_INTEGER_new();
        p_ASN1_INTEGER_set(sn_host, 0);
        p_X509_set_serialNumber(host_cert, sn_host);
        p_ASN1_INTEGER_free(sn_host);

        p_X509_set1_notBefore(host_cert, tm_before);
        p_X509_set1_notAfter(host_cert, tm_after);
        p_X509_set_pubkey(host_cert, host_pkey);

        add_ext_helper(host_cert, 87 /* basicConstraints */, "critical,CA:FALSE");
        add_ext_helper(host_cert, 83 /* keyUsage */, "critical,digitalSignature,keyEncipherment");
        p_X509_sign(host_cert, root_pkey, p_EVP_sha256()); // Ký bằng Root CA!

        // Xuất PEM
        BIO *bioRootCert = p_BIO_new(p_BIO_s_mem());
        p_PEM_write_bio_X509(bioRootCert, root_cert);
        NSData *rootCertData = bio_to_data(bioRootCert);
        p_BIO_free(bioRootCert);

        BIO *bioRootKey = p_BIO_new(p_BIO_s_mem());
        p_PEM_write_bio_PrivateKey(bioRootKey, root_pkey, NULL, NULL, 0, NULL, NULL);
        NSData *rootKeyData = bio_to_data(bioRootKey);
        p_BIO_free(bioRootKey);

        BIO *bioHostCert = p_BIO_new(p_BIO_s_mem());
        p_PEM_write_bio_X509(bioHostCert, host_cert);
        NSData *hostCertData = bio_to_data(bioHostCert);
        p_BIO_free(bioHostCert);

        BIO *bioHostKey = p_BIO_new(p_BIO_s_mem());
        p_PEM_write_bio_PrivateKey(bioHostKey, host_pkey, NULL, NULL, 0, NULL, NULL);
        NSData *hostKeyData = bio_to_data(bioHostKey);
        p_BIO_free(bioHostKey);

        // 3.3. Device Certificate (tạo từ DevicePublicKey của iPhone, ký bởi Root CA)
        send_plist(fd, @{@"Request": @"GetValue", @"Key": @"DevicePublicKey"});
        NSDictionary *respDevPK = recv_plist(fd);
        NSData *devPKData = respDevPK[@"Value"];
        NSData *deviceCertData = nil;

        if (devPKData && devPKData.length > 0) {
            BIO *bioDevPub = p_BIO_new_mem_buf(devPKData.bytes, (int)devPKData.length);
            RSA *dev_rsa = p_PEM_read_bio_RSAPublicKey(bioDevPub, NULL, NULL, NULL);
            p_BIO_free(bioDevPub);

            if (dev_rsa) {
                EVP_PKEY *dev_pkey = p_EVP_PKEY_new();
                EVP_PKEY_assign_RSA(dev_pkey, dev_rsa);

                X509 *dev_cert = p_X509_new();
                p_X509_set_version(dev_cert, 2);
                ASN1_INTEGER *sn_dev = p_ASN1_INTEGER_new();
                p_ASN1_INTEGER_set(sn_dev, 0);
                p_X509_set_serialNumber(dev_cert, sn_dev);
                p_ASN1_INTEGER_free(sn_dev);

                p_X509_set1_notBefore(dev_cert, tm_before);
                p_X509_set1_notAfter(dev_cert, tm_after);
                p_X509_set_pubkey(dev_cert, dev_pkey);

                add_ext_helper(dev_cert, 87 /* basicConstraints */, "critical,CA:FALSE");
                add_ext_helper(dev_cert, 83 /* keyUsage */, "critical,digitalSignature,keyEncipherment");
                p_X509_sign(dev_cert, root_pkey, p_EVP_sha256());

                BIO *bioDevCert = p_BIO_new(p_BIO_s_mem());
                p_PEM_write_bio_X509(bioDevCert, dev_cert);
                deviceCertData = bio_to_data(bioDevCert);
                p_BIO_free(bioDevCert);

                p_X509_free(dev_cert);
                p_EVP_PKEY_free(dev_pkey);
            }
        }

        p_ASN1_TIME_free(tm_before);
        p_ASN1_TIME_free(tm_after);
        if (fd >= 0) close(fd); // Close initial query socket

        NSString *hostID = [[NSUUID UUID] UUIDString];
        NSString *systemBUID = [[NSUUID UUID] UUIDString];

        // 4. Create Pair Request
        NSMutableDictionary *pairRecord = [NSMutableDictionary dictionaryWithDictionary:@{
            @"DeviceCertificate": deviceCertData,
            @"HostCertificate": hostCertData,
            @"HostID": hostID,
            @"RootCertificate": rootCertData,
            @"SystemBUID": systemBUID
        }];
        if (devPKData) {
            pairRecord[@"DevicePublicKey"] = devPKData;
        }

        NSDictionary *pairRequest = @{
            @"Label": @"idevicepair",
            @"Request": @"Pair",
            @"ProtocolVersion": @"2",
            @"PairRecord": pairRecord,
            @"PairingOptions": @{
                @"ExtendedPairingErrors": @YES
            }
        };

        // Small delay before opening handshake socket
        usleep(500000); // 500ms delay

        int fdPair = -1;
        for (int attempt = 1; attempt <= 3; attempt++) {
            if (fdPair >= 0) close(fdPair);
            fdPair = socket(AF_INET, SOCK_STREAM, 0);
            struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
            setsockopt(fdPair, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fdPair, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(62078);
            addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            if (connect(fdPair, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                send_plist(fdPair, @{@"Request": @"QueryType"});
                NSDictionary *qt = recv_plist(fdPair);
                if (qt && qt[@"Type"]) break;
            }
            usleep(200000);
        }

        printf("[*] Sending pair request...\n");
        send_plist(fdPair, pairRequest);

        NSData *escrowBag = nil;
        BOOL promptShown = NO;
        int maxAttempts = 30; // 30 * 2s = 60s max wait for trust dialog
        int currentAttempt = 0;

        while (1) {
            NSDictionary *pairResp = recv_plist(fdPair);
            if (!pairResp) {
                printf("\nERROR: Connection closed by lockdownd.\n");
                if (fdPair >= 0) close(fdPair);
                return 1;
            }

            NSString *error = pairResp[@"Error"];
            if (!error) {
                if (promptShown) {
                    printf("\n[+] Trust confirmed. Passcode verified.\n");
                }
                printf("SUCCESS: Paired with device %s\n", [udid UTF8String]);
                escrowBag = pairResp[@"EscrowBag"];
                if (pairResp[@"DeviceCertificate"]) {
                    deviceCertData = pairResp[@"DeviceCertificate"];
                }
                break;
            }

            if ([error isEqualToString:@"PasswordProtected"] || [error isEqualToString:@"PairingDialogResponsePending"]) {
                if (!promptShown) {
                    printf("Please accept the trust dialog on the screen of device %s and enter passcode...\n", [udid UTF8String]);
                    fflush(stdout);
                    promptShown = YES;
                }
                currentAttempt++;
                if (currentAttempt > maxAttempts) {
                    printf("\nERROR: Pairing timed out waiting for user confirmation.\n");
                    if (fdPair >= 0) close(fdPair);
                    return 1;
                }
                printf(".");
                fflush(stdout);
                sleep(2); // 2 second delay between checks (libimobiledevice standard)
                send_plist(fdPair, pairRequest);
            } else if ([error isEqualToString:@"UserDeniedPairing"]) {
                printf("\nERROR: Device %s refused to pair (user denied pairing).\n", [udid UTF8String]);
                if (fdPair >= 0) close(fdPair);
                return 1;
            } else {
                printf("\nERROR: Pairing failed: %s\n", [[pairResp description] UTF8String]);
                if (fdPair >= 0) close(fdPair);
                return 1;
            }
        }
        close(fdPair);

        // 5. Serialize Pairing Record
        NSMutableDictionary *finalRecord = [NSMutableDictionary dictionaryWithDictionary:@{
            @"DeviceCertificate": deviceCertData ?: hostCertData,
            @"HostCertificate": hostCertData,
            @"HostID": hostID,
            @"HostPrivateKey": hostKeyData,
            @"RootCertificate": rootCertData,
            @"RootPrivateKey": rootKeyData,
            @"SystemBUID": systemBUID,
            @"WiFiMACAddress": wifiMAC,
            @"UDID": udid
        }];
        if (escrowBag) {
            finalRecord[@"EscrowBag"] = escrowBag;
        }

        NSError *plistErr = nil;
        NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:finalRecord format:NSPropertyListXMLFormat_v1_0 options:0 error:&plistErr];
        if (!plistData) {
            printf("[-] Failed to serialize pairing plist: %s\n", [[plistErr localizedDescription] UTF8String]);
            return 1;
        }

        NSArray<NSString *> *outPaths = @[
            [NSString stringWithFormat:@"/var/mobile/Documents/%@.plist", udid],
            @"/var/mobile/Documents/PairingFile_Lockdown.plist",
            [NSString stringWithFormat:@"/var/mobile/%@.plist", udid]
        ];

        printf("[+] Pairing record generated:\n");
        for (NSString *p in outPaths) {
            BOOL written = [plistData writeToFile:p atomically:YES];
            chmod([p UTF8String], 0644);
            printf("  - %s (%s)\n", [p UTF8String], written ? "ok" : "failed");
        }

        // 6. Auto-inject into SideStore / LiveContainer app containers
        printf("[*] Searching for SideStore and LiveContainer containers...\n");
        NSString *containersDir = @"/private/var/mobile/Containers/Data/Application";
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray<NSString *> *uuids = [fm contentsOfDirectoryAtPath:containersDir error:nil];
        int injectedCount = 0;
        for (NSString *sub in uuids) {
            NSString *appDataDir = [containersDir stringByAppendingPathComponent:sub];
            NSString *metaPath = [appDataDir stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
            if ([fm fileExistsAtPath:metaPath]) {
                NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
                NSString *bid = meta[@"MCMMetadataIdentifier"];
                if (bid) {
                    NSString *lower = [bid lowercaseString];
                    if ([lower containsString:@"sidestore"] ||
                        [lower containsString:@"livecontainer"] ||
                        [lower containsString:@"altstore"] ||
                        [lower containsString:@"stik.store"]) {
                        NSString *docsDir = [appDataDir stringByAppendingPathComponent:@"Documents"];
                        [fm createDirectoryAtPath:docsDir withIntermediateDirectories:YES attributes:nil error:nil];

                        NSArray<NSString *> *targetFiles = @[
                            @"pairingFile.plist",
                            [NSString stringWithFormat:@"%@.plist", udid],
                            @"PairingFile_Lockdown.plist"
                        ];
                        for (NSString *fname in targetFiles) {
                            NSString *fpath = [docsDir stringByAppendingPathComponent:fname];
                            [plistData writeToFile:fpath atomically:YES];
                            chmod([fpath UTF8String], 0644);
                        }
                        printf("  [+] Injected into: %s\n", [bid UTF8String]);
                        injectedCount++;
                    }
                }
            }
        }
        if (injectedCount > 0) {
            printf("[+] Successfully configured %d app container(s).\n", injectedCount);
        }

        p_X509_free(host_cert);
        p_X509_free(root_cert);
        p_EVP_PKEY_free(host_pkey);
        p_EVP_PKEY_free(root_pkey);
    }
    return 0;
}
