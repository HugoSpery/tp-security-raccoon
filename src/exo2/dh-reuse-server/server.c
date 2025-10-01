// Legacy TLS 1.2 DHE server with fixed DH key reuse using OpenSSL 1.0.2
// WARNING: Educational only, intentionally insecure.
// Usage (via entrypoint):
//   tls_vuln_server HOST PORT CERT KEY DHPARAM TLS_VERSION KX DH_REUSE_KEYS DH_FIXED_PRIV DEBUG

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

static volatile sig_atomic_t g_running = 1;
static void on_sigint(int sig) { (void)sig; g_running = 0; }

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap); fputc('\n', stderr); exit(1);
}

static void ssl_die(const char *msg) {
    fprintf(stderr, "ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

// Global DH object holding fixed private/public key for reuse
static DH *g_fixed_dh = NULL;

static int init_fixed_dh_from_params_legacy(const char *dhparam_path, unsigned long fixed_priv_ul, int debug) {
    BIO *bio = BIO_new_file(dhparam_path, "r");
    if (!bio) { fprintf(stderr, "Cannot open DH params: %s\n", dhparam_path); return 0; }
    DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!dh) { fprintf(stderr, "Failed to read DH params\n"); ERR_print_errors_fp(stderr); return 0; }

    // Compute pub = g^priv mod p using legacy field access (pre-1.1.0)
    BN_CTX *bnctx = BN_CTX_new(); if (!bnctx) { DH_free(dh); return 0; }

    BIGNUM *priv = BN_new(); BIGNUM *pub = BN_new();
    if (!priv || !pub) { if (priv) BN_free(priv); if (pub) BN_free(pub); BN_CTX_free(bnctx); DH_free(dh); return 0; }

    // priv := fixed_priv_ul mod (p-1); ensure >= 1
    BIGNUM *p_minus_1 = BN_dup(dh->p);
    BN_sub_word(p_minus_1, 1);
    BN_set_word(priv, fixed_priv_ul);
    BN_mod(priv, priv, p_minus_1, bnctx);
    if (BN_is_zero(priv)) BN_one(priv);

    if (BN_mod_exp(pub, dh->g, priv, dh->p, bnctx) != 1) {
        BN_free(pub); BN_free(priv); BN_free(p_minus_1); BN_CTX_free(bnctx); DH_free(dh); return 0;
    }

    // Assign into DH (legacy direct fields)
    if (dh->pub_key) BN_free(dh->pub_key);
    if (dh->priv_key) BN_free(dh->priv_key);
    dh->pub_key = pub;
    dh->priv_key = priv;

    g_fixed_dh = dh;

    if (debug) fprintf(stderr, "✓ Fixed DH prepared (legacy OpenSSL 1.0.2).\n");

    BN_free(p_minus_1);
    BN_CTX_free(bnctx);
    return 1;
}

static DH *tmp_dh_cb(SSL *ssl, int is_export, int keylength) {
    (void)ssl; (void)is_export; (void)keylength;
    // Return the same DH each time
    return g_fixed_dh;
}

static SSL_CTX *create_ctx_legacy(const char *cert, const char *key, const char *dhparam,
                                  const char *tls_ver, const char *kx, int dh_reuse, unsigned long dh_fixed_priv, int debug) {
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) ssl_die("SSL_CTX_new failed");

    // Enforce TLS1.2 only (disable others). TLS1.3 not supported in 1.0.2
    long opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
    SSL_CTX_set_options(ctx, opts);

    // Cipher list
    if (strcmp(kx, "DHE_RSA") == 0) {
        if (SSL_CTX_set_cipher_list(ctx, "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256") != 1)
            ssl_die("Failed to set DHE-RSA ciphers");
    } else if (strcmp(kx, "ECDHE_RSA") == 0) {
        if (SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256") != 1)
            ssl_die("Failed to set ECDHE-RSA ciphers");
    } else { // RSA
        if (SSL_CTX_set_cipher_list(ctx, "AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256") != 1)
            ssl_die("Failed to set RSA ciphers");
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1) ssl_die("load certificate");
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) ssl_die("load key");
    if (SSL_CTX_check_private_key(ctx) != 1) ssl_die("key mismatch");

    if (strcmp(kx, "DHE_RSA") == 0) {
        if (dh_reuse) {
            if (!init_fixed_dh_from_params_legacy(dhparam, dh_fixed_priv, debug))
                ssl_die("init_fixed_dh_from_params failed");
            // Explicitly allow reuse (clear SINGLE_DH_USE)
            long cur = SSL_CTX_get_options(ctx);
            cur &= ~SSL_OP_SINGLE_DH_USE;
            SSL_CTX_clear_options(ctx, SSL_OP_SINGLE_DH_USE);
            // Set callback to return the same DH with fixed priv/pub
            SSL_CTX_set_tmp_dh_callback(ctx, tmp_dh_cb);
        } else {
            BIO *bio = BIO_new_file(dhparam, "r"); if (!bio) ssl_die("open dhparam");
            DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL); BIO_free(bio);
            if (!dh) ssl_die("read dhparam");
            if (SSL_CTX_set_tmp_dh(ctx, dh) != 1) ssl_die("set_tmp_dh");
            DH_free(dh);
            SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
        }
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    return ctx;
}

static int create_listen_socket(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket: %s", strerror(errno));
    int yes = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) { close(fd); die("inet_pton %s", host); }
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); die("bind: %s", strerror(errno)); }
    if (listen(fd, 128) < 0) { close(fd); die("listen: %s", strerror(errno)); }
    return fd;
}

static void handle_client(SSL *ssl, const char *desc, int reuse) {
    if (SSL_accept(ssl) <= 0) { ERR_print_errors_fp(stderr); return; }
    char body[256];
    int n = snprintf(body, sizeof(body),
        "Legacy TLS 1.2 DHE server\nConfig: %s\nDH reuse: %s\n",
        desc, reuse ? "enabled" : "disabled");

    // Expose DH public key (Y_s) as header for verification
    char *y_hex = NULL;
    if (g_fixed_dh && g_fixed_dh->pub_key) {
        y_hex = BN_bn2hex(g_fixed_dh->pub_key);
    }

    char resp[1024];
    int m = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n%s%s%s\r\n%.*s",
        n, y_hex ? "X-DH-Pub: " : "", y_hex ? y_hex : "", y_hex ? "\r\n" : "", n, body);

    SSL_write(ssl, resp, m);
    if (y_hex) OPENSSL_free(y_hex);
}

int main(int argc, char **argv) {
    signal(SIGINT, on_sigint);
    if (argc < 10) {
        fprintf(stderr, "Usage: %s HOST PORT CERT KEY DHPARAM TLS_VERSION KX DH_REUSE_KEYS DH_FIXED_PRIV DEBUG\n", argv[0]);
        return 1;
    }
    const char *host = argv[1];
    int port = atoi(argv[2]);
    const char *cert = argv[3];
    const char *key = argv[4];
    const char *dhparam = argv[5];
    const char *tls_ver = argv[6]; (void)tls_ver; // Only TLS1.2 in legacy
    const char *kx = argv[7];
    int dh_reuse = atoi(argv[8]);
    unsigned long dh_fixed_priv = strtoul(argv[9], NULL, 10);
    int debug = (argc > 10) ? atoi(argv[10]) : 1;

    SSL_library_init(); SSL_load_error_strings(); OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = create_ctx_legacy(cert, key, dhparam, tls_ver, kx, dh_reuse, dh_fixed_priv, debug);

    int lfd = create_listen_socket(host, port);
    fprintf(stderr, "Listening on https://%s:%d (legacy OpenSSL)\n", host, port);

    char desc[128]; snprintf(desc, sizeof(desc), "TLS1.2 with %s", kx);

    while (g_running) {
        struct sockaddr_in cli; socklen_t clilen = sizeof(cli);
        int cfd = accept(lfd, (struct sockaddr *)&cli, &clilen);
        if (cfd < 0) { if (errno == EINTR) break; perror("accept"); continue; }
        SSL *ssl = SSL_new(ctx); if (!ssl) { close(cfd); continue; }
        SSL_set_fd(ssl, cfd);
        handle_client(ssl, desc, dh_reuse);
        SSL_shutdown(ssl); SSL_free(ssl); close(cfd);
    }

    if (g_fixed_dh) DH_free(g_fixed_dh);
    close(lfd); SSL_CTX_free(ctx); EVP_cleanup();
    return 0;
}
