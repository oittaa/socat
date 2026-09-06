/* Optional Linux/macOS benchmark client for classic socat's DTLS 1.2 endpoint.
 * Build: cc -O3 -Wall -Wextra -Werror openssl-dtls-client.c -lssl -lcrypto -o client
 * Uses the scripts/benchclient flags and JSON contract; never linked into socat.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static void die(const char *message) {
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
    puts("{\"ok\":false,\"error\":\"OpenSSL DTLS client failed; see stderr\"}");
    exit(1);
}

static int number(const char *s) {
    char *end;
    long n = strtol(s, &end, 10);
    if (!*s || *end || n < 0 || n > 1000000) die("invalid numeric option");
    return (int)n;
}

static double now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) die("clock_gettime failed");
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static SSL *dial(SSL_CTX *ctx, const struct sockaddr_in *peer, const char *name) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct timeval timeout = {.tv_sec = 10};
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
        connect(fd, (const struct sockaddr *)peer, sizeof(*peer))) die("UDP connect failed");
    SSL *ssl = SSL_new(ctx);
    BIO *bio = BIO_new_dgram(fd, BIO_CLOSE);
    if (!ssl || !bio || BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (void *)peer) <= 0)
        die("SSL/BIO setup failed");
    SSL_set_bio(ssl, bio, bio);
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
    if (SSL_set_mtu(ssl, 1200) <= 0 || !SSL_set1_host(ssl, name) ||
        !SSL_set_tlsext_host_name(ssl, name)) die("SSL parameters failed");
    if (SSL_connect(ssl) != 1 || SSL_get_verify_result(ssl) != X509_V_OK ||
        SSL_version(ssl) != DTLS1_2_VERSION || SSL_session_reused(ssl))
        die("verified full DTLS 1.2 handshake failed");
    return ssl;
}

static void close_connection(SSL *ssl) {
    /* Send close_notify once, without waiting for the peer's reply. */
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

static void echo(SSL *ssl, const unsigned char *payload, int size) {
    unsigned char reply[1024];
    if (SSL_write(ssl, payload, size) != size || SSL_read(ssl, reply, sizeof(reply)) != size ||
        memcmp(payload, reply, (size_t)size)) die("echo failed");
}

static int compare(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    const char *mode = "probe", *addr = NULL, *ca = NULL, *name = "localhost";
    int n = 20000, warmup = 1000, size = 64;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 == argc) die("missing option value");
        const char *key = argv[i], *value = argv[i + 1];
        if (!strcmp(key, "-mode")) mode = value;
        else if (!strcmp(key, "-addr")) addr = value;
        else if (!strcmp(key, "-ca")) ca = value;
        else if (!strcmp(key, "-servername")) name = value;
        else if (!strcmp(key, "-n")) n = number(value);
        else if (!strcmp(key, "-warmup")) warmup = number(value);
        else if (!strcmp(key, "-size")) size = number(value);
        else if (strcmp(key, "-proto") || strcmp(value, "dtls")) die("unknown option");
    }
    if (!addr || strncmp(addr, "127.0.0.1:", 10) || !ca || n < 1 || size < 1 || size > 1024 ||
        (strcmp(mode, "probe") && strcmp(mode, "rr") && strcmp(mode, "hs")))
        die("expected loopback address, CA, probe/rr/hs mode, n > 0, size 1..1024");
    int port = number(addr + 10);
    if (port < 1 || port > 65535) die("invalid port");
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    if (inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr) != 1) die("invalid address");
    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION) ||
        !SSL_CTX_load_verify_locations(ctx, ca, NULL)) die("SSL context failed");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    unsigned char payload[1024];
    for (int i = 0; i < size; i++) payload[i] = (unsigned char)i;

    if (!strcmp(mode, "probe")) {
        SSL *ssl = dial(ctx, &peer, name);
        const char *group = SSL_group_to_name(ssl, SSL_get_negotiated_group(ssl));
        printf("{\"ok\":true,\"version\":\"DTLS 1.2\",\"cipher\":\"%s\",\"group\":\"%s\"}\n",
               SSL_CIPHER_standard_name(SSL_get_current_cipher(ssl)), group ? group : "");
        close_connection(ssl);
    } else if (!strcmp(mode, "rr")) {
        SSL *ssl = dial(ctx, &peer, name);
        double *samples = calloc((size_t)n, sizeof(*samples));
        if (!samples) die("allocation failed");
        for (int i = 0; i < warmup; i++) echo(ssl, payload, size);
        double start = now();
        for (int i = 0; i < n; i++) {
            double t = now();
            echo(ssl, payload, size);
            samples[i] = (now() - t) * 1e6;
        }
        double elapsed = now() - start;
        close_connection(ssl);
        qsort(samples, (size_t)n, sizeof(*samples), compare);
        printf("{\"ok\":true,\"elapsed_s\":%.9f,\"msgs_s\":%.6f,"
               "\"rtt_us\":{\"median\":%.6f,\"p99\":%.6f,\"min\":%.6f,\"max\":%.6f}}\n",
               elapsed, n / elapsed, samples[(n - 1) / 2], samples[(n - 1) * 99 / 100],
               samples[0], samples[n - 1]);
        free(samples);
    } else {
        double start = 0;
        for (int i = -warmup; i < n; i++) {
            if (i == 0) start = now();
            SSL *ssl = dial(ctx, &peer, name);
            echo(ssl, payload, 1);
            close_connection(ssl);
        }
        double elapsed = now() - start;
        printf("{\"ok\":true,\"elapsed_s\":%.9f,\"hs_s\":%.6f}\n", elapsed, n / elapsed);
    }
    SSL_CTX_free(ctx);
    return 0;
}
