/* Lab adapter for OpenSSL demos/dtlslistenerecho's SSL_new_listener path.
 * Built by scripts/dtls13-lab.py against the pinned static libraries.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define DTLS_MAX_RETRANSMIT_TIMEOUT_US (8 * 1000000u)

static void die(const char *message)
{
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static unsigned int dtls_timer_cb(SSL *ssl, unsigned int timer_us)
{
    unsigned int next = (timer_us == 0) ? 1000000u : timer_us * 2;

    (void)ssl;
    if (next > DTLS_MAX_RETRANSMIT_TIMEOUT_US)
        next = DTLS_MAX_RETRANSMIT_TIMEOUT_US;
    return next;
}

static void apply_mtu(SSL *ssl, int mtu)
{
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
    if (SSL_set_mtu(ssl, (unsigned int)mtu) <= 0)
        die("SSL_set_mtu");
    if (!DTLS_set_link_mtu(ssl, mtu))
        die("DTLS_set_link_mtu");
}

static int wait_ssl(SSL *ssl, uint64_t events)
{
    SSL_POLL_ITEM item;
    struct timeval timeout;
    size_t result_count = 0;

    item.desc = SSL_as_poll_descriptor(ssl);
    item.events = events;
    item.revents = 0;
    if (!DTLSv1_get_timeout(ssl, &timeout)) {
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
    }
    if (!SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count))
        die("SSL_poll");
    return result_count > 0 && (item.revents & events) != 0;
}

static void handshake(SSL *ssl)
{
    for (;;) {
        int ret = SSL_accept(ssl);
        int err;

        if (ret == 1)
            return;
        err = SSL_get_error(ssl, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
            die("handshake");
        wait_ssl(ssl, err == SSL_ERROR_WANT_WRITE ? SSL_POLL_EVENT_W : SSL_POLL_EVENT_R);
    }
}

static void echo(SSL *ssl)
{
    unsigned char buf[16384];

    for (;;) {
        size_t n = 0, written = 0;
        int err;

        if (!wait_ssl(ssl, SSL_POLL_EVENT_R))
            continue;
        if (SSL_read_ex(ssl, buf, sizeof(buf), &n) == 1) {
            while (!SSL_write_ex(ssl, buf, n, &written)) {
                err = SSL_get_error(ssl, 0);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                    die("echo write");
            }
            continue;
        }
        err = SSL_get_error(ssl, 0);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            continue;
        if (err == SSL_ERROR_ZERO_RETURN)
            return;
        die("echo read");
    }
}

int main(int argc, char **argv)
{
    const char *listen = NULL, *cert = NULL, *key = NULL, *ca = NULL;
    const char *groups = NULL, *ciphers = NULL;
    int mtu = 0, i, fd = -1, flags;
    struct sockaddr_in addr;
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL, *conn = NULL;
    BIO *bio = NULL;
    STACK_OF(X509_NAME) *names;

    for (i = 1; i + 1 < argc; i += 2) {
        const char *k = argv[i], *v = argv[i + 1];

        if (strcmp(k, "-listen") == 0)
            listen = v;
        else if (strcmp(k, "-cert") == 0)
            cert = v;
        else if (strcmp(k, "-key") == 0)
            key = v;
        else if (strcmp(k, "-CAfile") == 0)
            ca = v;
        else if (strcmp(k, "-mtu") == 0)
            mtu = atoi(v);
        else if (strcmp(k, "-groups") == 0)
            groups = v;
        else if (strcmp(k, "-ciphersuites") == 0)
            ciphers = v;
        else
            die("unknown option");
    }
    if (!listen || strncmp(listen, "127.0.0.1:", 10) != 0 || !cert || !key || !ca ||
        mtu < 256 || mtu > 65535 || !groups || !ciphers)
        die("usage: -listen 127.0.0.1:port -cert pem -key pem -CAfile pem -mtu n -groups name -ciphersuites name");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)atoi(listen + 10));
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1 || addr.sin_port == 0)
        die("listen address");

    ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx ||
        !SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION) ||
        !SSL_CTX_set1_groups_list(ctx, groups) ||
        !SSL_CTX_set_ciphersuites(ctx, ciphers) ||
        SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx) ||
        !SSL_CTX_load_verify_locations(ctx, ca, NULL))
        die("SSL_CTX");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    names = SSL_load_client_CA_file(ca);
    if (names == NULL)
        die("client CA list");
    SSL_CTX_set_client_CA_list(ctx, names);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    flags = fcntl(fd, F_GETFL, 0);
    if (fd < 0 || flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
        bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        die("UDP bind");

    bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    listener = SSL_new_listener(ctx, 0);
    if (!bio || !listener || !BIO_up_ref(bio))
        die("SSL_new_listener");
    SSL_set0_rbio(listener, bio);
    SSL_set0_wbio(listener, bio);
    bio = NULL;
    if (SSL_set_blocking_mode(listener, 0) != 1 || SSL_listen(listener) != 1)
        die("SSL_listen");
    /* SSL_set_mtu fails on the listener SSL; HRR is small. */
    DTLS_set_timer_cb(listener, dtls_timer_cb);
    printf("ready\n");
    fflush(stdout);

    alarm(60);
    {
        SSL_POLL_ITEM item;
        struct timeval timeout;
        size_t result_count;

        item.desc = SSL_as_poll_descriptor(listener);
        item.events = SSL_POLL_EVENT_IC;
        while (conn == NULL) {
            item.revents = 0;
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;
            result_count = 0;
            if (!SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count))
                die("SSL_poll listener");
            if (result_count == 0 || (item.revents & SSL_POLL_EVENT_IC) == 0)
                continue;
            conn = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
            if (conn == NULL)
                ERR_print_errors_fp(stderr);
        }
    }
    apply_mtu(conn, mtu);
    DTLS_set_timer_cb(conn, dtls_timer_cb);
    handshake(conn);
    echo(conn);
    SSL_shutdown(conn);
    SSL_free(conn);
    SSL_free(listener);
    SSL_CTX_free(ctx);
    close(fd);
    return 0;
}
