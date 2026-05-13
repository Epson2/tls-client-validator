#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TRUSTED_ROOT_DIR "trusted_root"
#define EXPECTED_CN "Secure Coding 2026 TLS Server"
#define CLIENT_MESSAGE "hello\n"
#define BUF_SIZE 4096

/*
 * Simple TLS client used for secure coding exercises.
 * - Loads trusted root CA certificates from `TRUSTED_ROOT_DIR`.
 * - Connects to a server provided as IP and port on the command line.
 * - Verifies the server certificate chain, validity period, and CN.
 * - Sends a short `CLIENT_MESSAGE` and prints the server response.
 */

static void cleanup(int sockfd, SSL *ssl, SSL_CTX *ctx, X509 *cert) {
    /* Free allocated resources, safe to call at any point. */
    if (cert) {
        X509_free(cert);
    }
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    if (sockfd >= 0) {
        close(sockfd);
    }
}

static int load_trusted_roots(X509_STORE *store, const char *dirpath) {
    DIR *dir;
    struct dirent *entry;
    char path[1024];
    int loaded_any = 0;

    /* Open the directory containing PEM-encoded trusted root CA files. */
    dir = opendir(dirpath);
    if (!dir) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(path, sizeof(path), "%s/%s", dirpath, entry->d_name);

        /* Try to open each file and load any PEM certificates found. */
        FILE *fp = fopen(path, "r");
        if (!fp) {
            continue;
        }

        while (1) {
            /* Read successive PEM certificates from the file. */
            X509 *ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
            if (!ca_cert) {
                ERR_clear_error();
                break;
            }

            /* Add certificate to store; ignore duplicates, treat other errors as fatal. */
            if (X509_STORE_add_cert(store, ca_cert) == 1) {
                loaded_any = 1;
            } else {
                unsigned long err = ERR_peek_last_error();
                if (ERR_GET_REASON(err) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                    X509_free(ca_cert);
                    fclose(fp);
                    closedir(dir);
                    return 0;
                }
                ERR_clear_error();
            }

            X509_free(ca_cert);
        }

        fclose(fp);
    }

    closedir(dir);
    return loaded_any;
}

static int extract_cn(X509 *cert, char *buf, size_t buflen) {
    X509_NAME *subject;
    int len;
    /* Extract the Common Name (CN) from the certificate subject. */
    subject = X509_get_subject_name(cert);
    if (!subject) {
        return 0;
    }

    len = X509_NAME_get_text_by_NID(subject, NID_commonName, buf, (int)buflen);
    if (len < 0 || (size_t)len >= buflen) {
        return 0;
    }

    return 1;
}

static int get_not_after_string(X509 *cert, char *buf, size_t buflen) {
    const ASN1_TIME *not_after;
    BIO *bio;
    int n;
    /* Convert certificate 'notAfter' ASN1_TIME into a human-readable string. */
    not_after = X509_get0_notAfter(cert);
    if (!not_after) {
        return 0;
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return 0;
    }

    if (ASN1_TIME_print(bio, not_after) != 1) {
        BIO_free(bio);
        return 0;
    }

    n = BIO_read(bio, buf, (int)buflen - 1);
    BIO_free(bio);

    if (n <= 0) {
        return 0;
    }

    buf[n] = '\0';
    return 1;
}

static int certificate_time_invalid(X509 *cert) {
    const ASN1_TIME *not_before;
    const ASN1_TIME *not_after;
    int before_cmp;
    int after_cmp;

    /* Ensure current time is within [notBefore, notAfter]. */
    not_before = X509_get0_notBefore(cert);
    not_after = X509_get0_notAfter(cert);

    if (!not_before || !not_after) {
        return 1;
    }

    before_cmp = X509_cmp_current_time(not_before);
    after_cmp = X509_cmp_current_time(not_after);

    if (before_cmp == 0 || after_cmp == 0) {
        return 1;
    }

    if (before_cmp == 1) {
        return 1;
    }

    if (after_cmp == -1) {
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    const char *server_ip;
    int port;
    int sockfd = -1;
    struct sockaddr_in addr;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    X509_STORE *store = NULL;
    X509 *cert = NULL;
    long verify_result;
    char cn[256];
    char expiry[256];
    char buffer[BUF_SIZE];
    int n;

    /* Expect: ./tls_client <server_ip> <port> */
    if (argc != 3) {
        return EXIT_FAILURE;
    }

    server_ip = argv[1];
    port = atoi(argv[2]);

    /* Initialize OpenSSL libraries and load error strings. */
    SSL_library_init();
    SSL_load_error_strings();
    OPENSSL_init_ssl(0, NULL);

    /* Create a TLS client context supporting modern TLS versions. */
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    /* Require peer verification and set minimum TLS version to 1.2. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* Create an X509 store and populate it with trusted root CAs. */
    store = X509_STORE_new();
    if (!store) {
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    if (!load_trusted_roots(store, TRUSTED_ROOT_DIR)) {
        X509_STORE_free(store);
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    /* Transfer ownership of the store to the SSL context. */
    SSL_CTX_set_cert_store(ctx, store);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);

    /* Parse the server IPv4 address string. */
    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) != 1) {
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    if (SSL_set_fd(ssl, sockfd) != 1) {
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    /* Perform the TLS handshake. SSL_connect returns 1 on success. */
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "ERROR: certificate not signed by trusted root CA\n");
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        fprintf(stderr, "ERROR: certificate not signed by trusted root CA\n");
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    /* Check OpenSSL's verification result for the peer certificate. */
    verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "ERROR: certificate not signed by trusted root CA\n");
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    /* Ensure certificate is not expired and not yet valid. */
    if (certificate_time_invalid(cert)) {
        if (!get_not_after_string(cert, expiry, sizeof(expiry))) {
            expiry[0] = '\0';
        }
        fprintf(stderr, "ERROR: certificate expired at %s\n", expiry);
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    if (!extract_cn(cert, cn, sizeof(cn))) {
        cn[0] = '\0';
    }

    /* Verify the certificate Common Name (CN) matches the expected value. */
    if (strcmp(cn, EXPECTED_CN) != 0) {
        fprintf(stderr, "ERROR: certificate CN mismatch\n(found: %s)\n", cn);
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    X509_free(cert);
    cert = NULL;

    if (SSL_write(ssl, CLIENT_MESSAGE, (int)strlen(CLIENT_MESSAGE)) <= 0) {
        cleanup(sockfd, ssl, ctx, cert);
        return EXIT_FAILURE;
    }

    n = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\0';
        fputs(buffer, stdout);
    }

    cleanup(sockfd, ssl, ctx, cert);
    return EXIT_SUCCESS;
}