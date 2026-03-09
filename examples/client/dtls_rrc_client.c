/* dtls_rrc_client.c
 *
 * Minimal DTLS 1.2 + CID + RRC client for interop testing with Californium.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif

#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(WOLFSSL_DTLS) && defined(WOLFSSL_DTLS_CID) && \
    defined(WOLFSSL_DTLS_CID_RRC)

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 6684

static unsigned int psk_client_cb(WOLFSSL* ssl, const char* hint,
    char* identity, unsigned int id_max_len, unsigned char* key,
    unsigned int key_max_len)
{
    static const char psk_id[] = "Client_identity";
    static const char psk_key[] = "secretPSK";
    size_t id_len = sizeof(psk_id) - 1;
    size_t key_len = sizeof(psk_key) - 1;

    (void)ssl;
    (void)hint;

    if (id_max_len <= id_len || key_max_len < key_len)
        return 0;

    XMEMCPY(identity, psk_id, id_len);
    identity[id_len] = '\0';
    XMEMCPY(key, psk_key, key_len);
    return (unsigned int)key_len;
}

static void hex_dump(const unsigned char* buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static int make_coap_get_rrc(unsigned char* out, unsigned short mid,
    unsigned char token)
{
    out[0] = 0x41; /* CoAP v1, CON, token length 1 */
    out[1] = 0x01; /* GET */
    out[2] = (unsigned char)(mid >> 8);
    out[3] = (unsigned char)(mid & 0xFF);
    out[4] = token;
    out[5] = 0xB3; /* Uri-Path, len=3 */
    out[6] = 'r';
    out[7] = 'r';
    out[8] = 'c';
    return 9;
}

static int do_request(WOLFSSL* ssl, const char* label, unsigned short mid,
    unsigned char token)
{
    unsigned char req[9];
    unsigned char resp[2048];
    int req_len;
    int ret;
    int err;

    req_len = make_coap_get_rrc(req, mid, token);
    printf("  > %s send %d bytes\n", label, req_len);
    ret = wolfSSL_write(ssl, req, req_len);
    if (ret <= 0) {
        err = wolfSSL_get_error(ssl, ret);
        printf("  ! wolfSSL_write failed: %d\n", err);
        return -1;
    }

    do {
        ret = wolfSSL_read(ssl, resp, (int)sizeof(resp));
        if (ret > 0)
            break;
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);

    if (ret <= 0) {
        printf("  ! wolfSSL_read failed: %d\n", err);
        return -1;
    }

    printf("  < %s recv %d bytes: ", label, ret);
    hex_dump(resp, ret);
    return 0;
}

int main(int argc, char** argv)
{
    const char* host = DEFAULT_HOST;
    int port = DEFAULT_PORT;
    int fd = -1;
    int ret;
    int err;
    struct sockaddr_in addr;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char err_buf[80];
    unsigned char cid[4] = { 0x01, 0x02, 0x03, 0x04 };
    static const char* const ciphers[] = {
        "ECDHE-PSK-AES128-GCM-SHA256",
        "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
        "PSK-AES128-GCM-SHA256",
        "TLS_PSK_WITH_AES_128_GCM_SHA256",
        "PSK-AES128-CCM-8",
        "TLS_PSK_WITH_AES_128_CCM_8",
        "ECDHE-PSK-AES128-CBC-SHA256",
        "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"
    };
    size_t i;
    int cipher_ok = 0;

    if (argc > 1)
        host = argv[1];
    if (argc > 2)
        port = atoi(argv[2]);

    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    if (ctx == NULL) {
        printf("wolfSSL_CTX_new failed\n");
        ret = 1;
        goto exit;
    }

    /* Work around CID interop issues in CBC+EtM path. */
    (void)wolfSSL_CTX_AllowEncryptThenMac(ctx, 0);

    for (i = 0; i < sizeof(ciphers) / sizeof(ciphers[0]); i++) {
        ret = wolfSSL_CTX_set_cipher_list(ctx, ciphers[i]);
        if (ret == WOLFSSL_SUCCESS) {
            fprintf(stderr, "  . Cipher list: %s\n", ciphers[i]);
            cipher_ok = 1;
            break;
        }
    }
    if (!cipher_ok) {
        printf("wolfSSL_CTX_set_cipher_list failed for all candidates\n");
        ret = 1;
        goto exit;
    }

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_CTX_set_psk_client_callback(ctx, psk_client_cb);

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        printf("wolfSSL_new failed\n");
        ret = 1;
        goto exit;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        ret = 1;
        goto exit;
    }

    XMEMSET(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        printf("invalid host: %s\n", host);
        ret = 1;
        goto exit;
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect");
        ret = 1;
        goto exit;
    }

    wolfSSL_set_fd(ssl, fd);

    ret = wolfSSL_dtls_cid_rrc_use(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        printf("wolfSSL_dtls_cid_rrc_use failed: %d\n", ret);
        ret = 1;
        goto exit;
    }

    ret = wolfSSL_dtls_cid_set(ssl, cid, sizeof(cid));
    if (ret != WOLFSSL_SUCCESS) {
        printf("wolfSSL_dtls_cid_set failed: %d\n", ret);
        ret = 1;
        goto exit;
    }

    printf("  . Performing DTLS handshake...\n");
    do {
        ret = wolfSSL_connect(ssl);
        if (ret == WOLFSSL_SUCCESS)
            break;
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);

    if (ret != WOLFSSL_SUCCESS) {
        printf("  ! wolfSSL_connect failed: %d (%s)\n", err,
            wolfSSL_ERR_error_string(err, err_buf));
        ret = 1;
        goto exit;
    }

    printf("  . RRC negotiated: %s\n",
        wolfSSL_dtls_cid_rrc_is_enabled(ssl) ? "yes" : "no");

    if (do_request(ssl, "req1", 0x1001, 0x11) != 0) {
        ret = 1;
        goto exit;
    }

    printf("  . Waiting 7s to expire NAT mapping...\n");
    sleep(7);

    if (do_request(ssl, "req2", 0x1002, 0x22) != 0) {
        ret = 1;
        goto exit;
    }

    if (do_request(ssl, "req3", 0x1003, 0x33) != 0) {
        ret = 1;
        goto exit;
    }

    ret = 0;

exit:
    if (ssl != NULL) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    if (fd >= 0)
        close(fd);
    wolfSSL_Cleanup();
    return ret;
}

#else
int main(void)
{
    printf("Required features not enabled.\n");
    return 0;
}
#endif
