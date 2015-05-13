#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/conf.h>

#define LOG(...) \
    fprintf(stderr, __VA_ARGS__)

static int socket_setsockblock(int sock, int block)
{
    long arg;

    if ((arg = fcntl(sock, F_GETFL, NULL)) < 0) {
        return -1;
    }

    if (block) {
        arg &= (~O_NONBLOCK);
    } else {
        arg |= O_NONBLOCK;
    }

    if (fcntl(sock, F_SETFL, arg) < 0) {
        LOG("failed to set flags: %m");
        return -1;
    }

    return 0;
}

static int resolve_host(const char *host, struct in_addr *addr)
{
    struct hostent *h = gethostbyname(host);
    if (!h)
    {
        LOG("failed to resolve %s: %s\n", hstrerror(h_errno));
        return -1;
    }

    LOG("official name: %s\n", h->h_name);
    LOG("add type: %s\n", (h->h_addrtype == AF_INET) ? "IPv4" : "IPv6");

    *addr = *((struct in_addr *)h->h_addr);

    LOG("resolved to: %s\n", inet_ntoa(*addr));

    return 0;
}

static int do_connect(const char *host, int port)
{
    struct in_addr addr;

    if (resolve_host(host, &addr))
    {
        LOG("faled to resolve host\n");
        exit(1);
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in in_addr;
    in_addr.sin_family = AF_INET;
    in_addr.sin_port = htons(port);
    in_addr.sin_addr = addr;

    int cret = connect(sock, (struct sockaddr *)&in_addr, sizeof(in_addr));
    if (cret == -1)
    {
        LOG("failed to connect: %m\n");
        return -1;
    }
    else
    {
        LOG("connected on fd: %d\n", sock);
    }
    return sock;
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
  printf("verify called\n");
  return 1;
}

static int isdir(const char *path)
{
    struct stat st;

    if (stat(path, &st) != -1)
    {
        if (S_ISDIR(st.st_mode))
            return 1;
        return 0;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    const char *host = NULL;
    int port = 0;

    if (argc < 3)
    {
        LOG("usage: %s <host> <port>\n", program_invocation_short_name);
        exit(1);
    }
    host = argv[1];
    port = atoi(argv[2]);

    LOG("connect to %s:%d\n", host, port);
    int fd = do_connect(host, port);
    if (fd == -1)
    {
        exit(1);
    }

    /* socket_setsockblock(fd, 0); */

    LOG("connected: %d\n", fd);
    OPENSSL_config(NULL);

    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    assert(ctx != NULL);

    if (argc == 4)
    {
        char *cacert = NULL;
        char *capath = NULL;

        if (isdir(argv[3]))
            capath = argv[3];
        else
            cacert = argv[3];

        LOG("CA path: %s cert: %s\n", capath, cacert);
        int status = SSL_CTX_load_verify_locations(ctx, cacert, capath);
        if (status == 0)
        {
            LOG("failed to CA files");
            exit(1);
        }

    }

    printf("SSL options: %08x\n", SSL_CTX_get_options(ctx));
    SSL *ssl = SSL_new(ctx);
    assert(ssl != NULL);

    SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_callback);
    SSL_set_fd(ssl, fd);

    while(1) {
        int sslret = SSL_connect(ssl);
        if (sslret == 1)
        {
            printf("proto version: %s\n", SSL_get_version(ssl));
            printf("cipher: %s\n", SSL_get_cipher(ssl));

            int vres = SSL_get_verify_result(ssl);
            printf("verify result: %d\n", vres);
            if (vres != X509_V_OK)
            {
                int err = SSL_get_error(ssl, vres);
                printf("SSL verify error: %d\n", err);
            }
            break;
        }
        else
        {
            int sslerr = SSL_get_error(ssl, sslret);
            if (sslerr != SSL_ERROR_WANT_READ && sslerr != SSL_ERROR_WANT_WRITE)
            {
                LOG("SSL connect failed: %d\n", sslret);
                LOG("failed to perform handshake: %d\n", SSL_get_error(ssl, sslret));
                break;
            }
            else
            {
                LOG("SSL error: %d\n", sslerr);
            }
        }
    }


    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    close(fd);
    return 0;
}
