/*
 * Example of establishing a connection using OpenSSL
 * Copyright (C) 2015 Maciej Borzecki
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
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

#define LOG(...)                                \
    do {                                        \
        fprintf(stderr, __VA_ARGS__);           \
    } while(0)

/* if set to 1, ceritificates are alwayas accepted */
static int always_accept = 0;

/**
 * socket_setsockblock:
 * @sock: file descriptor
 * @block: block setting
 *
 * Set/unset O_NONBLOCK
 */
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

/**
 * resolve_host:
 * @host: hostname
 * @addr: in_addr to place the result at
 */
static int resolve_host(const char *host, struct in_addr *addr)
{
    assert(host);
    assert(addr);

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

/**
 * do_connect:
 * @host: hostname
 * @port: port
 *
 * Establish TCP connection to @host:@port. Return connected fd or -1.
 */
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

    LOG("connect...\n");
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
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    char buf[1024];
    int err;
    int depth;

    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));

    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);
    LOG("verify: %s\n", buf);
    LOG("   depth: %d preverify: %d err: %s\n",
        depth, preverify_ok, X509_verify_cert_error_string(err));

    if (preverify_ok == 0 && always_accept)
    {
        LOG("overriding verification\n");
        X509_STORE_CTX_set_error(ctx, X509_V_OK);
        preverify_ok = 1;
    }

    return preverify_ok;
}

/**
 * isdir:
 * @path: path
 *
 * Check if given path points to a directory
 */
static int isdir(const char *path)
{
    struct stat st;

    if (stat(path, &st) != -1)
    {
        if (S_ISDIR(st.st_mode))
            return 1;
        return 0;
    }
    /* return not-dir anyway */
    return 0;
}

int main(int argc, char *argv[])
{
    const char *host = NULL;
    int port = 0;

    if (argc < 3)
    {
        LOG("usage: %s <host> <port> [<ca-cert|ca-path>]\n",
            program_invocation_short_name);
        exit(1);
    }
    host = argv[1];
    port = atoi(argv[2]);

    LOG("connect to %s:%d\n", host, port);
    int fd = do_connect(host, port);
    if (fd == -1)
    {
        LOG("no connection\n");
        exit(1);
    }

    /* make socket non-blocking, to see
     * SSL_ERROR_WANT_READ/SSL_ERROR_WANT_WRITE interaction */
    socket_setsockblock(fd, 0);

    LOG("connected: %d\n", fd);

    /* init openssl */
    OPENSSL_config(NULL);
    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    assert(ctx != NULL);

    if (argc == 4)
    {
        const char *cacert = NULL;
        const char *capath = NULL;
        const char *path = argv[3];

        if (isdir(path))
            capath = path;
        else
            cacert = path;

        LOG("CA path: %s cert: %s\n", capath, cacert);
        int status = SSL_CTX_load_verify_locations(ctx, cacert, capath);
        if (status == 0)
        {
            LOG("failed to CA files");
            exit(1);
        }

    }

    printf("SSL options: 0x%08x\n", SSL_CTX_get_options(ctx));

    SSL *ssl = SSL_new(ctx);
    assert(ssl != NULL);

    /* enable peer verification */
    SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_callback);

    /* set file descriptor */
    SSL_set_fd(ssl, fd);

    int handshake_status = 0;
    while(1) {
        /* if socket was non-blockin we'd have to loop here and handle
         * SSL_ERROR_WANT_READ/SSL_ERROR_WANT_WRITE until the
         * handshake completes or fails */
        handshake_status = SSL_connect(ssl);
        if (handshake_status == 1)
        {
            break;
        }
        else
        {
            int sslerr = SSL_get_error(ssl, handshake_status);

            if (sslerr != SSL_ERROR_WANT_READ
                && sslerr != SSL_ERROR_WANT_WRITE)
            {
                LOG("SSL error: %d\n", sslerr);
                break;
            }
        }
    }

    if (handshake_status == 1)
    {
        /* handshake complete */
        LOG("proto version: %s\n", SSL_get_version(ssl));
        LOG("cipher: %s\n", SSL_get_cipher(ssl));

        int vres = SSL_get_verify_result(ssl);
        LOG("verify result: %s\n",
            X509_verify_cert_error_string(vres));
        if (vres != X509_V_OK)
        {
            int err = SSL_get_error(ssl, vres);
            LOG("SSL verify error: %d\n", err);
        }
        else
        {
            LOG("certificate verified\n");
        }
    }
    else
    {
        /* handshake terminated */
        LOG("SSL connect failed: %d\n", handshake_status);
        LOG("failed to perform handshake: %d\n",
            SSL_get_error(ssl, handshake_status));
    }


    /* shutdown should go through the same IO loop as SSL_connect() if
     * socket is non-blocking */
    SSL_shutdown(ssl);

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    close(fd);
    return 0;
}
