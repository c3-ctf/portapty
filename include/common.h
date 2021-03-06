#pragma once

#define _GNU_SOURCE
#include <pty.h>

#include <mbedtls/error.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ecp.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/base64.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORTAPTY_HELLO "portapty"
#define PORTAPTY_HELLO_LEN (sizeof(PORTAPTY_HELLO) - 1)

#define PORTAPTY_PRINTF_IMPORTANT(...) printf("[portapty] " __VA_ARGS__)
#define PORTAPTY_PRINTF_ERR(...)       printf("[ERROR   ] " __VA_ARGS__)

#ifdef PORTAPTY_QUIET
#define PORTAPTY_PRINTF_WARN(...)
#define PORTAPTY_PRINTF_INFO(...)
#else
#define PORTAPTY_PRINTF_WARN(...)      printf("[WARNING ] " __VA_ARGS__)
#define PORTAPTY_PRINTF_INFO(...)      printf("[INFO    ] " __VA_ARGS__)
#endif
#define WRITE_STRLIT(FD, STR) write(FD, STR, sizeof(STR) - 1)
#define WRITE_STR(FD, STR) write(FD, STR, strlen(STR))
#define PORTAPTY_CTRL_LEN 1024

#define PORTAPTY_POLL_PERIOD {.tv_sec = 0, .tv_usec = 1e6 };

//                                Max ip length + '\0' + "[]" + ':' + "65536"
#define PORTAPTY_SOCKADDR_STRLEN (INET6_ADDRSTRLEN     + 2    +  1  + 5      )
// The lack of a size argument is OK, as we have a nice macro up there ^
/// @returns number of bytes written to buf on success, or -errno on an error
int sockaddr2str(const struct sockaddr_in6* ep, char buf[PORTAPTY_SOCKADDR_STRLEN]);
/// @returns 0 on success, 1 on a bad address and 2 on a bad port
int str2sockaddr(struct sockaddr_in6* ep, const char* addr, const char* port);
/// @returns the socket on success
int portapty_bind_all(const char** eps_elems, size_t eps_len);
/// @returns the socket on success
int portapty_connect_first(const char** eps_elems, size_t eps_len);



enum portapty_poll_t {
  Portapty_Poll_Nothing     = 0b0000,

  Portapty_Poll_ClosedMask  = 0b0011,
  Portapty_Poll_FirstClosed = 0b0001,
  Portapty_Poll_SecondClosed= 0b0010,

  Portapty_Poll_FirstData   = 0b0100,
  Portapty_Poll_SecondData  = 0b1000,
};
enum portapty_poll_t portapty_poll(int fd_0, int fd_1);
void portapty_read_loop(mbedtls_ssl_context* ssl_ctx, int client_fd, int read_fd, int write_fd);
int portapty_fork_pipe(int* read_fd, int* write_fd, const char* cmdline);

/// @param args: a null terminated array of arguments, with proper quotation and escapes
void upgrade(int fd, const uint8_t* plod, size_t len, char const* const* args);

#define PORTAPTY_CERT_BUF_LEN 16384
#define PORTAPTY_CERT_PEM_LEN (16384 * 2)
int gen_self_signed_cert(uint8_t buf[PORTAPTY_CERT_BUF_LEN], mbedtls_pk_context* key, mbedtls_hmac_drbg_context* rng);
int gen_key(mbedtls_pk_context* key, mbedtls_hmac_drbg_context* rng);
void init_entropy(mbedtls_entropy_context* ctx);
void init_drbg(mbedtls_hmac_drbg_context*, mbedtls_entropy_context*);
#define PORTAPTY_HASH_LEN (256/8)
#define PORTAPTY_HASH_STR_LEN (44 + 1)
void get_hash(uint8_t hash[PORTAPTY_HASH_LEN], const uint8_t* data, size_t data_len);
void encode_hash(char str[PORTAPTY_HASH_STR_LEN], const uint8_t data[PORTAPTY_HASH_LEN]);
int decode_hash(uint8_t data[PORTAPTY_HASH_LEN], const char str[PORTAPTY_HASH_STR_LEN]);
int portapty_load(const char* file, const uint8_t** buf, size_t* len);

// The infimum posix ARG_MAX
#define PORTAPTY_CMD_WIDTH 4096

// Again, infimum host length
#define PORTAPTY_MAX_HOST_LEN 256

enum handshake_flags {
  Portapty_Handshake_IsPty   = 0b01,
  Portapty_Handshake_Persist = 0b10
} __attribute__((packed));

union handshake_config {
  struct {
    mbedtls_x509_crt* crt;
    mbedtls_pk_context* pk;
    const char* cmdline;
    char (*hostname_ret)[PORTAPTY_MAX_HOST_LEN];
    // Use a uint8_t for easier serialisation
    enum handshake_flags flags;
  } server;

  struct {
    const uint8_t (*fingerprint)[PORTAPTY_HASH_LEN];
    char (*cmdline_ret)[PORTAPTY_CMD_WIDTH];
    enum handshake_flags* flags;
    const char* hostname;
  } client;
};

// This API is sadistic: it took me hours to work out that a mbedtls_ssl_config allocated in this
// function would cause weird stack corruptions 5 frames down.
int do_handshake(int sock, mbedtls_ssl_context* ssl_ctx, mbedtls_ssl_config* ssl_cfg,
                 mbedtls_hmac_drbg_context* rng, int is_server,
                 const union handshake_config* cfg);

// TODO: dynamic plod selection based on remote arch
int run_server(const char** eps_elems, size_t eps_len, const char** advert_elems, size_t advert_len, const char* key_path, const char* cert_path,
               const char* driver, const char* cmd, enum handshake_flags flags, const char* plod);
int run_client(const char** eps_elems, size_t eps_len, const char* cert_hash_b64);
int run_gen(const char* key_path, const char* cert_path);
int run_relay(const char** bind_elems, size_t bind_len, const char** to_elems, size_t to_len);
