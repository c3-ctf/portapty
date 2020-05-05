#pragma once


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

#define PORTAPTY_PRINTF_NORMAL(...) printf("[shell   ] " __VA_ARGS__)
#define PORTAPTY_PRINTF_UPGRADED(...) printf("[portapty] " __VA_ARGS__)

#ifdef PORTAPTY_QUIET
#define PORTAPTY_PRINTF_ERR(...)
#define PORTAPTY_PRINTF_WARN(...)
#define PORTAPTY_PRINTF_INFO(...)
#else
#define PORTAPTY_PRINTF_ERR(...)      printf("[ERROR   ] " __VA_ARGS__)
#define PORTAPTY_PRINTF_WARN(...)     printf("[WARNING ] " __VA_ARGS__)
#define PORTAPTY_PRINTF_INFO(...)     printf("[INFO    ] " __VA_ARGS__)
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
void portapty_read_loop(mbedtls_ssl_context* ssl_ctx, int client_fd, int pty_fd);

/// @param args: a null terminated array of arguments, with proper quotation and escapes
void upgrade(int fd, char const* const* args);

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

// The handles to the source (as global mutable variables filled in main).
// mmap means almost no extra memory is used
//
// There is no 'nicer' way of doing this, except for the hateful pass-the-parcel approach (see Rust)
//
// Yes, this can be spoofed, but only by a) the owner of the executable, or b) the caller
//
// If that is a problem, then why are you running user-writable executables as root?
extern int source_fd;
extern const uint8_t* source_buf;
extern off_t source_len;

// The infimum posix ARG_MAX
#define PORTAPTY_CMD_WIDTH 4096

union handshake_config {
  struct {
    mbedtls_x509_crt* crt;
    mbedtls_pk_context* pk;
    const char* cmdline;
  } server;

  struct {
    const uint8_t (*fingerprint)[PORTAPTY_HASH_LEN];
    char (*cmdline_ret)[PORTAPTY_CMD_WIDTH];
  } client;
};

// This API is sadistic: it took me hours to work out that a mbedtls_ssl_config allocated in this
// function would cause weird stack corruptions 5 frames down.
int do_handshake(int sock, mbedtls_ssl_context* ssl_ctx, mbedtls_ssl_config* ssl_cfg,
                 mbedtls_hmac_drbg_context* rng, int is_server, const union handshake_config* cfg);

int run_server(const char** eps_elems, size_t eps_len,
               const char* key_path, const char* cert_path, const char* driver, const char* cmd);
int run_client(const char** eps_elems, size_t eps_len, const char* cert_hash_b64);
int run_gen(const char* key_path, const char* cert_path);
