#include "common.h"

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>

static int gen_self_signed_cert_inner(mbedtls_x509write_cert* crt, mbedtls_pk_context* key, mbedtls_hmac_drbg_context* rng) {
  int ret = 0;

  mbedtls_mpi mpi;
  mbedtls_mpi_init(&mpi);

  mbedtls_mpi_read_string(&mpi, 10, "31337");

  mbedtls_x509write_crt_set_version                 (crt, MBEDTLS_X509_CRT_VERSION_3);
  mbedtls_x509write_crt_set_md_alg                  (crt, MBEDTLS_MD_SHA256);
  if ((ret = mbedtls_x509write_crt_set_validity     (crt, "20010101000000", "20301231235959")))
    goto cleanup;
  if ((ret = mbedtls_x509write_crt_set_serial       (crt, &mpi)))
    goto cleanup;
  if ((ret = mbedtls_x509write_crt_set_subject_name (crt, "O=portapty")))
    goto cleanup;
  if ((mbedtls_x509write_crt_set_issuer_name        (crt, "O=portapty")))
     goto cleanup;

  mbedtls_x509write_crt_set_subject_key             (crt, key);
  mbedtls_x509write_crt_set_issuer_key              (crt, key);

  cleanup:
  mbedtls_mpi_free(&mpi);

  return ret;
}

int gen_self_signed_cert(uint8_t buf[PORTAPTY_CERT_BUF_LEN], mbedtls_pk_context* key, mbedtls_hmac_drbg_context* rng) {
  int ret = 0;

  mbedtls_x509write_cert crt;
  mbedtls_x509write_crt_init(&crt);

  if ((ret = gen_self_signed_cert_inner(&crt, key, rng)))
    goto cleanup;

  // Here ret is actually the offset from the end where the data is stored
  //
  // This is stupid and dumb, so I fixed it
  if ((ret = mbedtls_x509write_crt_der(&crt, buf, PORTAPTY_CERT_BUF_LEN, mbedtls_hmac_drbg_random, rng)) < 0)
    goto cleanup;
  memmove(buf, buf + PORTAPTY_CERT_BUF_LEN - ret, ret);

cleanup:
  mbedtls_x509write_crt_free(&crt);


  // Forward on error codes
  return ret;
}

int gen_key(mbedtls_pk_context* pk_ctx, mbedtls_hmac_drbg_context* rng) {
  int ret ;
  if ((ret = mbedtls_pk_setup(pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))))
    return ret;
  return mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256K1, mbedtls_pk_ec(*pk_ctx), mbedtls_hmac_drbg_random, rng);
}

void init_entropy(mbedtls_entropy_context* entropy) {
  mbedtls_entropy_init(entropy);
  // maybe /dev/random?
}

void init_drbg(mbedtls_hmac_drbg_context* ctx, mbedtls_entropy_context* entropy) {
   mbedtls_hmac_drbg_init(ctx);
   mbedtls_hmac_drbg_seed(ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), mbedtls_entropy_func, entropy, NULL, 0);
}

void get_hash(uint8_t hash[PORTAPTY_HASH_LEN], const uint8_t* data, size_t data_len) {
  mbedtls_sha256(data, data_len, hash, 0);
}

void encode_hash(char str[PORTAPTY_HASH_STR_LEN], const uint8_t hash[PORTAPTY_HASH_LEN]) {
  size_t len_;
  mbedtls_base64_encode((uint8_t*)str, PORTAPTY_HASH_STR_LEN, &len_, hash, PORTAPTY_HASH_LEN);
}
int decode_hash(uint8_t hash[PORTAPTY_HASH_LEN], const char str[PORTAPTY_HASH_STR_LEN]) {
  size_t len;
  int err;
  if ((err = mbedtls_base64_decode(hash, PORTAPTY_HASH_LEN, &len, (uint8_t*)str, strlen(str))))
    return err;
  else
    return len != PORTAPTY_HASH_LEN;
}


static void ssl_dbg( void *ctx, int level,
                      const char *file, int line,
                      const char *str ) {
    const char *p, *basename;

    /* Extract basename from file */
    for( p = basename = file; *p != '\0'; p++ )
        if( *p == '/' || *p == '\\' )
            basename = p + 1;

    PORTAPTY_PRINTF_INFO("%s:%04d: |%d| %s\n", basename, line, level, str );
}

static int sock_write(void* fd, const uint8_t* buf, size_t n) {
  return write((int)fd, buf, n);
}
static int sock_read(void* fd, uint8_t* buf, size_t n) {
  return read((int)fd, buf, n);
}

static int portapty_tls_verif(void* cfg_ptr, struct mbedtls_x509_crt* remote_crt, int depth, uint32_t* flags) {
  uint8_t hash[PORTAPTY_HASH_LEN];
  get_hash(hash, remote_crt->raw.p, remote_crt->raw.len);
#ifndef NDEBUG
  char str[PORTAPTY_HASH_STR_LEN] = {0};
  encode_hash(str, hash);
  PORTAPTY_PRINTF_INFO("connected to cert %s\n", str);
#endif

  // We return 0 on success
  return memcmp(((union handshake_config*)cfg_ptr)->client.fingerprint, hash, PORTAPTY_HASH_LEN)
      ? MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED
      : 0;
}

int do_handshake(int sock, mbedtls_ssl_context* ssl_ctx, mbedtls_ssl_config* ssl_cfg,
                 mbedtls_hmac_drbg_context* rng, int is_server, const union handshake_config* cfg) {
  int err;

  // Setup ssl config
  if ((err = mbedtls_ssl_config_defaults(ssl_cfg,
                              is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                              MBEDTLS_SSL_TRANSPORT_STREAM,
                              MBEDTLS_SSL_PRESET_DEFAULT))) {
    PORTAPTY_PRINTF_ERR("unable to init TLS config (err %i)\n", err);
    goto cleanup;
  }
  mbedtls_ssl_conf_rng(ssl_cfg, mbedtls_hmac_drbg_random, rng);
#ifndef NDEBUG
  mbedtls_ssl_conf_dbg(ssl_cfg, ssl_dbg, NULL);
#endif

  // Role-specific config
  if (is_server) {
    mbedtls_ssl_conf_ca_chain(ssl_cfg, cfg->server.crt, NULL);
    if ((err = mbedtls_ssl_conf_own_cert(ssl_cfg, cfg->server.crt, cfg->server.pk))) {
      char err_buf[256];
      mbedtls_strerror(err, err_buf, 256);
      PORTAPTY_PRINTF_ERR("unable to set cert (%s)\n", err_buf);
      goto cleanup;
    }
  }
  else {
    // This means that only our handler is called
    mbedtls_ssl_conf_authmode(ssl_cfg, MBEDTLS_SSL_VERIFY_OPTIONAL);
    if (cfg->client.fingerprint)
      mbedtls_ssl_conf_verify(ssl_cfg, portapty_tls_verif, (void*)cfg);
  }

  if ((err = mbedtls_ssl_setup(ssl_ctx, ssl_cfg))) {
    char err_buf[256];
    mbedtls_strerror(err, err_buf, 256);
    PORTAPTY_PRINTF_ERR("unable to set up TLS (%s)\n", err_buf);
    goto cleanup;
  }
  // Dunno, this is in the examples
  mbedtls_ssl_session_reset(ssl_ctx);
  // Feed in the client socket
  //
  // Yes, this could cause an error with more than 255 sockets on an 8-bit system
  //
  // screw you if you break this
  mbedtls_ssl_set_bio(ssl_ctx, (void*)(size_t)sock, sock_write, sock_read, NULL);

  // Now do what we came here for
  //
  // TODO: maybe drop back to shell if this screws up
  if ((err = mbedtls_ssl_handshake(ssl_ctx))) {
    PORTAPTY_PRINTF_ERR("TLS handshake failed (err %i)\n", err);
    goto cleanup;
  }

  // Now to send or receive the pty indicator and cmdline
  if (is_server) {
    mbedtls_ssl_write(ssl_ctx, &cfg->server.is_pty, 1);
    // Make little endian
    uint16_t len = strlen(cfg->server.cmdline);
    uint8_t le_len[2] = { len & 0xFF, len >> 8 };
    mbedtls_ssl_write(ssl_ctx, le_len, 2);
    mbedtls_ssl_write(ssl_ctx, (const uint8_t*)cfg->server.cmdline, len);
  }
  else {
    if (mbedtls_ssl_read(ssl_ctx, cfg->client.is_pty, 1) != 1) {
      err = 1; goto cleanup;
    }
    // Make little endian
    uint8_t le_len[2];
    if ((err = mbedtls_ssl_read(ssl_ctx, le_len, 2) < 2))
      goto cleanup;
    uint16_t len = (uint16_t)le_len[0] | ((uint16_t)le_len[1] << 8);
    // We need to leave a byte for the trailing null
    if (len >= PORTAPTY_CMD_WIDTH) {
      err = 1; goto cleanup;
    }
    if (mbedtls_ssl_read(ssl_ctx, (uint8_t*)*cfg->client.cmdline_ret, len) != len) {
      err = 1; goto cleanup;
    }
    (*cfg->client.cmdline_ret)[len] = 0;
  }

cleanup:
  return err;
}

int run_gen(const char* key_path, const char* cert_path) {
  int ret;

  mbedtls_entropy_context entropy;
  init_entropy(&entropy);

  mbedtls_hmac_drbg_context rng;
  init_drbg(&rng, &entropy);

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  mbedtls_x509write_cert crt;
  mbedtls_x509write_crt_init(&crt);

  // If we init it to null, then a malloc can always be safely performed
  char* pem_buf = NULL;

  if ((ret = gen_key(&pk, &rng))) {
    PORTAPTY_PRINTF_ERR("unable to generate key (err %i)\n", ret);
    goto cleanup;
  }

  if ((ret = gen_self_signed_cert_inner(&crt, &pk, &rng))) {
    PORTAPTY_PRINTF_ERR("unable to generate cert (err %i)\n", ret);
    goto cleanup;
  }

  // Now we have a cert and a key, we can re-export the DER as PEM
  FILE* file;
  pem_buf = malloc(PORTAPTY_CERT_PEM_LEN);

  // First we write the privkey
  {
    if ((ret = mbedtls_pk_write_key_pem(&pk, (uint8_t*)pem_buf, PORTAPTY_CERT_PEM_LEN))) {
      PORTAPTY_PRINTF_ERR("unable to make private key pem (err %i)\n", ret);
      goto cleanup;
    }
    if (!(file = fopen(key_path, "w"))) {
      PORTAPTY_PRINTF_ERR("unable to open private key file\n");
      goto cleanup;
    }
    fwrite(pem_buf, strlen(pem_buf), 1, file);
    fclose(file);
  }
  // Now the cert
  {
    if ((ret = mbedtls_x509write_crt_pem(&crt, (uint8_t*)pem_buf, PORTAPTY_CERT_PEM_LEN,
                                         mbedtls_hmac_drbg_random, &rng))) {
      PORTAPTY_PRINTF_ERR("unable to make cert pem (err %i)\n", ret);
      goto cleanup;
    }
    if (!(file = fopen(cert_path, "w"))) {
      PORTAPTY_PRINTF_ERR("unable to open private key file\n");
      goto cleanup;
    }
    fwrite(pem_buf, strlen(pem_buf), 1, file);
    fclose(file);
  }

  // Spread some goodwill
  PORTAPTY_PRINTF_INFO("keygen successful\n");

cleanup:
  free(pem_buf);
  mbedtls_x509write_crt_free(&crt);
  mbedtls_pk_free(&pk);
  mbedtls_hmac_drbg_free(&rng);
  mbedtls_entropy_free(&entropy);

  return ret;
}
