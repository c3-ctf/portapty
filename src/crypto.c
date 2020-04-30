#include "common.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>

int gen_self_signed_cert(uint8_t buf[PORTAPTY_CERT_BUF_LEN], mbedtls_pk_context* key, mbedtls_hmac_drbg_context* rng) {
  int ret;

  mbedtls_mpi mpi;
  mbedtls_x509write_cert crt;

  mbedtls_mpi_init(&mpi);
  mbedtls_x509write_crt_init(&crt);

  mbedtls_mpi_read_string(&mpi, 10, "31337");

  mbedtls_x509write_crt_set_version             (&crt, MBEDTLS_X509_CRT_VERSION_3);
  mbedtls_x509write_crt_set_md_alg              (&crt, MBEDTLS_MD_SHA256);
  if ((ret = mbedtls_x509write_crt_set_validity (&crt, "20010101000000", "20301231235959")))
    goto finish;
  if ((ret = mbedtls_x509write_crt_set_serial(&crt, &mpi)))
    goto finish;
  if ((ret = mbedtls_x509write_crt_set_subject_name(&crt, "CN=Cert,O=mbed TLS,C=UK")))
    goto finish;
  if ((mbedtls_x509write_crt_set_issuer_name(&crt, "CN=CA,O=mbed TLS,C=UK")))
     goto finish;

  mbedtls_x509write_crt_set_subject_key         (&crt, key);
  mbedtls_x509write_crt_set_issuer_key          (&crt, key);

  // Here ret is actually the offset from the end where the data is stored
  //
  // This is stupid and dumb, so I fixed it
  if ((ret = mbedtls_x509write_crt_der(&crt, buf, PORTAPTY_CERT_BUF_LEN, mbedtls_hmac_drbg_random, rng)) < 0)
    goto finish;
  memmove(buf, buf + PORTAPTY_CERT_BUF_LEN - ret, ret);
finish:
  mbedtls_x509write_crt_free(&crt);
  mbedtls_mpi_free(&mpi);

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

void get_hash(char str[PORTAPTY_HASH_STR_LEN], const uint8_t* data, size_t data_len) {
  uint8_t hash_bytes[160/8];
  mbedtls_ripemd160(data, data_len, hash_bytes);
  size_t len_;
  mbedtls_base64_encode((uint8_t*)str, PORTAPTY_HASH_STR_LEN, &len_, hash_bytes, 160/8);
}
