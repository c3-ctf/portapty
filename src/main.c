#include "common.h"

int source_fd;
const uint8_t* source_buf;
off_t source_len;

int test() {
  uint8_t der[PORTAPTY_CERT_BUF_LEN];
  mbedtls_pk_context pk_ctx;
  mbedtls_entropy_context entropy_ctx;
  mbedtls_hmac_drbg_context drbg_ctx;
  init_entropy(&entropy_ctx);
  init_drbg(&drbg_ctx, &entropy_ctx);

  mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
  mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256K1, mbedtls_pk_ec(pk_ctx), mbedtls_hmac_drbg_random, &drbg_ctx);

  int len = gen_self_signed_cert(der, &pk_ctx, &drbg_ctx);

  char b64[PORTAPTY_HASH_STR_LEN];
  get_hash(b64, der, len);

  printf("%s\n", b64);
  return 0;
}

// Cyclic3's big TODO list of doom:
//
// * Set up channel multiplexing
// * Add routing for pivoting (because it will make me look cool)
// * Disconnect recovery or smth idk



int main(const int argc, const char* argv[]) {
  // We need to bind sighup ASAP, incase the shell closes
  signal(SIGHUP, SIG_IGN);
  signal(SIGINT, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);


  // Fork to background
//  if (!fork())
//    return 0;

  // First we need to parse the arguments:
  int is_client;
  const char* cert_str = NULL;
  const char* key_str = NULL;
  int eps_offset;
  int eps_len;

  {
    // If the args are obviously wrong, tell them
    if (argc < 4) {
      PORTAPTY_PRINTF_ERR("invalid number of arguments\n");
      goto print_help;
    }

    // Find ep list
    for (eps_offset = 2; eps_offset < argc - 1; ++eps_offset)
      if (!strcmp(argv[eps_offset], "--"))
        goto found_ep_list;
    // If we get here, we did not find the ep list delimiter
    PORTAPTY_PRINTF_ERR("missing ep list\n");
    goto print_help;

found_ep_list:
    ++eps_offset;

    if ((eps_len = argc - eps_offset) % 2) {
      PORTAPTY_PRINTF_ERR("mismatched eps\n");
      goto print_help;
    }

    // Get mode, and handle mode-specific options
    if (!strcmp(argv[1], "client")) {
      is_client = 1;
      if (eps_offset > 3) {
        key_str = argv[2];
      }
    }
    else if (!strcmp(argv[1], "server")) {
      is_client = 0;
      if (eps_offset > 4) {
        key_str = argv[2];
        cert_str = argv[3];
      }
    }
    else {
      PORTAPTY_PRINTF_ERR("invalid mode given\n");
      goto print_help;
    }
  }


  // Now we open the source file, and map it into memory
  source_fd = open(argv[0], O_RDONLY);
  source_len = lseek(source_fd, 0, SEEK_END);
  source_buf = mmap(0, source_len, PROT_READ, MAP_PRIVATE, source_fd, 0);

  int ret = 0;
  if (!strcmp(argv[1], "server")) {
    return run_server(argv + eps_offset, argc - eps_offset, key_str, cert_str);
  }
  else if (!strcmp(argv[1], "client"))
    return run_client(argv + eps_offset, argc - eps_offset, cert_str);

print_help:
  printf("%s <client|server> [INFO] -- ip port [ip port]...\n\n", argv[0]);
  printf("client: [cert hash]\n");
  printf("server: [key file] [cert file]\n");
  return 1;
}
