#include "common.h"

#include <time.h>

int run_client(const char** eps_elems, size_t eps_len, const char* cert_hash_b64) {
#ifdef NDEBUG
  // Fork to background
  if (fork())
    exit(0);
  setsid();
#endif

  int err = 0;

  int client = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  // Allow IPv4
  int v6_only_val = 0;
  setsockopt(client, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only_val, sizeof(v6_only_val));

  for (int i = 0; i < eps_len; i += 2) {
    // Try to parse socket, and handle the many forms of screwup that arise thereof
    struct sockaddr_in6 ep;
    switch(str2sockaddr(&ep, eps_elems[i], eps_elems[i + 1])) {
      case 0: break;
      case 1: { PORTAPTY_PRINTF_WARN("could not parse ip %i\n", i / 2); } continue;
      case 2: { PORTAPTY_PRINTF_WARN("could not parse port %i\n", i / 2); } continue;
      default: { PORTAPTY_PRINTF_WARN("unknown error for ep %i\n", i / 2); } continue;
    }

    if (connect(client, (struct sockaddr*)&ep, sizeof(ep))) {
      err = errno;
      PORTAPTY_PRINTF_INFO("could not connect to ep %i (errno %i)\n", i / 2, err);
    }
    else
      goto connected;
  }
  // If we get here, then nothing connected
  PORTAPTY_PRINTF_ERR("could not connect to any ep\n");
  // We can return here because nothing has been allocated
  return 1;

connected: {}
  mbedtls_entropy_context entropy;
  init_entropy(&entropy);

  mbedtls_hmac_drbg_context rng;
  init_drbg(&rng, &entropy);

  mbedtls_ssl_config ssl_cfg;
  mbedtls_ssl_config_init(&ssl_cfg);

  mbedtls_ssl_context ssl_ctx;
  mbedtls_ssl_init(&ssl_ctx);

  uint8_t buf[256];
  if ((err = mbedtls_hmac_drbg_random(&rng, buf, 256))) {
    char err_buf[256];
    mbedtls_strerror(err, err_buf, 256);
    PORTAPTY_PRINTF_ERR("rng borked (%s)\n", err_buf);
    goto cleanup;
  }

  union handshake_config handshake_cfg;
  char cmdline[PORTAPTY_CMD_WIDTH];
  handshake_cfg.client.cmdline_ret = &cmdline;
  uint8_t is_pty;
  handshake_cfg.client.is_pty = &is_pty;

  if (cert_hash_b64) {
    uint8_t hash[PORTAPTY_HASH_LEN];
    if (decode_hash(hash, cert_hash_b64)) {
      PORTAPTY_PRINTF_ERR("could not decode hash (err %i)\n", err);
      goto cleanup;
    }
    handshake_cfg.client.fingerprint = &hash;
  }
  else
    handshake_cfg.client.fingerprint = NULL;

  if ((err = do_handshake(client, &ssl_ctx, &ssl_cfg, &rng, 0, &handshake_cfg))) {
    PORTAPTY_PRINTF_ERR("handshake failed (err %i)\n", err);
    goto cleanup;
  }

  if (is_pty) {
    PORTAPTY_PRINTF_INFO("starting pty\n");

    int master;

    char name[PATH_MAX];

    // Fork and exec the executable
    if (!forkpty(&master, name, NULL, NULL)) {
      // XXX: This will not wait for a flush before exiting, and will just sighup!
      execl("/bin/sh", "/bin/sh", "-c", cmdline, (char*)NULL);
      // Make a bit of noise if we can't exec sh
      abort();
    }

    portapty_read_loop(&ssl_ctx, client, master, master);
    close(master);
  }
  else {
    PORTAPTY_PRINTF_INFO("starting pipes\n");
    int read_fd, write_fd;
    if ((err = portapty_fork_pipe(&read_fd, &write_fd, cmdline))) {
      PORTAPTY_PRINTF_ERR("could not create pipes (errno %i)\n", err);
      goto cleanup;
    }

    portapty_read_loop(&ssl_ctx, client, read_fd, write_fd);
    close(read_fd); close(write_fd);
  }

  PORTAPTY_PRINTF_INFO("done\n");

cleanup:
  mbedtls_ssl_free(&ssl_ctx);
  mbedtls_ssl_config_free(&ssl_cfg);
  mbedtls_hmac_drbg_free(&rng);
  mbedtls_entropy_free(&entropy);

  return err;
}
