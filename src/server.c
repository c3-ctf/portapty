#include "common.h"

#include <mbedtls/error.h>

struct server_ctx {
  mbedtls_pk_context pk_ctx;
  mbedtls_x509_crt crt;
  const char* driver;
  const char* cmd;
};

static void handle_client(int client, struct server_ctx* ctx, const char* client_ep_str) {
  int err;

  // Since this will be forked, we need to make new rngs or we reuse entropy
  mbedtls_entropy_context entropy;
  init_entropy(&entropy);

  mbedtls_hmac_drbg_context rng;
  init_drbg(&rng, &entropy);

  mbedtls_ssl_config ssl_cfg;
  mbedtls_ssl_config_init(&ssl_cfg);

  mbedtls_ssl_context ssl_ctx;
  mbedtls_ssl_init(&ssl_ctx);

  union handshake_config cfg;
  cfg.server.pk = &ctx->pk_ctx;
  cfg.server.crt = &ctx->crt;
  // Default to /bin/sh
  cfg.server.cmdline = ctx->cmd ? ctx->cmd : "/bin/sh";

  if ((err = do_handshake(client, &ssl_ctx, &ssl_cfg, &rng, 1, &cfg))) {
    PORTAPTY_PRINTF_ERR("handshake failed (err %i)\n", err);
    goto cleanup;
  }

  int master, slave;
  char name[PATH_MAX];

  if (ctx->driver) {
    if (!forkpty(&master, name, NULL, NULL)) {
      execl("/bin/sh", "/bin/sh", "-c", ctx->driver, NULL);
      // Make some noise if we cannot exec sh
      abort();
    }
    PORTAPTY_PRINTF_UPGRADED("controlling on %s\n", name);
  }
  else {
    struct termios tty;
    cfmakeraw(&tty);

    if (openpty(&master, &slave, name, &tty, NULL)) {
      int err = errno;
      PORTAPTY_PRINTF_ERR("could not open pty (errno %i)\n", err);
      goto cleanup;
    }
    PORTAPTY_PRINTF_UPGRADED("%s available on %s\n", client_ep_str, name);
  }

  portapty_read_loop(&ssl_ctx, client, master);
  PORTAPTY_PRINTF_UPGRADED("closing %s (%s)\n", client_ep_str, name);

  cleanup:
  if (!ctx->driver) close(slave);
  close(master);
  mbedtls_ssl_free(&ssl_ctx);
  mbedtls_ssl_config_free(&ssl_cfg);
  mbedtls_hmac_drbg_free(&rng);
  mbedtls_entropy_free(&entropy);
}

int run_server(const char** eps_elems, size_t eps_len,
               const char* key_path, const char* cert_path, const char* driver, const char* cmd) {
  // Re-enable sigint
  signal(SIGINT, SIG_DFL);
  int err;
  int ret = 0;

  if (eps_len % 2) {
    PORTAPTY_PRINTF_ERR("unpaired ep\n");
    return 1;
  }

  const char** args = calloc( // This probably doesn't need to be a calloc
        1 + // 'cert'
        1 + // the hash
        1 + // 'eps'
        eps_len + // All the ips and ports
        1, // trailing null
        sizeof(char**)
  );
  int is_cert_ber_alloc = 0;

  // Crypto stuff to be filled in
  struct server_ctx ctx;
  mbedtls_pk_init(&ctx.pk_ctx);
  mbedtls_x509_crt_init(&ctx.crt);

  mbedtls_entropy_context entropy;
  init_entropy(&entropy);

  mbedtls_hmac_drbg_context rng;
  init_drbg(&rng, &entropy);

  char fingerprint[PORTAPTY_HASH_STR_LEN];

  // Now we have finished init'ing , we can get to work
  ctx.driver = driver;
  ctx.cmd = cmd;

  if (key_path) {
    uint8_t* buf;
    size_t len;
    if ((ret = mbedtls_pk_parse_keyfile(&ctx.pk_ctx, key_path, NULL))) {
      PORTAPTY_PRINTF_ERR("could not load private key (err %i)\n", ret);
      goto cleanup;
    }
  }
  // A cert without a key is non-sensical
  else if (cert_path) {
    PORTAPTY_PRINTF_ERR("certificate given without key\n");
    ret = 1; goto cleanup;
  }
  // If we have no private key, then we must generate one
  else {
    if ((ret = gen_key(&ctx.pk_ctx, &rng))) {
      PORTAPTY_PRINTF_ERR("key generation failed (err %i)\n", ret);
      goto cleanup;
    }
  }

  if (cert_path) {
    if ((ret = mbedtls_x509_crt_parse_file(&ctx.crt, cert_path))) {
      PORTAPTY_PRINTF_ERR("failed to parse certificate (err %i)\n", ret);
      goto cleanup;
    }
  }
  else {
    // I'm malloc'ing, as 16384 is a lot of bytes for the stack
    uint8_t* tmp_ber = malloc(PORTAPTY_CERT_BUF_LEN);
    int tmp_ber_len = gen_self_signed_cert(tmp_ber, &ctx.pk_ctx, &rng);
//    tmp_ber_len = 261;

    if (tmp_ber_len < 0 || (ret = mbedtls_x509_crt_parse_der_nocopy(&ctx.crt, tmp_ber, tmp_ber_len))) {
      PORTAPTY_PRINTF_ERR("failed to create self-signed certificate (%i)\n", ret ? ret : tmp_ber_len);
      // We failed, so we have to clean up the buffer ourselves
      free(tmp_ber);
      goto cleanup;
    }
    // We don't need to free tmp_ber, as it was stolen by the _nocopy function above
  }

  uint8_t hash_buf[PORTAPTY_HASH_LEN];
  get_hash(hash_buf, ctx.crt.raw.p, ctx.crt.raw.len);
  encode_hash(fingerprint, hash_buf);
  PORTAPTY_PRINTF_INFO("loaded cert with fingerprint %s\n", fingerprint);

  // Work out what args we forward to the client
  args[0] = "cert";
  args[1] = fingerprint;
  args[2] = "eps";
  memcpy(&args[3], eps_elems, eps_len * sizeof(const char*));

  // INET6 means that we get to do both v4 and v6
  int server = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  if (server < 0) {
    err = errno;
    PORTAPTY_PRINTF_ERR("could not create socket (errno %i)\n", err);
    ret = 1; goto cleanup;
  }
  // We don't care if this fails; it's nice if it works, but ah well
  //
  // This DOES leave us open to port hijacking (cool!), but means that if we screw up,
  // we don't need to wait for 1-2 years
  int reuse_port_val = 1;
  setsockopt(server, SOL_SOCKET, SO_REUSEPORT, &reuse_port_val, sizeof(reuse_port_val));

  // Allow IPv4
  //
  // Again, we want this, but it is not necessary.
  // This is already allowed by default on Linux.
  int v6_only_val = 0;
  setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only_val, sizeof(v6_only_val));

  // Actually bind the socket, and handle failure
  for (int i = 0; i < eps_len; i += 2) {
    // Try to parse socket, and handle the many forms of screwup that arise thereof
    struct sockaddr_in6 ep;
    switch(str2sockaddr(&ep, eps_elems[i], eps_elems[i + 1])) {
      case 0: break;
      case 1: { PORTAPTY_PRINTF_WARN("could not parse ip %i\n", i / 2); } continue;
      case 2: { PORTAPTY_PRINTF_WARN("could not parse port %i\n", i / 2); } continue;
      default: { PORTAPTY_PRINTF_WARN("unknown error for ep %i\n", i / 2); } continue;
    }

    if (bind(server, (struct sockaddr*)&ep, sizeof(ep))) {
      err = errno;
      PORTAPTY_PRINTF_WARN("could not bind to ep %i (errno %i)\n", i / 2, err);
    }
  }


  // Ur not 1337 enough to need more than 1337 connections m9
  if (listen(server, 1337)) {
    PORTAPTY_PRINTF_ERR("could not listen (errno %i)\n", err);
    ret = 1; goto cleanup;
  }

  PORTAPTY_PRINTF_INFO("ready\n");

  // Do a boring accept loop
  while (1) {

#ifdef NDEBUG
#define PORTAPTY_CLIENT_DROP exit(0)
#else
#define PORTAPTY_CLIENT_DROP close(client); continue
#endif
    struct sockaddr_in6 client_sa;
    socklen_t client_sa_len = sizeof(client_sa);
    int client = accept(server, (struct sockaddr*)&client_sa, &client_sa_len);
    // ???
    if (client < 0)
      continue;

    // Disable fork if we're debugging
#ifdef NDEBUG
    if (fork()) {
      close(client);
      continue;
    }

    close(server);
#endif

    char client_ep_str[PORTAPTY_SOCKADDR_STRLEN];
    // This can only really go wrong if somehow a non IPv4/IPv6 client connects.
    //
    // If you somehow managed to create that situation, then you *deserve* no readouts
    if ((err = sockaddr2str(&client_sa, client_ep_str)) < 0)
      PORTAPTY_PRINTF_INFO("could not convert ep address to a string (errno %i)\n", -err);

    PORTAPTY_PRINTF_INFO("%s connected\n", client_ep_str);

    // The first byte of a TLS handshake is 0x16, which is convienently not a printable char in ascii
    char buf;
    // Give the remote 2 seconds to send tls handshake
    {
      const struct timeval timeout = {.tv_sec = 2, .tv_usec = 0 };
      if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (void*)&timeout, sizeof(timeout))) {
        err = errno;
        PORTAPTY_PRINTF_ERR("could not set receive timeout (errno %i)\n", err);
        PORTAPTY_CLIENT_DROP;
      }
    }
    int n_recv = recv(client, &buf, 1, MSG_PEEK);
    // Unset the timeout
    {
      const struct timeval timeout = { 0 };
      if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (void*)&timeout, sizeof(timeout))) {
        err = errno;
        PORTAPTY_PRINTF_ERR("could not unset receive timeout (errno %i)\n", err);
        PORTAPTY_CLIENT_DROP;
      }
    }
    if (n_recv == 1 && buf == 0x16) {
      PORTAPTY_PRINTF_INFO("%s upgraded\n", client_ep_str);
      handle_client(client, &ctx, client_ep_str);
      PORTAPTY_CLIENT_DROP;
    }

    // If we get here, then we have a non-upgraded shell.
    PORTAPTY_PRINTF_INFO("%s is posix shell\n", client_ep_str);
    // Upgrade the client
    //
    // TODO: make this optional for edge cases
    upgrade(client, args);
    PORTAPTY_PRINTF_INFO("%s upgrading\n", client_ep_str);
    close(client);
    // No need to exit if we haven't forked
    PORTAPTY_CLIENT_DROP;
  }

  cleanup:
  mbedtls_x509_crt_free(&ctx.crt);
  mbedtls_pk_free(&ctx.pk_ctx);
  mbedtls_hmac_drbg_free(&rng);
  mbedtls_entropy_free(&entropy);
  free(args);
  return ret;
}
