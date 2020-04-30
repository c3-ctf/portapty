#include "common.h"

#include <mbedtls/error.h>

static void handle_client(int client) {
  int master, slave;
  char name[PATH_MAX];

  if (openpty(&master, &slave, name, NULL, NULL)) {
    int err = errno;
    PORTAPTY_PRINTF_ERR("could not open pty (errno %i)\n", err);
  }

  PORTAPTY_PRINTF_UPGRADED("available on %s\n", name);
}

int run_server(const char** eps_elems, size_t eps_len, const char* key_path, const char* cert_path) {
  // TODO: what do we do with a CTRL+C?
  signal(SIGINT, SIG_DFL);
  int err;
  int ret = 0;

  if (eps_len % 2) {
    PORTAPTY_PRINTF_ERR("unpaired ep\n");
    return 1;
  }


  const char** args = calloc( // This probably doesn't need to be a calloc
        1 + // the hash
        1 + // the list delimiter
        eps_len + // All the ips and ports
        1, // trailing null
        sizeof(char**)
  );
  int is_cert_ber_alloc = 0;

  // Crypto stuff to be filled in
  mbedtls_pk_context pk_ctx;
  mbedtls_x509_crt crt;
  char fingerprint[PORTAPTY_HASH_STR_LEN];
  mbedtls_entropy_context entropy;
  mbedtls_hmac_drbg_context rng;

  init_entropy(&entropy);
  init_drbg(&rng, &entropy);
  mbedtls_pk_init(&pk_ctx);
  mbedtls_x509_crt_init(&crt);

  // Now we have finished init'ing and alloc'ing, we can get to work
  if (key_path) {
    uint8_t* buf;
    size_t len;
    if ((ret = mbedtls_pk_parse_keyfile(&pk_ctx, key_path, ""))) {
      PORTAPTY_PRINTF_ERR("could not load private key\n");
      goto cleanup;
    }
  }
  else if (cert_path) {
    PORTAPTY_PRINTF_ERR("certificate given without key\n");
    ret = 1; goto cleanup;
  }
  else {
    if ((ret = gen_key(&pk_ctx, &rng))) {
      PORTAPTY_PRINTF_ERR("key generation failed\n");
      goto cleanup;
    }
  }

  if (cert_path) {
    if ((ret = mbedtls_x509_crt_parse_file(&crt, key_path))) {
      PORTAPTY_PRINTF_ERR("failed to parse certificate\n");
      goto cleanup;
    }
  }
  else {
    // I'm malloc'ing, as 16384 is a lot of bytes for the stack
    uint8_t* tmp_ber = calloc(PORTAPTY_CERT_BUF_LEN, 1);
    int tmp_ber_len = gen_self_signed_cert(tmp_ber, &pk_ctx, &rng);
//    tmp_ber_len = 261;

    // This took me ages to figure out. ret is actually an offset because screw you
    if (tmp_ber_len < 0 || (ret = mbedtls_x509_crt_parse_der_nocopy(&crt, tmp_ber, tmp_ber_len))) {
      char error_buf[256];
      mbedtls_strerror(ret ? ret : tmp_ber_len, error_buf, 256);

      PORTAPTY_PRINTF_ERR("failed to create self-signed certificate (%s)\n", error_buf);
      free(tmp_ber);
      goto cleanup;
    }
    // We don't need to free tmp_ber, as it was stolen by the _nocopy function above
    free(tmp_ber); // yeet
  }

  get_hash(fingerprint, crt.raw.p, crt.raw.len);
  PORTAPTY_PRINTF_INFO("loaded cert with fingerprint %s\n", fingerprint);

  // Work out what args we forward to the client
  //
  //                   all the ips and ports +

  args[0] = fingerprint;
  args[1] = "--";
  memcpy(&args[2], eps_elems, eps_len * sizeof(const char*));

  // INET6 means that we get to do both v4 and v6
  int server = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
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

  // Allow IPv6
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
    struct sockaddr_in6 client_sa;
    socklen_t client_sa_len = sizeof(client_sa);
    int client = accept(server, (struct sockaddr*)&client_sa, &client_sa_len);
    // ???
    if (client < 0)
      continue;

    if (!fork()) {
      close(client);
      continue;
    }

    close(server);

    // Set the receive timeout to something sensible
    //
    // TODO: be sensible
    {
      const struct timeval timeout = {.tv_sec = 2, .tv_usec = 0 };
      if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (void*)&timeout, sizeof(timeout))) {
        err = errno;
        PORTAPTY_PRINTF_ERR("could not set receive timeout (errno %i)\n", err);
        exit(0);
      }
      if (setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (void*)&timeout, sizeof(timeout))) {
        err = errno;
        PORTAPTY_PRINTF_ERR("could not set send timeout (errno %i)\n", err);
        exit(0);
      }
    }

    char client_ep_str[PORTAPTY_SOCKADDR_STRLEN];
    // This can only really go wrong if somehow a non IPv4/IPv6 client connects.
    //
    // If you somehow managed to create that situation, then you *deserve* no readouts
    if ((err = sockaddr2str(&client_sa, client_ep_str)) < 0)
      PORTAPTY_PRINTF_INFO("could not convert ep address to a string (errno %i)\n", -err);

    PORTAPTY_PRINTF_INFO("%s connected\n", client_ep_str);

    // Added 1 for debugging purposes
    char hello_buf[PORTAPTY_HELLO_LEN + 1] = {0};

    // Check if this is already upgraded
    //
    // Yes, this will _technically_ fail if the other end is somehow compiled with a different encoding.
    // That failure mode is superior, as otherwise we behave differently if the length is different (because of EWOULDBLOCK)
    fd_set set;
    FD_ZERO(&set);
    FD_SET(client, &set);

    if (recv(client, &hello_buf, PORTAPTY_HELLO_LEN, MSG_PEEK) == PORTAPTY_HELLO_LEN) {
      if (!memcmp(hello_buf, PORTAPTY_HELLO, PORTAPTY_HELLO_LEN)) {
        // Skip the bytes
        read(client, &hello_buf, PORTAPTY_HELLO_LEN);
        PORTAPTY_PRINTF_INFO("%s upgraded\n", client_ep_str);
        handle_client(client);
        exit(0);
      }
      else
        PORTAPTY_PRINTF_WARN("non-portapty OOB data received (begins %s), assuming basic shell\n", hello_buf);
    }

    // If we get here, then we have a non-upgraded shell.
    PORTAPTY_PRINTF_INFO("%s is posix shell %s\n", client_ep_str, hello_buf);
    // Upgrade the client
    upgrade(client, args);
    PORTAPTY_PRINTF_INFO("%s upgrading\n", client_ep_str);
    close(client);
    exit(0);

    // FIXME: nope
    close(client);
  }

  cleanup:
  mbedtls_x509_crt_free(&crt);
  mbedtls_pk_free(&pk_ctx);
  mbedtls_hmac_drbg_free(&rng);
  mbedtls_entropy_free(&entropy);
  free(args);
  return ret;
}
