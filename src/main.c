#include "common.h"

#include <sys/stat.h>

int source_fd;
const uint8_t* source_buf;
off_t source_len;

enum mode {
  Portapty_Client, Portapty_Server, Portapty_Keygen, Portapty_Relay
};

int main(const int argc, const char* argv[]) {
  // We need to bind sighup ASAP, incase the shell closes
#ifdef NDEBUG
  signal(SIGHUP, SIG_IGN);
  signal(SIGINT, SIG_IGN);
#endif
  // Disabling this means that we can handle disconnects socket by socket
  signal(SIGPIPE, SIG_IGN);

  // For cleanup purposes, it makes sense to put the arguments here
  int is_client;
  const char* cert_str = NULL;
  const char* key_str = NULL;
  const char* driver = NULL;
  const char* cmd = NULL;
  // Better to be safe than sorry
  const char** bind = malloc(argc * sizeof(const char*));
  size_t bind_len = 0;
  const char** to = malloc(argc * sizeof(const char*));
  size_t to_len = 0;
  const char** advert = malloc(argc * sizeof(const char*));
  size_t advert_len = 0;

  int is_pty = -1;
  int persist = -1;

  if (argc < 2)
    goto print_help;

  // First, work out what mode we're in
  enum mode mode;
  if (!strcmp(argv[1], "client")) {
    mode = Portapty_Client;
  }
  else if (!strcmp(argv[1], "server")) {
    mode = Portapty_Server;
  }
  else if (!strcmp(argv[1], "keygen")) {
    mode = Portapty_Keygen;
  }
  else if (!strcmp(argv[1], "relay")) {
    mode = Portapty_Relay;
  }
  else {
    PORTAPTY_PRINTF_ERR("invalid mode\n");
    goto print_help;
  }

  // Now parse the arguments
  // Since all options take at least one argument, we can iterate up to argc - 1,
  // so we don't have to bounds check
  for (int i = 2; i < argc - 1; ++i) {
    if (!strcmp(argv[i], "driver")) {
      if (mode != Portapty_Server) {
        PORTAPTY_PRINTF_ERR("driver can only be specified in server mode\n");
        goto print_help;
      }
      // We disable the pty and persistence by default for a driver
      if (is_pty < 0)
        is_pty = 0;
      if (persist < 0)
        persist = 0;
      driver = argv[++i];
    }
    else if (!strcmp(argv[i], "cert"))
      cert_str = argv[++i];
    else if (!strcmp(argv[i], "key")) {
      if (mode == Portapty_Client || mode == Portapty_Relay) {
        PORTAPTY_PRINTF_ERR("key cannot be specified in client mode\n");
        goto print_help;
      }
      key_str = argv[++i];
    }
    else if (!strcmp(argv[i], "pty")) {
      if (mode != Portapty_Server) {
        PORTAPTY_PRINTF_ERR("pty can only be specified in server mode\n");
        goto print_help;
      }
      ++i;
      if (!strcmp(argv[i], "on"))
        is_pty = 1;
      else if (!strcmp(argv[i], "off"))
        is_pty = 0;
      else {
        PORTAPTY_PRINTF_ERR("invalid pty mode");
        goto print_help;
      }
    }
    else if (!strcmp(argv[i], "persist")) {
      if (mode != Portapty_Server) {
        PORTAPTY_PRINTF_ERR("persist can only be specified in server mode\n");
        goto print_help;
      }
      ++i;
      if (!strcmp(argv[i], "on"))
        persist = 1;
      else if (!strcmp(argv[i], "off"))
        persist = 0;
      else {
        PORTAPTY_PRINTF_ERR("invalid pty mode");
        goto print_help;
      }
    }
    else if (!strcmp(argv[i], "cmd")) {
      if (mode != Portapty_Server) {
        PORTAPTY_PRINTF_ERR("cmd can only be specified in server mode\n");
        goto print_help;
      }
      cmd = argv[++i];
    }
    else if (!strcmp(argv[i], "bind")) {
      if (mode == Portapty_Keygen || mode == Portapty_Client) {
        PORTAPTY_PRINTF_ERR("bind cannot be specified in keygen or client mode\n");
        goto print_help;
      }
      bind[bind_len++] = argv[++i];
      // If we hit the end for this double arg, fail
      if (i == argc) {
        PORTAPTY_PRINTF_ERR("port not given\n");
      }
      bind[bind_len++] = argv[++i];
    }
    else if (!strcmp(argv[i], "advert")) {
      if (mode != Portapty_Server) {
        PORTAPTY_PRINTF_ERR("advert can only be specified in keygen or client mode\n");
        goto print_help;
      }
      advert[advert_len++] = argv[++i];
      // If we hit the end for this double arg, fail
      if (i == argc) {
        PORTAPTY_PRINTF_ERR("port not given\n");
      }
      advert[advert_len++] = argv[++i];
    }
    else if (!strcmp(argv[i], "to")) {
      if (mode == Portapty_Keygen || mode == Portapty_Server) {
        PORTAPTY_PRINTF_ERR("to cannot be specified in keygen or server mode\n");
        goto print_help;
      }
      to[to_len++] = argv[++i];
      // If we hit the end for this double arg, fail
      if (i == argc) {
        PORTAPTY_PRINTF_ERR("port not given\n");
      }
      to[to_len++] = argv[++i];
    }
    else {
      PORTAPTY_PRINTF_ERR("invalid option %s\n", argv[i]);
      goto print_help;
    }
  }
  // Handle the required args
  switch (mode) {
    case Portapty_Server: {
      if (!bind_len) {
        PORTAPTY_PRINTF_ERR("missing bind list\n");
        goto print_help;
      }
    } break;
    case Portapty_Client: {
      if (!to_len) {
        PORTAPTY_PRINTF_ERR("missing to list\n");
        goto print_help;
      }
    } break;
    case Portapty_Relay: {
      if (!to_len || !bind_len) {
        PORTAPTY_PRINTF_ERR("need both to and bind lists\n");
        goto print_help;
      }
    } break;
    default: {}
  }

  // If we didn't decide on a is_pty or a persist, enable it
  if (is_pty < 0)
    is_pty = 1;
  if (persist < 0)
    persist = 1;

  enum handshake_flags flags = 0;
  flags |= (is_pty  ? Portapty_Handshake_IsPty   : 0);
  flags |= (persist ? Portapty_Handshake_Persist : 0);

  switch (mode) {
    case Portapty_Client:
#ifdef NDEBUG
  // Fork to background
  if (fork())
    exit(0);
  // Move to our own group
  setsid();
  // Fork again
  if (fork())
    exit(0);
  // Close the file descriptors
  close(0);
  close(1);
  close(2);
#endif
#ifdef NDEBUG
      while(1) {
#else
      return
#endif
      run_client(to, to_len, cert_str);
#ifdef NDEBUG
      sleep(1);
    }
#endif
    case Portapty_Server: return run_server(bind, bind_len, advert, advert_len, key_str, cert_str, driver, cmd, flags, argv[0]);
    case Portapty_Keygen: return run_gen(key_str, cert_str);
    case Portapty_Relay: return run_relay(bind, bind_len, to, to_len);
    default: abort();
  }

print_help:
  free(to);
  free(bind);
  // This is helpful even outside of debug mode
//#ifndef NDEBUG
  printf("%s {client|server|keygen|relay} [OPTIONS]\n", argv[0]);
  printf("Options:\n");
  printf("    client: [cert CERTHASH] to IP PORT [to IP PORT]...\n");
  printf("    server: [cert CERTFILE] [key KEYFILE] [driver CMD] [cmd CMD] [pty {on|off}] [persist {on|off}] bind IP PORT [{bind|advert} IP PORT]...\n");
  printf("    keygen: [cert CERTFILE] [key KEYFILE]\n");
  printf("    relay:  bind IP PORT to IP PORT [{bind|to} IP PORT]...\n");
//#endif
  return 1;
}
