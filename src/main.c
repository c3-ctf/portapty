#include "common.h"

int source_fd;
const uint8_t* source_buf;
off_t source_len;

// Cyclic3's big TODO list of doom:
//
// * Add routing for pivoting (because it will make me look cool)
// * Disconnect recovery or smth idk

enum mode {
  Portapty_Client, Portapty_Server, Portapty_Keygen
};

int main(const int argc, const char* argv[]) {
  // We need to bind sighup ASAP, incase the shell closes
#ifdef NDEBUG
  signal(SIGHUP, SIG_IGN);
  signal(SIGINT, SIG_IGN);
#endif
  // Disabling this means that we can handle disconnects socket by socket
  signal(SIGPIPE, SIG_IGN);


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
  else {
    PORTAPTY_PRINTF_ERR("invalid mode\n");
    goto print_help;
  }

  // Now parse the arguments
  int is_client;
  const char* cert_str = NULL;
  const char* key_str = NULL;
  const char* driver = NULL;
  const char* cmd = NULL;
  int eps_offset;
  int eps_len;
  // Since all options take at least one argument, we can iterate up to argc - 1,
  // so we don't have to bounds check
  for (eps_offset = 2; eps_offset < argc - 1; ++eps_offset) {
    if (!strcmp(argv[eps_offset], "driver")) {
      if (mode != Portapty_Server) {
        PORTAPTY_PRINTF_ERR("driver can only be specified in server mode\n");
        goto print_help;
      }
      driver = argv[++eps_offset];
    }
    else if (!strcmp(argv[eps_offset], "cert"))
      cert_str = argv[++eps_offset];
    else if (!strcmp(argv[eps_offset], "key")) {
      if (mode == Portapty_Client) {
        PORTAPTY_PRINTF_ERR("key cannot be specified in client mode\n");
        goto print_help;
      }
      key_str = argv[++eps_offset];
    }
    else if (!strcmp(argv[eps_offset], "cmd")) {
      if (mode != Portapty_Server) {
        PORTAPTY_PRINTF_ERR("cmd can only be specified in server mode\n");
        goto print_help;
      }
      cmd = argv[++eps_offset];
    }
    else if (!strcmp(argv[eps_offset], "eps")) {
      if (mode == Portapty_Keygen) {
        PORTAPTY_PRINTF_ERR("eps cannot be specified in keygen mode\n");
        goto print_help;
      }
      goto found_ep_list;
    }
    else {
      PORTAPTY_PRINTF_ERR("invalid option %s\n", argv[eps_offset]);
      goto print_help;
    }
  }
  // If we get here, we did not find the ep list delimiter
  if (mode != Portapty_Keygen) {
    PORTAPTY_PRINTF_ERR("missing ep list\n");
    goto print_help;
    // This label can be in an if, as we have the same conditions as before
found_ep_list:
    ++eps_offset;

    if ((eps_len = argc - eps_offset) % 2) {
      PORTAPTY_PRINTF_ERR("mismatched eps\n");
      goto print_help;
    }
  }


  // Now we open the source file, and map it into memory
  source_fd = open(argv[0], O_RDONLY | O_CLOEXEC);
  source_len = lseek(source_fd, 0, SEEK_END);
  source_buf = mmap(0, source_len, PROT_READ, MAP_PRIVATE, source_fd, 0);

  switch (mode) {
    case Portapty_Client: return run_client(argv + eps_offset, argc - eps_offset, cert_str);
    case Portapty_Server: return run_server(argv + eps_offset, argc - eps_offset, key_str, cert_str, driver, cmd);
    case Portapty_Keygen: return run_gen(key_str, cert_str);
    default: abort();
  }

print_help:
#ifndef NDEBUG
  printf("%s <client|server|keygen> OPTIONS\n", argv[0]);
  printf("Options:\n");
  printf("    client: [cert CERTHASH] eps IP PORT [IP PORT]...\n");
  printf("    server: [cert CERTFILE] [key KEYFILE] [driver PATH] [cmd CMD] eps IP PORT [IP PORT]...\n");
  printf("    keygen: [cert CERTFILE] [key KEYFILE]\n");
#endif
  return 1;
}
