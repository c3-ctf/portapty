#include "common.h"

#include <sys/stat.h>

// Cyclic3's big TODO list of doom:
//
// * Set up channel multiplexing
// * Add routing for pivoting (because it will make me look cool)
// * Disconnect recovery or smth idk

int source_fd;
const uint8_t* source_buf;
off_t source_len;

int portapty_fork_pipe(int* read_fd, int* write_fd, const char* cmdline) {
  int stdin_pipes[2], stdout_pipes[2];
  if (pipe(stdin_pipes) || pipe(stdout_pipes)) {
    return errno;
  }
  // pipe[0] is for reading, and pipe[1] is for writing
  if (!fork()) {
    // Close the master end
    close(stdin_pipes[1]); close(stdout_pipes[0]);

    dup2(stdin_pipes[0], STDIN_FILENO);
    dup2(stdout_pipes[1], STDOUT_FILENO);
    dup2(stdout_pipes[1], STDERR_FILENO);

    // Close the trailing slave fds
    close(stdin_pipes[0]); close(stdout_pipes[1]);
    execl("/bin/sh", "/bin/sh", "-c", cmdline, (char*)NULL);

    // Make a bit of noise if we can't exec sh
    abort();
  }

  // Close the slave fds
  close(stdin_pipes[0]); close(stdout_pipes[1]);
  *read_fd = stdout_pipes[0];
  *write_fd = stdin_pipes[1];
  return 0;
}

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
  int is_pty = -1;
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
      // We disable the pty by default for a driver
      if (is_pty < 0)
        is_pty = 0;
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
    else if (!strcmp(argv[eps_offset], "pty")) {
      if (mode == Portapty_Client) {
        PORTAPTY_PRINTF_ERR("pty cannot be specified in client mode\n");
        goto print_help;
      }
      ++eps_offset;
      if (!strcmp(argv[eps_offset], "on"))
        is_pty = 1;
      else if (!strcmp(argv[eps_offset], "off"))
        is_pty = 0;
      else {
        PORTAPTY_PRINTF_ERR("invalid pty mode");
        goto print_help;
      }
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

  // If we didn't decide on a is_pty, enable it
  if (is_pty < 0)
    is_pty = 1;


  // Now we open the source file, and map it into memory
  source_fd = open(argv[0], O_RDONLY | O_CLOEXEC);
  struct stat s;
  fstat(source_fd, &s);
  source_len = s.st_size; //lseek(source_fd, 0, SEEK_END);
  source_buf = mmap(0, source_len, PROT_READ, MAP_PRIVATE, source_fd, 0);

  switch (mode) {
    case Portapty_Client: return run_client(argv + eps_offset, argc - eps_offset, cert_str);
    case Portapty_Server: return run_server(argv + eps_offset, argc - eps_offset, key_str, cert_str, driver, cmd, is_pty);
    case Portapty_Keygen: return run_gen(key_str, cert_str);
    default: abort();
  }

print_help:
  // This is helpful even outside of debug mode
//#ifndef NDEBUG
  printf("%s <client|server|keygen> [OPTIONS]\n", argv[0]);
  printf("Options:\n");
  printf("    client: [cert CERTHASH] eps IP PORT [IP PORT]...\n");
  printf("    server: [cert CERTFILE] [key KEYFILE] [driver PATH] [cmd CMD] [pty on|off] eps IP PORT [IP PORT]...\n");
  printf("    keygen: [cert CERTFILE] [key KEYFILE]\n");
//#endif
  return 1;
}
