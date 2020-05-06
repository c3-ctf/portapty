#include "common.h"


int run_relay(const char** bind_elems, size_t bind_len, const char** to_elems, size_t to_len) {
  int server = portapty_bind_all(bind_elems, bind_len);

  if (server < 0)
    return server;

  while (1) {
    struct sockaddr_in6 client_sa;
    socklen_t client_sa_len = sizeof(client_sa);
    int client = accept(server, (struct sockaddr*)&client_sa, &client_sa_len);
    // ???
    if (client < 0)
      continue;
#ifdef NDEBUG
#define PORTAPTY_CLIENT_DROP { exit(0); }
#else
#define PORTAPTY_CLIENT_DROP {close(client); continue;}
#endif
    // Disable fork if we're debugging
#ifdef NDEBUG
    if (fork()) {
      close(client);
      continue;
    }

    close(server);
#endif

    int remote_server = portapty_connect_first(to_elems, to_len);
    if (remote_server < 0)
      PORTAPTY_CLIENT_DROP;
    {
      int client_flags = fcntl(client, F_GETFL, 0);
      client_flags |= O_NONBLOCK;
      fcntl(client, F_SETFL, client_flags);
    }
    {
      int remote_flags = fcntl(remote_server, F_GETFL, 0);
      remote_flags |= O_NONBLOCK;
      fcntl(client, F_SETFL, remote_flags);
    }

    enum portapty_poll_t poll_result;

    // Using pipes, we can achieve zero-copy, which means much fast throughput
    int pipes[2];
    if (pipe2(pipes, O_NONBLOCK)) {
      int err = errno;
      PORTAPTY_PRINTF_ERR("could not create pipes (errno %i)\n", err);
      PORTAPTY_CLIENT_DROP;
    }
#define PORTAPTY_SPLICE_BUF_SIZE 16384
    fcntl(pipes[0], F_SETPIPE_SZ, PORTAPTY_SPLICE_BUF_SIZE);

#define PORTAPTY_SPLICE_FLAGS SPLICE_F_NONBLOCK | SPLICE_F_MOVE
    // SPLICE_F_MORE | SPLICE_F_NONBLOCK | SPLICE_F_MOVE
    // Set up the forwarding
    int n_read = 0;
    while (!((poll_result = portapty_poll(client, remote_server)) & Portapty_Poll_ClosedMask)) {
      errno=0;
      if (poll_result & Portapty_Poll_FirstData) {
        if(splice(client, NULL, pipes[1], NULL, PORTAPTY_SPLICE_BUF_SIZE, PORTAPTY_SPLICE_FLAGS) > 0)
          splice(pipes[0], NULL, remote_server, NULL, PORTAPTY_SPLICE_BUF_SIZE, PORTAPTY_SPLICE_FLAGS);

        else if (errno != EWOULDBLOCK)
          break;
      }

      if (poll_result & Portapty_Poll_SecondData) {
        if (splice(remote_server, NULL, pipes[1], NULL, PORTAPTY_SPLICE_BUF_SIZE, PORTAPTY_SPLICE_FLAGS))
          splice(pipes[0], NULL, client, NULL, PORTAPTY_SPLICE_BUF_SIZE, PORTAPTY_SPLICE_FLAGS);
        else if (errno != EWOULDBLOCK)
          break;
      }
    }

    close(client);
    close(remote_server);
  }
}

