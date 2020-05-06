#include "common.h"

int sockaddr2str(const struct sockaddr_in6* ep, char buf[PORTAPTY_SOCKADDR_STRLEN]) {
  char ip_str[INET6_ADDRSTRLEN + 2] = {0};
  uint16_t port;

  errno = 0;
//  switch (ep->sin6_family) {
//    case AF_INET: {
      // Ah, isn't IPv4 nice. Imagine having horrific formating...
//      inet_ntop(AF_INET, &((struct sockaddr_in*)ep)->sin_addr, ip_str, sizeof(ip_str));
//      if (errno)
//        return errno;
//      port = ntohs(((struct sockaddr_in*)ep)->sin_port);
//    } break;
//    case AF_INET6: {
      // Oh look, horrific formatting
      //
      // Because IPv6 has an annoying syntax, we use [::]:0 notation
      // Set first char
      ip_str[0] = '[';
      // Skip bracket and fill up to length - 2 (INET6_ADDRSTRLEN) chars,
      // leaving the maximum length being INET6_ADDRSTRLEN (as INET6_ADDRSTRLEN - 1 is the longest an output could be)
      inet_ntop(AF_INET6, &((struct sockaddr_in6*)ep)->sin6_addr, ip_str + 1, sizeof(ip_str) - 2);
      if (errno)
        return errno;
      // Set the next char (max INET6_ADDRSTRLEN + 1) as ']'
      ip_str[strlen(ip_str)] = ']';
      // This leaves 1 byte minimum for the null terminator
      if (errno)
        return errno;
      port = ntohs(((struct sockaddr_in6*)ep)->sin6_port);
//    } break;
//    default: return -ENOSYS;
//  }

  // Why is he using snprintf?
  //
  //               because I'm bloody paranoid
  return snprintf(buf, PORTAPTY_SOCKADDR_STRLEN, "%s:%hu", ip_str, port);
}

int str2sockaddr(struct sockaddr_in6* ep, const char* addr, const char* port) {
  memset(ep, 0, sizeof(*ep));
  // Unified address decoding requires us to keep track of where we put the address
  //
  // We could just replicate the code for each one:
  // that saves a single assignment, but costs many bytes
  void* addr_ptr;

  ep->sin6_family = AF_INET6;
  struct in_addr v4_tmp;
  int family;

  // Simple address type detection
  //
  // We need to check this way around, as ::ffff:0.0.0.0 is valid IPv6 but not v4
  if (strchr(addr, ':')) {
    family = AF_INET6;
    addr_ptr = &ep->sin6_addr;
  }
  else {
    family = AF_INET;
    addr_ptr = &v4_tmp;
  }

  // Now we know what form the address is in, we can fill it out, and error if necessary
  if (!inet_pton(family, addr, addr_ptr))
    return 1;

  // Now we do some IPv6 dark magic
  //
  // DONE: sacrifice a goat to get this thing to actually bind
  if (family == AF_INET) {
    ep->sin6_addr.s6_addr[10] = 0xFF;
    ep->sin6_addr.s6_addr[11] = 0xFF;
    memcpy(&ep->sin6_addr.s6_addr[12], &v4_tmp.s_addr, 4);
  }

  // We need to check it is in range BEFORE we truncate it to an int
  errno = 0;
  unsigned long port_maybe = strtoul(port, NULL, 10);
  // We allow 0 port for some cases, so don't block it
  if (errno || port_maybe >= 65536)
    return 2;

  ep->sin6_port = htons(port_maybe);

  // Wow! Nothing broke!
  return 0;
}

enum portapty_poll_t portapty_poll(int first_fd, int secnd_fd) {
  enum portapty_poll_t ret = Portapty_Poll_Nothing;

  uint8_t testbuf;

  fd_set read_fds;
  FD_ZERO(&read_fds);
  FD_SET(first_fd, &read_fds);
  FD_SET(secnd_fd, &read_fds);

  fd_set except_fds = read_fds;

  int max_fd = first_fd > secnd_fd ? first_fd : secnd_fd;

  struct timeval poll_period = PORTAPTY_POLL_PERIOD;

  // TLS cannot get any new data without socket data being available
  if (select(max_fd + 1, &read_fds, NULL, &except_fds, &poll_period) > 0) {
    ret |= (FD_ISSET(first_fd, &except_fds) ? Portapty_Poll_FirstClosed  : 0);
    ret |= (FD_ISSET(secnd_fd, &except_fds) ? Portapty_Poll_SecondClosed : 0);
    ret |= (FD_ISSET(first_fd, &read_fds  ) ? Portapty_Poll_FirstData    : 0);
    ret |= (FD_ISSET(secnd_fd, &read_fds  ) ? Portapty_Poll_SecondData   : 0);
  }

  // Probe the fds to determine if they are closed

//  else if (!recv(pty_fd, &testbuf, sizeof(testbuf), MSG_PEEK))
//    return Portapty_Poll_PtyClosed;

  return ret;
}

void portapty_read_loop(mbedtls_ssl_context* ssl_ctx, int client_fd, int read_fd, int write_fd) {
  int err = 0;
  {
    int client_flags = fcntl(client_fd, F_GETFL, 0);
    client_flags |= O_NONBLOCK;
    err = fcntl(client_fd, F_SETFL, client_flags);
  }
  {
    int pty_flags = fcntl(read_fd, F_GETFL, 0);
    pty_flags |= O_NONBLOCK;
    err = fcntl(read_fd, F_SETFL, pty_flags);
  }

  int poll_result = Portapty_Poll_FirstData;
  while (mbedtls_ssl_get_bytes_avail(ssl_ctx) || !((poll_result = portapty_poll(client_fd, read_fd)) & Portapty_Poll_ClosedMask)) {
    if (!poll_result)
      continue;

    uint8_t buf[8192];
    int pty_n_avail;
    int n_read;

    errno=0;
    // This will still be true if we miss the poll
    if (poll_result & Portapty_Poll_FirstData) {
      if ((n_read = mbedtls_ssl_read(ssl_ctx, buf, sizeof(buf))))
        write(write_fd, buf, n_read);
      // If this happens, the socket has actually errored
      else if (errno != EWOULDBLOCK)
        break;
    }

    if (poll_result & Portapty_Poll_SecondData) {
      while ((n_read = read(read_fd, buf, sizeof(buf))) > 0)
        mbedtls_ssl_write(ssl_ctx, buf, n_read);
      // If this happens, the socket has actually errored
      if (errno != EWOULDBLOCK)
        break;
    }
  }
}

int portapty_bind_all(const char** eps_elems, size_t eps_len) {
  int err = 0;

  int server = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  if (server < 0) {
    err = errno;
    PORTAPTY_PRINTF_ERR("could not create socket (errno %i)\n", err);
    // Skip socket closing
    return err;
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
    err = errno;
    PORTAPTY_PRINTF_ERR("could not listen (errno %i)\n", err);
    goto cleanup;
  }

  cleanup:

  if (!err)
    return server;
  else {
    close(server);
    // Force it to be negative, we cannot look like a real fd!
    return err > 0 ? -err : err;
  }
}

int portapty_connect_first(const char** eps_elems, size_t eps_len) {
  int err = 0;

  int client = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  if (client < 0) {
    err = errno;
    PORTAPTY_PRINTF_ERR("could not create socket (errno %i)\n", err);
    return -err;
  }
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
  close(client);
  return -ECONNREFUSED;

  connected:
  return client;
}
