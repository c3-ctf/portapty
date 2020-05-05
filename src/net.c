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

enum portapty_poll_t {
  Portapty_Poll_Nothing     = 0b0000,

  Portapty_Poll_ClosedMask  = 0b0011,
  Portapty_Poll_NetClosed   = 0b0001,
  Portapty_Poll_PtyClosed   = 0b0010,

  Portapty_Poll_NetData     = 0b0100,
  Portapty_Poll_PtyData     = 0b1000,
};

static enum portapty_poll_t portapty_poll(mbedtls_ssl_context* ssl_ctx, int net_fd, int pty_fd) {
  if (mbedtls_ssl_get_bytes_avail(ssl_ctx) > 0)
    return Portapty_Poll_NetData;

  enum portapty_poll_t ret = Portapty_Poll_Nothing;

  uint8_t testbuf;

  fd_set read_fds;
  FD_ZERO(&read_fds);
  FD_SET(net_fd, &read_fds);
  FD_SET(pty_fd, &read_fds);

  fd_set except_fds = read_fds;

  int max_fd = net_fd > pty_fd ? net_fd : pty_fd;

  struct timeval poll_period = PORTAPTY_POLL_PERIOD;

  // TLS cannot get any new data without socket data being available
  if (select(max_fd + 1, &read_fds, NULL, &except_fds, &poll_period) > 0) {
    ret |= (FD_ISSET(net_fd, &except_fds) ? Portapty_Poll_NetClosed : 0);
    ret |= (FD_ISSET(pty_fd, &except_fds) ? Portapty_Poll_PtyClosed : 0);
    ret |= (FD_ISSET(net_fd, &read_fds  ) ? Portapty_Poll_NetData   : 0);
    ret |= (FD_ISSET(pty_fd, &read_fds  ) ? Portapty_Poll_PtyData   : 0);
  }

  // Probe the fds to determine if they are closed

//  else if (!recv(pty_fd, &testbuf, sizeof(testbuf), MSG_PEEK))
//    return Portapty_Poll_PtyClosed;

  return ret;
}

void portapty_read_loop(mbedtls_ssl_context* ssl_ctx, int client_fd, int pty_fd) {
  int err = 0;
  {
    int client_flags = fcntl(client_fd, F_GETFL, 0);
    client_flags |= O_NONBLOCK;
    err = fcntl(client_fd, F_SETFL, client_flags);
  }
  {
    int pty_flags = fcntl(pty_fd, F_GETFL, 0);
    pty_flags |= O_NONBLOCK;
    err = fcntl(pty_fd, F_SETFL, pty_flags);
  }

  int poll_result;
  while (!((poll_result = portapty_poll(ssl_ctx, client_fd, pty_fd)) & Portapty_Poll_ClosedMask)) {
    if (!poll_result)
      continue;

    uint8_t buf[1024];
    int pty_n_avail;
    int n_read;

    if (poll_result & Portapty_Poll_NetData) {
      if((n_read = mbedtls_ssl_read(ssl_ctx, buf, sizeof(buf))) > 0) { //printf("%s", buf);
        write(pty_fd, buf, n_read); }
      // If this happens, the socket has actually errored
      else if (n_read != EWOULDBLOCK)
        break;
    }

    if (poll_result & Portapty_Poll_PtyData) {
      if ((n_read = read(pty_fd, buf, sizeof(buf))) > 0) { //printf("%s", buf);
        mbedtls_ssl_write(ssl_ctx, buf, n_read);}
      // If this happens, the socket has actually errored
      else if (n_read != EWOULDBLOCK)
        break;
    }
  }
}
