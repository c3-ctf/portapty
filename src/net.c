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
  // TODO: sacrifice a goat to get this thing to actually bind
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
