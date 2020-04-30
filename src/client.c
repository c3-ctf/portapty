#include "common.h"

int run_client(const char** eps_elems, size_t eps_len, const char* cert_hash_b64) {
  puts("woo");
  return 0;
//  int err;

//  int client = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
//  if (client < 0) {
//    err = errno;
//    PORTAPTY_PRINTF_ERR("could not create socket (errno %i)\n", err);
//    return 1;
//  }

//  for (int i = 0; i < eps_len; ++i)
//    if (!connect(client, (struct sockaddr*)&eps_names[i], sizeof(struct sockaddr_in6)))
//      goto connected;
//  PORTAPTY_PRINTF_ERR("could not reach server on any ep\n");
//  return 1;

//  connected:
//  mode_switch(client);
//  send_sys_details(client);
//  mode_switch(client);

//  char* remote_details = recv_ctrl(client);

//  int local_ctrl  = 0;
//  int remote_ctrl = 0;

//  send_sys_details(client);

//  int master, slave;
//  char name[PATH_MAX] = {0};
//  // This is *technically* vulnerable to a buffer overflow by an evil-but-compliant kernel
//  //
//  // If your kernel is evil, then this is the least of your worries
//  if (openpty(&master, &slave, name, NULL, NULL)) {
//    int err = errno;
//    PORTAPTY_PRINTF_ERR("could not open pty (errno %i)\n", err);
//    return 1;
//  }

//  PORTAPTY_PRINTF_UPGRADED("available on %s\n", name);

//  // Connect to each ep until one works
//  puts("WOOO");
//  return 0;
}
