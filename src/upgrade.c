#include "common.h"

static void upgrade_printf_buf(int fd, const uint8_t* buf, size_t len) {
  // This is really crap
  //
  // TODO: uncrapify
  //
  // If we don't do this, we end up mallocing =(
  WRITE_STRLIT(fd, "printf '");
  for (size_t i = 0; i < len; ++i) {
    char escape[5] = "\\";
    snprintf(escape + 1, 4, "%o", buf[i]);
    WRITE_STR(fd, escape);
  }
  WRITE_STRLIT(fd, "'>>/tmp/portapty\n");
}

static void upgrade_printf(int fd, char const* const* args) {
  size_t pos;
  // Printf is universally available on a posix shell, but slightly more than quadruples the binary size
  //
  // with clever magic, we can reduce this to (guessing) about 2x
  //
  // TODO: clever magic
  WRITE_STRLIT(fd, "echo -n>/tmp/portapty\n");
  size_t i;
  for (i = 0; i < source_len - (source_len % 32); i += 32)
    upgrade_printf_buf(fd, source_buf + i, 32);
  // Copy last part
  upgrade_printf_buf(fd, source_buf + i, source_len % 32);

  WRITE_STRLIT(fd, "chmod +x /tmp/portapty\n/tmp/portapty client");
  for (; *args; ++args) {
    WRITE_STRLIT(fd, " ");
    WRITE_STR(fd, *args);
  }
  WRITE_STRLIT(fd, "\n");
}

void upgrade(int fd, char const* const* args) {
  // TODO: dynamic selection alg (find if gzip, base64...)
  upgrade_printf(fd, args);
}
