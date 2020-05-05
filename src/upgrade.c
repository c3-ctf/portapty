#include "common.h"

#include <ctype.h>

// Sod it, do a bool array
static const uint8_t no_escape[256] = {
//0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 00
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 10
  1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, // 20
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, // 30
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 40
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, // 50
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 60
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, // 70
};

/// @returns the number of bytes of buf sent
static size_t upgrade_printf_buf(int fd, const uint8_t* buf, size_t len) {
  // This is really crap
  //
  // TODO: uncrapify
  //
  // If we don't do this, we end up mallocing =(
  char out_buf[PORTAPTY_CMD_WIDTH] = "printf -- '";
  // Points to just after the initial string
  size_t offset = sizeof("printf -- '") - 1;
  size_t i;

  // TODO: I could do the calc, but 32 is enough and is stable
  for (i = 0; i < len && offset < PORTAPTY_CMD_WIDTH - 32; ++i) {
    // If we used isalnum, we could break octal!
    if (no_escape[buf[i]])
      out_buf[offset++] = buf[i];
    else
      offset += sprintf(out_buf + offset, "\\%o", buf[i]);
  }
  write(fd, out_buf, offset);
  WRITE_STRLIT(fd, "'>>/tmp/portapty\n");

  return i;
}

static void upgrade_printf(int fd, char const* const* args) {
  size_t pos;
  // Printf is universally available on a posix shell, but slightly more than quadruples the binary size
  //
  // with clever magic, we can reduce this to (guessing) about 2x
  //
  // TODO: clever magic
  WRITE_STRLIT(fd, "echo -n>/tmp/portapty\n");
  size_t i = 0;
  while ((i += upgrade_printf_buf(fd, source_buf + i, source_len - i)) < source_len);

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
