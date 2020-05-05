#include <mbedtls/error.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("%s [ERR]\n", argv[0]);
    return 1;
  }

  long err = strtol(argv[1], NULL, 10);
  // We allow 0 port for some cases, so don't block it
  if (err < -32768) {
    puts("Error out of range\n");
    return 1;
  }

  char buf[4096];
  mbedtls_strerror(err, buf, 4096);
  puts(buf);
  return 0;
}
