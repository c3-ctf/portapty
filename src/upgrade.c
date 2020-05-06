#include "common.h"

#include <ctype.h>
#include <sys/stat.h>

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
  // We can just send the other chars. It's not nice, but it should work
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 80
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 90
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // A0
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // B0
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // C0
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // D0
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // E0
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // F0
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
  strcpy(out_buf + offset, "'>>/tmp/portapty\n");
  offset += sizeof("'>>/tmp/portapty\n") - 1;
  write(fd, out_buf, offset);

  return i;
}

// Printf is universally available on a posix shell, but can inflate our payload a bit
static void upgrade_printf(int fd, const uint8_t* source_buf, off_t source_len, char const* const* args) {
  size_t pos;
  // Clear the file
  WRITE_STRLIT(fd, "echo -n>/tmp/portapty\n");
  size_t i = 0;
  size_t read;
  while ((read = upgrade_printf_buf(fd, source_buf + i, source_len - i)))
    i += read;

  WRITE_STRLIT(fd, "chmod +x /tmp/portapty\n/tmp/portapty client");
  for (; *args; ++args) {
    WRITE_STRLIT(fd, " ");
    WRITE_STR(fd, *args);
  }
  WRITE_STRLIT(fd, "\n");
}

void upgrade(int fd, const uint8_t* plod, size_t len, char const* const* args) {
  // TODO: dynamic selection alg (find if gzip, base64...)
  upgrade_printf(fd, plod, len, args);
}

int portapty_load(const char* file, const uint8_t** buf, size_t* len) {
  int ret = 0;

  int source_fd;
  if ((source_fd = open(file, O_RDONLY | O_CLOEXEC)) < 0) {
    ret = errno;
    PORTAPTY_PRINTF_ERR("open failed (errno %i)", ret);
  }
  struct stat s;
  if (fstat(source_fd, &s)) {
    ret = errno;
    PORTAPTY_PRINTF_ERR("fstat failed (errno %i)", ret);
    goto cleanup;
  }
  *len = s.st_size; //lseek(source_fd, 0, SEEK_END);
  *buf = mmap(0, s.st_size, PROT_READ, MAP_PRIVATE, source_fd, 0);

  if (!*buf) {
    ret = errno;
    PORTAPTY_PRINTF_ERR("mmap failed (errno %i)", ret);
    goto cleanup;
  }

  cleanup:
  close(source_fd);
  return ret;
}

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
    // This allows reporting, and drivers shouldn't really be causing leaked errors
//    dup2(stdout_pipes[1], STDERR_FILENO);

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
