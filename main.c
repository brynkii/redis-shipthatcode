#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARGS 64
#define MAX_LINE 4096

/* ---------- RESP serialization helpers ---------- */

static void resp_simple_string(const char *s) { printf("+%s\r\n", s); }

static void resp_error(const char *msg) { printf("-%s\r\n", msg); }

static void resp_integer(long long n) { printf(":%lld\r\n", n); }

static void resp_bulk_string(const char *data, int len) {
  printf("$%d\r\n", len);
  if (len > 0)
    fwrite(data, 1, (size_t)len, stdout);
  printf("\r\n");
}

static void resp_bulk_cstr(const char *s) {
  resp_bulk_string(s, (int)strlen(s));
}

static void resp_null_bulk(void) { printf("$-1\r\n"); }

/* ---------- argument parsing (unchanged) ---------- */

int parse_args(char *line, char *args[], int max_args) {
  int count = 0;
  int in_quotes = 0;
  char *start = NULL;

  for (char *p = line; *p && count < max_args; p++) {
    if (*p == '"' && !in_quotes) {
      in_quotes = 1;
      start = p + 1;
    } else if (*p == '"' && in_quotes) {
      in_quotes = 0;
      *p = '\0';
      args[count++] = start;
      start = NULL;
    } else if (*p == ' ' && !in_quotes) {
      if (start) {
        *p = '\0';
        args[count++] = start;
        start = NULL;
      }
    } else if (!start) {
      start = p;
    }
  }
  if (start && count < max_args)
    args[count++] = start;
  return count;
}

void str_toupper(char *s) {
  for (; *s; s++)
    *s = toupper((unsigned char)*s);
}

/* ---------- command handling ---------- */

void handle_command(char *args[], int argc) {
  char cmd[256];
  strncpy(cmd, args[0], sizeof(cmd) - 1);
  cmd[sizeof(cmd) - 1] = '\0';
  str_toupper(cmd);

  if (strcmp(cmd, "PING") == 0) {
    if (argc == 1) {
      resp_simple_string("PONG");
    } else if (argc == 2) {
      resp_bulk_cstr(args[1]);
    } else {
      resp_error("ERR wrong number of arguments for 'ping' command");
    }
    fflush(stdout);
    return;
  }

  if (strcmp(cmd, "ECHO") == 0) {
    if (argc != 2) {
      resp_error("ERR wrong number of arguments for 'echo' command");
    } else {
      resp_bulk_cstr(args[1]);
    }
    fflush(stdout);
    return;
  }

  if (strcmp(cmd, "COMMAND") == 0) {
    if (argc == 2 && strcmp(args[1], "DOCS") == 0) {
      resp_simple_string("OK");
    } else {
      resp_error(
          "ERR unknown subcommand or wrong number of arguments for 'command'");
    }
    fflush(stdout);
    return;
  }

  /* unknown command: echo back the original (case-preserved) command name */
  char err[512];
  snprintf(err, sizeof(err), "ERR unknown command '%s'", args[0]);
  resp_error(err);
  fflush(stdout);
}

/* ---------- main (unchanged) ---------- */

int main(void) {
  char line[MAX_LINE];
  char *args[MAX_ARGS];

  while (fgets(line, sizeof(line), stdin)) {
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == '\0')
      continue;
    int argc = parse_args(line, args, MAX_ARGS);
    if (argc > 0)
      handle_command(args, argc);
  }
  return 0;
}
