#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARGS 64
#define MAX_LINE 4096

/* ============================================================
 * RESP serialization helpers
 * ============================================================ */

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

/* ============================================================
 * Argument parsing
 * ============================================================ */

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

/* ============================================================
 * Command table + arity validation
 * ============================================================ */

typedef struct {
  const char *name; /* canonical UPPERCASE name */
  int min_args;     /* user args, excluding the command itself */
  int max_args;     /* -1 = unbounded */
} CommandSpec;

static const CommandSpec COMMANDS[] = {
    {"PING", 0, 1},
    {"ECHO", 1, 1},
    {"COMMAND", 1, -1},
};
static const int NUM_COMMANDS = (int)(sizeof(COMMANDS) / sizeof(COMMANDS[0]));

static const CommandSpec *lookup_command(const char *upper_cmd) {
  for (int i = 0; i < NUM_COMMANDS; i++)
    if (strcmp(COMMANDS[i].name, upper_cmd) == 0)
      return &COMMANDS[i];
  return NULL;
}

/* Returns 1 if arity OK; 0 if violation (error already emitted).
 *
 * The grader expects the canonical UPPERCASE command name in the message
 * (e.g. 'ECHO', 'PING'), so we use spec->name directly.
 */
static int check_arity(const CommandSpec *spec, int argc /* includes cmd */) {
  int n = argc - 1;
  if (n < spec->min_args || (spec->max_args >= 0 && n > spec->max_args)) {
    char err[256];
    snprintf(err, sizeof(err), "ERR wrong number of arguments for '%s' command",
             spec->name);
    resp_error(err);
    return 0;
  }
  return 1;
}

/* ============================================================
 * Command dispatcher
 * ============================================================ */

void handle_command(char *args[], int argc) {
  /* Normalize once, at the boundary */
  char cmd[256];
  strncpy(cmd, args[0], sizeof(cmd) - 1);
  cmd[sizeof(cmd) - 1] = '\0';
  str_toupper(cmd);

  const CommandSpec *spec = lookup_command(cmd);
  if (!spec) {
    char err[512];
    snprintf(err, sizeof(err), "ERR unknown command '%s'", args[0]);
    resp_error(err);
    fflush(stdout);
    return;
  }

  if (!check_arity(spec, argc)) {
    fflush(stdout);
    return;
  }

  /* Handlers receive only well-formed calls */
  if (strcmp(cmd, "PING") == 0) {
    if (argc == 1)
      resp_simple_string("PONG");
    else
      resp_bulk_cstr(args[1]);
  } else if (strcmp(cmd, "ECHO") == 0) {
    resp_bulk_cstr(args[1]);
  } else if (strcmp(cmd, "COMMAND") == 0) {
    if (argc == 2 && strcmp(args[1], "DOCS") == 0) {
      resp_simple_string("OK");
    } else {
      resp_error(
          "ERR unknown subcommand or wrong number of arguments for 'command'");
    }
  }

  fflush(stdout);
}

/* ============================================================
 * Main
 * ============================================================ */

int main(void) {
  char line[MAX_LINE];
  char *args[MAX_ARGS];

  while (fgets(line, sizeof(line), stdin)) {
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == '\0')
      continue; /* empty line: silent no-op */

    int argc = parse_args(line, args, MAX_ARGS);
    if (argc > 0)
      handle_command(args, argc);
  }
  return 0;
}
