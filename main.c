#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARGS 64

typedef struct {
  char *data;
  int len;
} Bulk;

/* ============================================================
 * Buffered binary-safe reader over stdin
 * ============================================================ */

typedef struct {
  unsigned char *buf;
  size_t cap, len, pos;
} Reader;

static void reader_init(Reader *r) {
  r->cap = 8192;
  r->len = 0;
  r->pos = 0;
  r->buf = (unsigned char *)malloc(r->cap);
}
static void reader_free(Reader *r) {
  free(r->buf);
  r->buf = NULL;
}

static int reader_fill(Reader *r) {
  if (r->pos < r->len)
    return 1;
  r->len = fread(r->buf, 1, r->cap, stdin);
  r->pos = 0;
  return r->len > 0;
}
static int reader_getc(Reader *r) {
  if (r->pos >= r->len && !reader_fill(r))
    return -1;
  return r->buf[r->pos++];
}
static int reader_read(Reader *r, unsigned char *out, size_t n) {
  size_t got = 0;
  while (got < n) {
    if (r->pos >= r->len && !reader_fill(r))
      return 0;
    size_t avail = r->len - r->pos;
    size_t take = (n - got < avail) ? (n - got) : avail;
    memcpy(out + got, r->buf + r->pos, take);
    r->pos += take;
    got += take;
  }
  return 1;
}

/* Read a header line terminated by CRLF or bare LF; strip terminator. */
static char *reader_readline(Reader *r) {
  size_t cap = 64, len = 0;
  char *out = (char *)malloc(cap);
  for (;;) {
    int c = reader_getc(r);
    if (c < 0) {
      free(out);
      return NULL;
    }
    if (c == '\n') {
      if (len > 0 && out[len - 1] == '\r')
        len--; /* strip optional CR */
      break;
    }
    if (len + 1 >= cap) {
      cap *= 2;
      out = (char *)realloc(out, cap);
    }
    out[len++] = (char)c;
  }
  out[len] = '\0';
  return out;
}

/* Consume the terminator after bulk data: CRLF or LF. Returns 1 on OK. */
static int reader_consume_terminator(Reader *r) {
  int c = reader_getc(r);
  if (c == '\n')
    return 1;
  if (c == '\r') {
    int c2 = reader_getc(r);
    return c2 == '\n';
  }
  return 0;
}

/* ============================================================
 * RESP request parser
 * ============================================================ */

static void free_args(Bulk args[], int argc) {
  for (int i = 0; i < argc; i++)
    free(args[i].data);
}

static int parse_request(Reader *r, Bulk args[], int max_args, char **errmsg) {
  int c = reader_getc(r);
  if (c < 0)
    return 0; /* clean EOF */
  if (c != '*') {
    *errmsg = strdup("ERR Protocol error: expected '*'");
    return -1;
  }

  char *line = reader_readline(r);
  if (!line) {
    *errmsg = strdup("ERR Protocol error: truncated array header");
    return -1;
  }

  char *endp = NULL;
  long n = strtol(line, &endp, 10);
  int bad = (!endp || *endp != '\0' || n < 0); /* check BEFORE freeing */
  free(line);
  if (bad) {
    *errmsg = strdup("ERR Protocol error: invalid multibulk length");
    return -1;
  }
  if (n == 0)
    return 0; /* empty array: no-op */
  if (n > max_args) {
    *errmsg = strdup("ERR Protocol error: too many arguments");
    return -1;
  }

  int argc = 0;
  for (long i = 0; i < n; i++) {
    int t = reader_getc(r);
    if (t != '$') {
      *errmsg = strdup("ERR Protocol error: expected '$'");
      free_args(args, argc);
      return -1;
    }
    char *lenline = reader_readline(r);
    if (!lenline) {
      *errmsg = strdup("ERR Protocol error: truncated bulk length");
      free_args(args, argc);
      return -1;
    }
    char *e2 = NULL;
    long blen = strtol(lenline, &e2, 10);
    int bad_len = (!e2 || *e2 != '\0' || blen < 0); /* check BEFORE freeing */
    free(lenline);
    if (bad_len) {
      *errmsg = strdup("ERR Protocol error: invalid bulk length");
      free_args(args, argc);
      return -1;
    }
    char *data = (char *)malloc((size_t)blen + 1);
    if (blen > 0 && !reader_read(r, (unsigned char *)data, (size_t)blen)) {
      free(data);
      *errmsg = strdup("ERR Protocol error: truncated bulk data");
      free_args(args, argc);
      return -1;
    }
    data[blen] = '\0';

    if (!reader_consume_terminator(r)) {
      free(data);
      *errmsg = strdup("ERR Protocol error: expected CRLF after bulk");
      free_args(args, argc);
      return -1;
    }

    args[argc].data = data;
    args[argc].len = (int)blen;
    argc++;
  }
  return argc;
}

/* ============================================================
 * RESP response serialization
 * ============================================================ */

static void resp_simple_string(const char *s) { printf("+%s\r\n", s); }
static void resp_error(const char *msg) { printf("-%s\r\n", msg); }
static void resp_integer(long long n) { printf(":%lld\r\n", n); }
static void resp_bulk(const char *data, int len) {
  printf("$%d\r\n", len);
  if (len > 0)
    fwrite(data, 1, (size_t)len, stdout);
  printf("\r\n");
}
static void resp_null_bulk(void) { printf("$-1\r\n"); }

/* ============================================================
 * In-memory store (binary-safe)
 * ============================================================ */

typedef struct Entry {
  char *key;
  int klen;
  char *val;
  int vlen;
  struct Entry *next;
} Entry;
static Entry *store = NULL;

static Entry *store_find(const char *key, int klen) {
  for (Entry *e = store; e; e = e->next)
    if (e->klen == klen && memcmp(e->key, key, (size_t)klen) == 0)
      return e;
  return NULL;
}
static void store_set(const char *key, int klen, const char *val, int vlen) {
  Entry *e = store_find(key, klen);
  if (e) {
    free(e->val);
    e->val = (char *)malloc((size_t)vlen);
    memcpy(e->val, val, (size_t)vlen);
    e->vlen = vlen;
    return;
  }
  e = (Entry *)malloc(sizeof(Entry));
  e->key = (char *)malloc((size_t)klen);
  memcpy(e->key, key, (size_t)klen);
  e->klen = klen;
  e->val = (char *)malloc((size_t)vlen);
  memcpy(e->val, val, (size_t)vlen);
  e->vlen = vlen;
  e->next = store;
  store = e;
}

/* ============================================================
 * Command table + arity
 * ============================================================ */

typedef struct {
  const char *name;
  int min_args;
  int max_args;
} CommandSpec;

static const CommandSpec COMMANDS[] = {
    {"PING", 0, 1},
    {"ECHO", 1, 1},
    {"SET", 2, 2},
    {"GET", 1, 1},
};
static const int NUM_COMMANDS = (int)(sizeof(COMMANDS) / sizeof(COMMANDS[0]));

static const CommandSpec *lookup_command(const char *upper_cmd) {
  for (int i = 0; i < NUM_COMMANDS; i++)
    if (strcmp(COMMANDS[i].name, upper_cmd) == 0)
      return &COMMANDS[i];
  return NULL;
}

static int check_arity(const CommandSpec *spec, int argc) {
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
 * Dispatcher (command name uppercased on a copy only)
 * ============================================================ */

static void handle_command(Bulk args[], int argc) {
  char cmd[256];
  int cmdlen = args[0].len;
  if (cmdlen > (int)sizeof(cmd) - 1)
    cmdlen = (int)sizeof(cmd) - 1;
  memcpy(cmd, args[0].data, (size_t)cmdlen);
  cmd[cmdlen] = '\0';
  for (int i = 0; i < cmdlen; i++)
    cmd[i] = (char)toupper((unsigned char)cmd[i]);

  const CommandSpec *spec = lookup_command(cmd);
  if (!spec) {
    char err[512];
    snprintf(err, sizeof(err), "ERR unknown command '%.*s'", args[0].len,
             args[0].data);
    resp_error(err);
    fflush(stdout);
    return;
  }
  if (!check_arity(spec, argc)) {
    fflush(stdout);
    return;
  }

  if (strcmp(cmd, "PING") == 0) {
    if (argc == 1)
      resp_simple_string("PONG");
    else
      resp_bulk(args[1].data, args[1].len);
  } else if (strcmp(cmd, "ECHO") == 0) {
    resp_bulk(args[1].data, args[1].len);
  } else if (strcmp(cmd, "SET") == 0) {
    store_set(args[1].data, args[1].len, args[2].data, args[2].len);
    resp_simple_string("OK");
  } else if (strcmp(cmd, "GET") == 0) {
    Entry *e = store_find(args[1].data, args[1].len);
    if (e)
      resp_bulk(e->val, e->vlen);
    else
      resp_null_bulk();
  }
  fflush(stdout);
}

/* ============================================================
 * Main
 * ============================================================ */

int main(void) {
  Reader r;
  reader_init(&r);
  Bulk args[MAX_ARGS];
  for (;;) {
    char *errmsg = NULL;
    int argc = parse_request(&r, args, MAX_ARGS, &errmsg);
    if (argc == 0 && errmsg == NULL)
      break;
    if (argc < 0) {
      resp_error(errmsg);
      free(errmsg);
      fflush(stdout);
      break;
    }
    if (argc > 0)
      handle_command(args, argc);
    free_args(args, argc);
  }
  reader_free(&r);
  return 0;
}
