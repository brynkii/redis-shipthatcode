#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARGS 64

typedef struct {
  char *data;
  int len;
} Bulk;

/* ============================================================
 * Buffered reader over stdin (binary safe)
 * ============================================================ */

typedef struct {
  unsigned char *buf;
  size_t cap, len, pos;
  int peeked;
} Reader;

static void reader_init(Reader *r) {
  r->cap = 8192;
  r->len = 0;
  r->pos = 0;
  r->peeked = -1;
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
  if (r->peeked >= 0) {
    int c = r->peeked;
    r->peeked = -1;
    return c;
  }
  if (r->pos >= r->len && !reader_fill(r))
    return -1;
  return r->buf[r->pos++];
}
static int reader_peekc(Reader *r) {
  if (r->peeked >= 0)
    return r->peeked;
  if (r->pos >= r->len && !reader_fill(r))
    return -1;
  r->peeked = r->buf[r->pos++];
  return r->peeked;
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
        len--;
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

static char *reader_read_rawline(Reader *r) {
  size_t cap = 128, len = 0;
  char *out = (char *)malloc(cap);
  for (;;) {
    int c = reader_getc(r);
    if (c < 0) {
      if (len == 0) {
        free(out);
        return NULL;
      }
      break;
    }
    if (c == '\n')
      break;
    if (len + 1 >= cap) {
      cap *= 2;
      out = (char *)realloc(out, cap);
    }
    out[len++] = (char)c;
  }
  if (len > 0 && out[len - 1] == '\r')
    len--;
  out[len] = '\0';
  return out;
}

/* ============================================================
 * RESP array request parser (binary safe)
 * ============================================================ */

static void free_args(Bulk args[], int argc) {
  for (int i = 0; i < argc; i++)
    free(args[i].data);
}

static int parse_resp_request(Reader *r, Bulk args[], int max_args,
                              char **errmsg) {
  int c = reader_getc(r);
  if (c < 0)
    return 0;
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
  int bad = (!endp || *endp != '\0' || n < 0);
  free(line);
  if (bad) {
    *errmsg = strdup("ERR Protocol error: invalid multibulk length");
    return -1;
  }
  if (n == 0)
    return 0;
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
    int bad_len = (!e2 || *e2 != '\0' || blen < 0);
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
 * Text line parser (space separated, "..." quoting)
 * ============================================================ */

static int parse_text_request(char *line, Bulk args[], int max_args) {
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
      args[count].data = start;
      args[count].len = (int)strlen(start);
      count++;
      start = NULL;
    } else if (*p == ' ' && !in_quotes) {
      if (start) {
        *p = '\0';
        args[count].data = start;
        args[count].len = (int)strlen(start);
        count++;
        start = NULL;
      }
    } else if (!start) {
      start = p;
    }
  }
  if (start && count < max_args) {
    args[count].data = start;
    args[count].len = (int)strlen(start);
    count++;
  }
  return count;
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
 * In-memory hash map (binary-safe)
 * ============================================================ */

typedef struct {
  char *key;
  int klen;
  char *val;
  int vlen;
  int used;
} Slot;
typedef struct {
  Slot *slots;
  size_t cap, count;
} HashMap;

static uint64_t fnv1a(const void *data, size_t len) {
  const unsigned char *p = (const unsigned char *)data;
  uint64_t h = 1469598103934665603ULL;
  for (size_t i = 0; i < len; i++) {
    h ^= p[i];
    h *= 1099511628211ULL;
  }
  return h;
}

static void hm_init(HashMap *m, size_t cap) {
  size_t c = 8;
  while (c < cap)
    c <<= 1;
  m->cap = c;
  m->count = 0;
  m->slots = (Slot *)calloc(c, sizeof(Slot));
}
static void hm_free(HashMap *m) {
  for (size_t i = 0; i < m->cap; i++)
    if (m->slots[i].used) {
      free(m->slots[i].key);
      free(m->slots[i].val);
    }
  free(m->slots);
  m->slots = NULL;
  m->cap = m->count = 0;
}
static size_t hm_find_slot(const HashMap *m, const char *key, int klen) {
  uint64_t h = fnv1a(key, (size_t)klen);
  size_t mask = m->cap - 1, i = (size_t)h & mask;
  while (m->slots[i].used) {
    if (m->slots[i].klen == klen &&
        memcmp(m->slots[i].key, key, (size_t)klen) == 0)
      return i;
    i = (i + 1) & mask;
  }
  return i;
}
static void hm_grow(HashMap *m) {
  size_t newcap = m->cap * 2;
  Slot *old = m->slots;
  size_t oldcap = m->cap;
  m->slots = (Slot *)calloc(newcap, sizeof(Slot));
  m->cap = newcap;
  m->count = 0;
  for (size_t i = 0; i < oldcap; i++)
    if (old[i].used) {
      size_t j = hm_find_slot(m, old[i].key, old[i].klen);
      m->slots[j] = old[i];
      m->count++;
    }
  free(old);
}
static Slot *hm_get(HashMap *m, const char *key, int klen) {
  size_t i = hm_find_slot(m, key, klen);
  return m->slots[i].used ? &m->slots[i] : NULL;
}
static void hm_set(HashMap *m, const char *key, int klen, const char *val,
                   int vlen) {
  if ((m->count + 1) * 10 >= m->cap * 7)
    hm_grow(m);
  size_t i = hm_find_slot(m, key, klen);
  if (m->slots[i].used) {
    free(m->slots[i].val);
    m->slots[i].val = (char *)malloc((size_t)vlen);
    memcpy(m->slots[i].val, val, (size_t)vlen);
    m->slots[i].vlen = vlen;
    return;
  }
  m->slots[i].used = 1;
  m->slots[i].key = (char *)malloc((size_t)klen);
  memcpy(m->slots[i].key, key, (size_t)klen);
  m->slots[i].klen = klen;
  m->slots[i].val = (char *)malloc((size_t)vlen);
  memcpy(m->slots[i].val, val, (size_t)vlen);
  m->slots[i].vlen = vlen;
  m->count++;
}

static long hm_live_count(const HashMap *m) { return (long)m->count; }

static HashMap DB;

/* ============================================================
 * Integer parsing / arithmetic helpers
 * ============================================================ */

/* Strict base-10 signed 64-bit parse: optional +/- sign, then digits only.
 * Rejects "", "+", "-", "3.0", " 3", "0x10", and out-of-range. */
static int parse_ll_strict(const char *s, int len, long long *out) {
  if (len <= 0)
    return 0;
  int i = 0, neg = 0;
  if (s[0] == '-' || s[0] == '+') {
    neg = (s[0] == '-');
    i = 1;
  }
  if (i >= len)
    return 0;
  long long v = 0;
  for (; i < len; i++) {
    if (s[i] < '0' || s[i] > '9')
      return 0;
    int d = s[i] - '0';
    if (v > (9223372036854775807LL - d) / 10)
      return 0;
    v = v * 10 + d;
  }
  *out = neg ? -v : v;
  return 1;
}

/* Core INCR-family operation: key (args[key_idx]) += delta.
 * Missing key → current = 0. Writes back decimal, replies integer. */
static void do_incr_by(Bulk args[], int key_idx, long long delta) {
  Bulk *key = &args[key_idx];

  long long current = 0;
  Slot *s = hm_get(&DB, key->data, key->len);
  if (s) {
    if (!parse_ll_strict(s->val, s->vlen, &current)) {
      resp_error("ERR value is not an integer or out of range");
      return;
    }
  }

  /* overflow guard: current + delta must fit in int64 */
  if ((delta > 0 && current > LLONG_MAX - delta) ||
      (delta < 0 && current < LLONG_MIN - delta)) {
    resp_error("ERR increment or decrement would overflow");
    return;
  }
  long long n = current + delta;

  char buf[32];
  int blen = snprintf(buf, sizeof(buf), "%lld", n);
  hm_set(&DB, key->data, key->len, buf, blen);
  resp_integer(n);
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
    {"PING", 0, 1}, {"ECHO", 1, 1},   {"SET", 2, 4},
    {"GET", 1, 1},  {"DBSIZE", 0, 0}, {"INCR", 1, 1},
    {"DECR", 1, 1}, {"INCRBY", 2, 2}, {"DECRBY", 2, 2},
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
 * Dispatcher
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
    int nx = 0, xx = 0, bad_flag = 0;
    for (int i = 3; i < argc; i++) {
      char f[16];
      int flen = args[i].len;
      if (flen > (int)sizeof(f) - 1) {
        bad_flag = 1;
        break;
      }
      memcpy(f, args[i].data, (size_t)flen);
      f[flen] = '\0';
      for (int k = 0; k < flen; k++)
        f[k] = (char)toupper((unsigned char)f[k]);
      if (strcmp(f, "NX") == 0)
        nx = 1;
      else if (strcmp(f, "XX") == 0)
        xx = 1;
      else {
        bad_flag = 1;
        break;
      }
    }
    if (bad_flag || (nx && xx)) {
      resp_error("ERR syntax error");
    } else {
      int exists = (hm_get(&DB, args[1].data, args[1].len) != NULL);
      if ((nx && exists) || (xx && !exists)) {
        resp_null_bulk();
      } else {
        hm_set(&DB, args[1].data, args[1].len, args[2].data, args[2].len);
        resp_simple_string("OK");
      }
    }
  } else if (strcmp(cmd, "GET") == 0) {
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (s)
      resp_bulk(s->val, s->vlen);
    else
      resp_null_bulk();
  } else if (strcmp(cmd, "DBSIZE") == 0) {
    resp_integer(hm_live_count(&DB));
  } else if (strcmp(cmd, "INCR") == 0) {
    do_incr_by(args, 1, 1);
  } else if (strcmp(cmd, "DECR") == 0) {
    do_incr_by(args, 1, -1);
  } else if (strcmp(cmd, "INCRBY") == 0) {
    long long delta;
    if (!parse_ll_strict(args[2].data, args[2].len, &delta)) {
      resp_error("ERR value is not an integer or out of range");
    } else {
      do_incr_by(args, 1, delta);
    }
  } else if (strcmp(cmd, "DECRBY") == 0) {
    long long delta;
    if (!parse_ll_strict(args[2].data, args[2].len, &delta)) {
      resp_error("ERR value is not an integer or out of range");
    } else if (delta == LLONG_MIN) {
      resp_error("ERR increment or decrement would overflow");
    } else {
      do_incr_by(args, 1, -delta);
    }
  }
  fflush(stdout);
}

/* ============================================================
 * Main: auto-detect RESP array vs text line
 * ============================================================ */

int main(void) {
  hm_init(&DB, 1024);

  Reader r;
  reader_init(&r);
  Bulk args[MAX_ARGS];

  for (;;) {
    int first = reader_peekc(&r);
    if (first < 0)
      break;

    if (first == '*') {
      char *errmsg = NULL;
      int argc = parse_resp_request(&r, args, MAX_ARGS, &errmsg);
      if (argc < 0) {
        resp_error(errmsg);
        free(errmsg);
        fflush(stdout);
        break;
      }
      if (argc > 0)
        handle_command(args, argc);
      free_args(args, argc);
    } else {
      char *line = reader_read_rawline(&r);
      if (!line)
        break;
      if (line[0] != '\0') {
        int argc = parse_text_request(line, args, MAX_ARGS);
        if (argc > 0)
          handle_command(args, argc);
      }
      free(line);
    }
  }

  reader_free(&r);
  hm_free(&DB);
  return 0;
}
