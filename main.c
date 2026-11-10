#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARGS 64
#define WRONGTYPE_MSG                                                          \
  "WRONGTYPE Operation against a key holding the wrong kind of value"

typedef struct {
  char *data;
  int len;
} Bulk;

/* ============================================================
 * Virtual clock
 * ============================================================ */
static long long virtual_now_ms = 0;
static long long now_ms(void) { return virtual_now_ms; }

/* ============================================================
 * Buffered reader
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
  r->buf = malloc(r->cap);
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
    size_t avail = r->len - r->pos,
           take = (n - got < avail) ? (n - got) : avail;
    memcpy(out + got, r->buf + r->pos, take);
    r->pos += take;
    got += take;
  }
  return 1;
}
static char *reader_readline(Reader *r) {
  size_t cap = 64, len = 0;
  char *out = malloc(cap);
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
      out = realloc(out, cap);
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
  char *out = malloc(cap);
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
      out = realloc(out, cap);
    }
    out[len++] = (char)c;
  }
  if (len > 0 && out[len - 1] == '\r')
    len--;
  out[len] = '\0';
  return out;
}

/* ============================================================
 * RESP request parsers
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
    char *data = malloc((size_t)blen + 1);
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

static int parse_text_request(char *line, Bulk args[], int max_args) {
  int count = 0, in_quotes = 0;
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
 * RESP serialization
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
static void resp_array_header(int n) { printf("*%d\r\n", n); }

static void encode_array(const char **items, const int *lens, int count) {
  resp_array_header(count);
  for (int i = 0; i < count; i++)
    resp_bulk(items[i], lens[i]);
}

/* ============================================================
 * Common FNV-1a
 * ============================================================ */
static uint64_t fnv1a(const void *data, size_t len) {
  const unsigned char *p = (const unsigned char *)data;
  uint64_t h = 1469598103934665603ULL;
  for (size_t i = 0; i < len; i++) {
    h ^= p[i];
    h *= 1099511628211ULL;
  }
  return h;
}

/* ============================================================
 * Hash (inner) — open addressing with tombstones + insertion seq
 * ============================================================ */
static uint64_t hash_seq_counter = 0;

typedef struct HashField {
  char *field;
  int flen;
  char *value;
  int vlen;
  int used;
  uint64_t seq;
} HashField;

typedef struct {
  HashField *entries;
  size_t cap, count;
} Hash;

static void hash_init(Hash *h) {
  h->cap = 8;
  h->count = 0;
  h->entries = calloc(h->cap, sizeof(HashField));
}
static void hash_free(Hash *h) {
  for (size_t i = 0; i < h->cap; i++)
    if (h->entries[i].used == 1) {
      free(h->entries[i].field);
      free(h->entries[i].value);
    }
  free(h->entries);
  h->entries = NULL;
  h->cap = h->count = 0;
}

static size_t hash_find_slot(const Hash *h, const char *field, int flen) {
  uint64_t hv = fnv1a(field, (size_t)flen);
  size_t mask = h->cap - 1, i = (size_t)hv & mask;
  size_t first_tomb = (size_t)-1;
  while (h->entries[i].used != 0) {
    if (h->entries[i].used == 1 && h->entries[i].flen == flen &&
        memcmp(h->entries[i].field, field, (size_t)flen) == 0)
      return i;
    if (h->entries[i].used == 2 && first_tomb == (size_t)-1)
      first_tomb = i;
    i = (i + 1) & mask;
  }
  return (first_tomb != (size_t)-1) ? first_tomb : i;
}

static void hash_grow(Hash *h) {
  size_t newcap = h->cap * 2;
  HashField *old = h->entries;
  size_t oldcap = h->cap;
  h->entries = calloc(newcap, sizeof(HashField));
  h->cap = newcap;
  h->count = 0;
  for (size_t i = 0; i < oldcap; i++)
    if (old[i].used == 1) {
      size_t j = hash_find_slot(h, old[i].field, old[i].flen);
      h->entries[j] = old[i];
      h->count++;
    }
  free(old);
}

static HashField *hash_get(Hash *h, const char *field, int flen) {
  size_t i = hash_find_slot(h, field, flen);
  return (h->entries[i].used == 1) ? &h->entries[i] : NULL;
}

static int hash_set(Hash *h, const char *field, int flen, const char *value,
                    int vlen) {
  if ((h->count + 1) * 10 >= h->cap * 7)
    hash_grow(h);
  size_t i = hash_find_slot(h, field, flen);
  if (h->entries[i].used == 1) {
    free(h->entries[i].value);
    h->entries[i].value = malloc((size_t)vlen);
    memcpy(h->entries[i].value, value, (size_t)vlen);
    h->entries[i].vlen = vlen;
    return 0;
  }
  h->entries[i].used = 1;
  h->entries[i].field = malloc((size_t)flen);
  memcpy(h->entries[i].field, field, (size_t)flen);
  h->entries[i].flen = flen;
  h->entries[i].value = malloc((size_t)vlen);
  memcpy(h->entries[i].value, value, (size_t)vlen);
  h->entries[i].vlen = vlen;
  h->entries[i].seq = ++hash_seq_counter;
  h->count++;
  return 1;
}

static int hash_del(Hash *h, const char *field, int flen) {
  size_t i = hash_find_slot(h, field, flen);
  if (h->entries[i].used != 1)
    return 0;
  free(h->entries[i].field);
  free(h->entries[i].value);
  h->entries[i].field = NULL;
  h->entries[i].value = NULL;
  h->entries[i].flen = h->entries[i].vlen = 0;
  h->entries[i].seq = 0;
  h->entries[i].used = 2;
  h->count--;
  return 1;
}

static int cmp_seq(const void *a, const void *b) {
  const HashField *fa = *(const HashField *const *)a;
  const HashField *fb = *(const HashField *const *)b;
  if (fa->seq < fb->seq)
    return -1;
  if (fa->seq > fb->seq)
    return 1;
  return 0;
}

/* ============================================================
 * Set (inner) — open addressing with tombstones, no ordering
 * ============================================================ */
typedef struct SetMember {
  char *data;
  int len;
  int used;
} SetMember;

typedef struct {
  SetMember *entries;
  size_t cap, count;
} Set;

static void set_init(Set *s) {
  s->cap = 8;
  s->count = 0;
  s->entries = calloc(s->cap, sizeof(SetMember));
}
static void set_free(Set *s) {
  for (size_t i = 0; i < s->cap; i++)
    if (s->entries[i].used == 1)
      free(s->entries[i].data);
  free(s->entries);
  s->entries = NULL;
  s->cap = s->count = 0;
}

static size_t set_find_slot(const Set *s, const char *data, int len) {
  uint64_t hv = fnv1a(data, (size_t)len);
  size_t mask = s->cap - 1, i = (size_t)hv & mask;
  size_t first_tomb = (size_t)-1;
  while (s->entries[i].used != 0) {
    if (s->entries[i].used == 1 && s->entries[i].len == len &&
        memcmp(s->entries[i].data, data, (size_t)len) == 0)
      return i;
    if (s->entries[i].used == 2 && first_tomb == (size_t)-1)
      first_tomb = i;
    i = (i + 1) & mask;
  }
  return (first_tomb != (size_t)-1) ? first_tomb : i;
}

static void set_grow(Set *s) {
  size_t newcap = s->cap * 2;
  SetMember *old = s->entries;
  size_t oldcap = s->cap;
  s->entries = calloc(newcap, sizeof(SetMember));
  s->cap = newcap;
  s->count = 0;
  for (size_t i = 0; i < oldcap; i++)
    if (old[i].used == 1) {
      size_t j = set_find_slot(s, old[i].data, old[i].len);
      s->entries[j] = old[i];
      s->count++;
    }
  free(old);
}

static SetMember *set_get(Set *s, const char *data, int len) {
  size_t i = set_find_slot(s, data, len);
  return (s->entries[i].used == 1) ? &s->entries[i] : NULL;
}

static int set_add(Set *s, const char *data, int len) {
  if ((s->count + 1) * 10 >= s->cap * 7)
    set_grow(s);
  size_t i = set_find_slot(s, data, len);
  if (s->entries[i].used == 1)
    return 0;
  s->entries[i].used = 1;
  s->entries[i].data = malloc((size_t)len);
  memcpy(s->entries[i].data, data, (size_t)len);
  s->entries[i].len = len;
  s->count++;
  return 1;
}

static int set_remove(Set *s, const char *data, int len) {
  size_t i = set_find_slot(s, data, len);
  if (s->entries[i].used != 1)
    return 0;
  free(s->entries[i].data);
  s->entries[i].data = NULL;
  s->entries[i].len = 0;
  s->entries[i].used = 2;
  s->count--;
  return 1;
}

/* ============================================================
 * Top-level store
 * ============================================================ */
typedef enum { T_STR = 1, T_LIST = 2, T_HASH = 3, T_SET = 4 } ValueType;

typedef struct ListNode {
  char *data;
  int len;
  struct ListNode *prev, *next;
} ListNode;

typedef struct {
  ListNode *head, *tail;
  long len;
} List;

typedef struct {
  char *key;
  int klen;
  int used;
  long long expire_at_ms;
  ValueType type;
  char *val;
  int vlen;
  List list;
  Hash hash;
  Set set;
} Slot;

typedef struct {
  Slot *slots;
  size_t cap, count;
} HashMap;

static void list_free(List *l) {
  ListNode *n = l->head;
  while (n) {
    ListNode *next = n->next;
    free(n->data);
    free(n);
    n = next;
  }
  l->head = l->tail = NULL;
  l->len = 0;
}

static void slot_clear(Slot *s) {
  free(s->key);
  s->key = NULL;
  s->klen = 0;
  if (s->type == T_LIST)
    list_free(&s->list);
  else if (s->type == T_HASH)
    hash_free(&s->hash);
  else if (s->type == T_SET)
    set_free(&s->set);
  else {
    free(s->val);
    s->val = NULL;
    s->vlen = 0;
  }
  s->expire_at_ms = 0;
  s->type = T_STR;
  s->used = 2;
}

static void hm_init(HashMap *m, size_t cap) {
  size_t c = 8;
  while (c < cap)
    c <<= 1;
  m->cap = c;
  m->count = 0;
  m->slots = calloc(c, sizeof(Slot));
}
static void hm_free(HashMap *m) {
  for (size_t i = 0; i < m->cap; i++)
    if (m->slots[i].used == 1)
      slot_clear(&m->slots[i]);
  free(m->slots);
  m->slots = NULL;
  m->cap = m->count = 0;
}

static size_t hm_find_slot(const HashMap *m, const char *key, int klen) {
  uint64_t h = fnv1a(key, (size_t)klen);
  size_t mask = m->cap - 1, i = (size_t)h & mask;
  size_t first_tomb = (size_t)-1;
  while (m->slots[i].used != 0) {
    if (m->slots[i].used == 1 && m->slots[i].klen == klen &&
        memcmp(m->slots[i].key, key, (size_t)klen) == 0)
      return i;
    if (m->slots[i].used == 2 && first_tomb == (size_t)-1)
      first_tomb = i;
    i = (i + 1) & mask;
  }
  return (first_tomb != (size_t)-1) ? first_tomb : i;
}

static void hm_grow(HashMap *m) {
  size_t newcap = m->cap * 2;
  Slot *old = m->slots;
  size_t oldcap = m->cap;
  m->slots = calloc(newcap, sizeof(Slot));
  m->cap = newcap;
  m->count = 0;
  for (size_t i = 0; i < oldcap; i++)
    if (old[i].used == 1) {
      size_t j = hm_find_slot(m, old[i].key, old[i].klen);
      m->slots[j] = old[i];
      m->count++;
    }
  free(old);
}

static Slot *hm_get(HashMap *m, const char *key, int klen) {
  size_t i = hm_find_slot(m, key, klen);
  return (m->slots[i].used == 1) ? &m->slots[i] : NULL;
}

static void hm_set_str(HashMap *m, const char *key, int klen, const char *val,
                       int vlen, long long expire_at_ms) {
  if ((m->count + 1) * 10 >= m->cap * 7)
    hm_grow(m);
  size_t i = hm_find_slot(m, key, klen);
  if (m->slots[i].used == 1) {
    if (m->slots[i].type == T_LIST)
      list_free(&m->slots[i].list);
    else if (m->slots[i].type == T_HASH)
      hash_free(&m->slots[i].hash);
    else if (m->slots[i].type == T_SET)
      set_free(&m->slots[i].set);
    else
      free(m->slots[i].val);
    m->slots[i].type = T_STR;
    m->slots[i].val = malloc((size_t)vlen);
    memcpy(m->slots[i].val, val, (size_t)vlen);
    m->slots[i].vlen = vlen;
    m->slots[i].expire_at_ms = expire_at_ms;
    return;
  }
  m->slots[i].used = 1;
  m->slots[i].key = malloc((size_t)klen);
  memcpy(m->slots[i].key, key, (size_t)klen);
  m->slots[i].klen = klen;
  m->slots[i].type = T_STR;
  m->slots[i].val = malloc((size_t)vlen);
  memcpy(m->slots[i].val, val, (size_t)vlen);
  m->slots[i].vlen = vlen;
  m->slots[i].expire_at_ms = expire_at_ms;
  m->slots[i].list.head = m->slots[i].list.tail = NULL;
  m->slots[i].list.len = 0;
  m->count++;
}

static void hm_set_list(HashMap *m, const char *key, int klen,
                        long long expire_at_ms) {
  if ((m->count + 1) * 10 >= m->cap * 7)
    hm_grow(m);
  size_t i = hm_find_slot(m, key, klen);
  if (m->slots[i].used == 1) {
    m->slots[i].expire_at_ms = expire_at_ms;
    return;
  }
  m->slots[i].used = 1;
  m->slots[i].key = malloc((size_t)klen);
  memcpy(m->slots[i].key, key, (size_t)klen);
  m->slots[i].klen = klen;
  m->slots[i].type = T_LIST;
  m->slots[i].val = NULL;
  m->slots[i].vlen = 0;
  m->slots[i].expire_at_ms = expire_at_ms;
  m->slots[i].list.head = m->slots[i].list.tail = NULL;
  m->slots[i].list.len = 0;
  m->count++;
}

static void hm_set_hash(HashMap *m, const char *key, int klen,
                        long long expire_at_ms) {
  if ((m->count + 1) * 10 >= m->cap * 7)
    hm_grow(m);
  size_t i = hm_find_slot(m, key, klen);
  if (m->slots[i].used == 1) {
    m->slots[i].expire_at_ms = expire_at_ms;
    return;
  }
  m->slots[i].used = 1;
  m->slots[i].key = malloc((size_t)klen);
  memcpy(m->slots[i].key, key, (size_t)klen);
  m->slots[i].klen = klen;
  m->slots[i].type = T_HASH;
  m->slots[i].val = NULL;
  m->slots[i].vlen = 0;
  m->slots[i].expire_at_ms = expire_at_ms;
  m->slots[i].list.head = m->slots[i].list.tail = NULL;
  m->slots[i].list.len = 0;
  hash_init(&m->slots[i].hash);
  m->count++;
}

static void hm_set_set(HashMap *m, const char *key, int klen,
                       long long expire_at_ms) {
  if ((m->count + 1) * 10 >= m->cap * 7)
    hm_grow(m);
  size_t i = hm_find_slot(m, key, klen);
  if (m->slots[i].used == 1) {
    m->slots[i].expire_at_ms = expire_at_ms;
    return;
  }
  m->slots[i].used = 1;
  m->slots[i].key = malloc((size_t)klen);
  memcpy(m->slots[i].key, key, (size_t)klen);
  m->slots[i].klen = klen;
  m->slots[i].type = T_SET;
  m->slots[i].val = NULL;
  m->slots[i].vlen = 0;
  m->slots[i].expire_at_ms = expire_at_ms;
  m->slots[i].list.head = m->slots[i].list.tail = NULL;
  m->slots[i].list.len = 0;
  set_init(&m->slots[i].set);
  m->count++;
}

static HashMap DB;

static int expire_if_needed_impl(const char *key, int klen) {
  Slot *s = hm_get(&DB, key, klen);
  if (!s)
    return 0;
  if (s->expire_at_ms != 0 && now_ms() >= s->expire_at_ms) {
    slot_clear(s);
    DB.count--;
    return 1;
  }
  return 0;
}

static long hm_live_count(HashMap *m) {
  long n = 0;
  for (size_t i = 0; i < m->cap; i++)
    if (m->slots[i].used == 1 &&
        (m->slots[i].expire_at_ms == 0 || now_ms() < m->slots[i].expire_at_ms))
      n++;
  return n;
}

/* ============================================================
 * List operations
 * ============================================================ */
static ListNode *list_node_new(const char *data, int len) {
  ListNode *n = malloc(sizeof *n);
  n->data = malloc((size_t)len);
  memcpy(n->data, data, (size_t)len);
  n->len = len;
  n->prev = n->next = NULL;
  return n;
}
static void list_push_head(List *l, const char *data, int len) {
  ListNode *n = list_node_new(data, len);
  n->next = l->head;
  if (l->head)
    l->head->prev = n;
  else
    l->tail = n;
  l->head = n;
  l->len++;
}
static void list_push_tail(List *l, const char *data, int len) {
  ListNode *n = list_node_new(data, len);
  n->prev = l->tail;
  if (l->tail)
    l->tail->next = n;
  else
    l->head = n;
  l->tail = n;
  l->len++;
}
static int list_pop_head(List *l, char **out_data, int *out_len) {
  if (!l->head)
    return 0;
  ListNode *n = l->head;
  l->head = n->next;
  if (l->head)
    l->head->prev = NULL;
  else
    l->tail = NULL;
  l->len--;
  *out_data = n->data;
  *out_len = n->len;
  free(n);
  return 1;
}
static int list_pop_tail(List *l, char **out_data, int *out_len) {
  if (!l->tail)
    return 0;
  ListNode *n = l->tail;
  l->tail = n->prev;
  if (l->tail)
    l->tail->next = NULL;
  else
    l->head = NULL;
  l->len--;
  *out_data = n->data;
  *out_len = n->len;
  free(n);
  return 1;
}

/* ============================================================
 * Integer helpers
 * ============================================================ */
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

static void do_incr_by(Bulk args[], int key_idx, long long delta) {
  Bulk *key = &args[key_idx];
  expire_if_needed_impl(key->data, key->len);

  long long current = 0;
  Slot *s = hm_get(&DB, key->data, key->len);
  if (s) {
    if (s->type != T_STR) {
      resp_error(WRONGTYPE_MSG);
      return;
    }
    if (!parse_ll_strict(s->val, s->vlen, &current)) {
      resp_error("ERR value is not an integer or out of range");
      return;
    }
  }
  if ((delta > 0 && current > LLONG_MAX - delta) ||
      (delta < 0 && current < LLONG_MIN - delta)) {
    resp_error("ERR increment or decrement would overflow");
    return;
  }
  long long n = current + delta;
  char buf[32];
  int blen = snprintf(buf, sizeof(buf), "%lld", n);
  hm_set_str(&DB, key->data, key->len, buf, blen, 0);
  resp_integer(n);
}

/* ============================================================
 * Command table
 * ============================================================ */
typedef struct {
  const char *name;
  int min_args;
  int max_args;
} CommandSpec;

static const CommandSpec COMMANDS[] = {
    {"PING", 0, 1},     {"ECHO", 1, 1},      {"SET", 2, 6},    {"GET", 1, 1},
    {"EXISTS", 1, 1},   {"DBSIZE", 0, 0},    {"INCR", 1, 1},   {"DECR", 1, 1},
    {"INCRBY", 2, 2},   {"DECRBY", 2, 2},    {"EXPIRE", 2, 2}, {"TTL", 1, 1},
    {"PTTL", 1, 1},     {"PERSIST", 1, 1},   {"WAIT", 1, 1},   {"LPUSH", 2, -1},
    {"RPUSH", 2, -1},   {"LRANGE", 3, 3},    {"LPOP", 1, 1},   {"RPOP", 1, 1},
    {"LLEN", 1, 1},     {"HSET", 3, -1},     {"HGET", 2, 2},   {"HDEL", 2, -1},
    {"HGETALL", 1, 1},  {"HEXISTS", 2, 2},   {"HLEN", 1, 1},   {"SADD", 2, -1},
    {"SMEMBERS", 1, 1}, {"SISMEMBER", 2, 2}, {"SCARD", 1, 1},  {"SREM", 2, -1},
};
static const int NUM_COMMANDS = (int)(sizeof(COMMANDS) / sizeof(COMMANDS[0]));

static const CommandSpec *lookup_command(const char *u) {
  for (int i = 0; i < NUM_COMMANDS; i++)
    if (strcmp(COMMANDS[i].name, u) == 0)
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
    int nx = 0, xx = 0, have_ex = 0, have_px = 0, bad_flag = 0, non_int = 0;
    long long ttl_ms = 0;
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
      else if (strcmp(f, "EX") == 0 || strcmp(f, "PX") == 0) {
        if (i + 1 >= argc) {
          bad_flag = 1;
          break;
        }
        long long n;
        if (!parse_ll_strict(args[i + 1].data, args[i + 1].len, &n) || n < 0) {
          non_int = 1;
          break;
        }
        if (strcmp(f, "EX") == 0) {
          have_ex = 1;
          ttl_ms = n * 1000LL;
        } else {
          have_px = 1;
          ttl_ms = n;
        }
        i++;
      } else {
        bad_flag = 1;
        break;
      }
    }
    if (non_int)
      resp_error("ERR value is not an integer or out of range");
    else if (bad_flag || (nx && xx) || (have_ex && have_px))
      resp_error("ERR syntax error");
    else {
      expire_if_needed_impl(args[1].data, args[1].len);
      Slot *s = hm_get(&DB, args[1].data, args[1].len);
      int exists = (s != NULL);
      if (nx && exists)
        resp_null_bulk();
      else if (xx && !exists)
        resp_null_bulk();
      else if (s && s->type != T_STR)
        resp_error(WRONGTYPE_MSG);
      else {
        long long deadline = (ttl_ms > 0) ? now_ms() + ttl_ms : 0;
        hm_set_str(&DB, args[1].data, args[1].len, args[2].data, args[2].len,
                   deadline);
        resp_simple_string("OK");
      }
    }
  } else if (strcmp(cmd, "GET") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s)
      resp_null_bulk();
    else if (s->type != T_STR)
      resp_error(WRONGTYPE_MSG);
    else
      resp_bulk(s->val, s->vlen);
  } else if (strcmp(cmd, "EXISTS") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    resp_integer(s ? 1 : 0);
  } else if (strcmp(cmd, "DBSIZE") == 0) {
    resp_integer(hm_live_count(&DB));
  } else if (strcmp(cmd, "INCR") == 0)
    do_incr_by(args, 1, 1);
  else if (strcmp(cmd, "DECR") == 0)
    do_incr_by(args, 1, -1);
  else if (strcmp(cmd, "INCRBY") == 0) {
    long long d;
    if (!parse_ll_strict(args[2].data, args[2].len, &d))
      resp_error("ERR value is not an integer or out of range");
    else
      do_incr_by(args, 1, d);
  } else if (strcmp(cmd, "DECRBY") == 0) {
    long long d;
    if (!parse_ll_strict(args[2].data, args[2].len, &d))
      resp_error("ERR value is not an integer or out of range");
    else if (d == LLONG_MIN)
      resp_error("ERR increment or decrement would overflow");
    else
      do_incr_by(args, 1, -d);
  } else if (strcmp(cmd, "EXPIRE") == 0) {
    long long secs;
    if (!parse_ll_strict(args[2].data, args[2].len, &secs)) {
      resp_error("ERR value is not an integer or out of range");
    } else {
      expire_if_needed_impl(args[1].data, args[1].len);
      Slot *s = hm_get(&DB, args[1].data, args[1].len);
      if (!s)
        resp_integer(0);
      else if (secs <= 0) {
        slot_clear(s);
        DB.count--;
        resp_integer(1);
      } else {
        s->expire_at_ms = now_ms() + secs * 1000LL;
        resp_integer(1);
      }
    }
  } else if (strcmp(cmd, "TTL") == 0 || strcmp(cmd, "PTTL") == 0) {
    int is_pttl = (cmd[0] == 'P');
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s)
      resp_integer(-2);
    else if (s->expire_at_ms == 0)
      resp_integer(-1);
    else {
      long long rem = s->expire_at_ms - now_ms();
      if (rem <= 0)
        resp_integer(-2);
      else
        resp_integer(is_pttl ? rem : (rem + 500) / 1000);
    }
  } else if (strcmp(cmd, "PERSIST") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s || s->expire_at_ms == 0)
      resp_integer(0);
    else {
      s->expire_at_ms = 0;
      resp_integer(1);
    }
  } else if (strcmp(cmd, "WAIT") == 0) {
    long long ms;
    if (!parse_ll_strict(args[1].data, args[1].len, &ms) || ms < 0)
      resp_error("ERR value is not an integer or out of range");
    else {
      virtual_now_ms += ms;
      resp_simple_string("OK");
    }
  } else if (strcmp(cmd, "LPUSH") == 0 || strcmp(cmd, "RPUSH") == 0) {
    int is_lpush = (cmd[0] == 'L');
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (s && s->type != T_LIST) {
      resp_error(WRONGTYPE_MSG);
    } else {
      if (!s) {
        hm_set_list(&DB, args[1].data, args[1].len, 0);
        s = hm_get(&DB, args[1].data, args[1].len);
      }
      for (int i = 2; i < argc; i++) {
        if (is_lpush)
          list_push_head(&s->list, args[i].data, args[i].len);
        else
          list_push_tail(&s->list, args[i].data, args[i].len);
      }
      resp_integer(s->list.len);
    }
  } else if (strcmp(cmd, "LRANGE") == 0) {
    long long start, stop;
    if (!parse_ll_strict(args[2].data, args[2].len, &start) ||
        !parse_ll_strict(args[3].data, args[3].len, &stop)) {
      resp_error("ERR value is not an integer or out of range");
    } else {
      expire_if_needed_impl(args[1].data, args[1].len);
      Slot *s = hm_get(&DB, args[1].data, args[1].len);
      if (s && s->type != T_LIST) {
        resp_error(WRONGTYPE_MSG);
      } else {
        long n = s ? s->list.len : 0;
        if (start < 0)
          start += n;
        if (stop < 0)
          stop += n;
        if (start < 0)
          start = 0;
        if (stop >= n)
          stop = n - 1;
        if (n == 0 || start > stop) {
          resp_array_header(0);
        } else {
          int count = (int)(stop - start + 1);
          const char **items = malloc(sizeof(char *) * (size_t)count);
          int *lens = malloc(sizeof(int) * (size_t)count);
          ListNode *cur = s->list.head;
          for (long i = 0; i < start && cur; i++)
            cur = cur->next;
          for (int i = 0; i < count && cur; i++) {
            items[i] = cur->data;
            lens[i] = cur->len;
            cur = cur->next;
          }
          encode_array(items, lens, count);
          free(items);
          free(lens);
        }
      }
    }
  } else if (strcmp(cmd, "LPOP") == 0 || strcmp(cmd, "RPOP") == 0) {
    int is_lpop = (cmd[0] == 'L');
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s) {
      resp_null_bulk();
    } else if (s->type != T_LIST)
      resp_error(WRONGTYPE_MSG);
    else {
      char *pdata = NULL;
      int plen = 0;
      int ok = is_lpop ? list_pop_head(&s->list, &pdata, &plen)
                       : list_pop_tail(&s->list, &pdata, &plen);
      if (!ok) {
        resp_null_bulk();
      } else {
        resp_bulk(pdata, plen);
        free(pdata);
        if (s->list.len == 0) {
          slot_clear(s);
          DB.count--;
        }
      }
    }
  } else if (strcmp(cmd, "LLEN") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s)
      resp_integer(0);
    else if (s->type != T_LIST)
      resp_error(WRONGTYPE_MSG);
    else
      resp_integer(s->list.len);
  } else if (strcmp(cmd, "HSET") == 0) {
    int nargs = argc - 2;
    if (nargs % 2 != 0) {
      resp_error("ERR wrong number of arguments for 'hset' command");
    } else {
      expire_if_needed_impl(args[1].data, args[1].len);
      Slot *s = hm_get(&DB, args[1].data, args[1].len);
      if (s && s->type != T_HASH)
        resp_error(WRONGTYPE_MSG);
      else {
        if (!s) {
          hm_set_hash(&DB, args[1].data, args[1].len, 0);
          s = hm_get(&DB, args[1].data, args[1].len);
        }
        int new_count = 0;
        for (int i = 2; i + 1 < argc; i += 2)
          new_count += hash_set(&s->hash, args[i].data, args[i].len,
                                args[i + 1].data, args[i + 1].len);
        resp_integer(new_count);
      }
    }
  } else if (strcmp(cmd, "HGET") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s)
      resp_null_bulk();
    else if (s->type != T_HASH)
      resp_error(WRONGTYPE_MSG);
    else {
      HashField *f = hash_get(&s->hash, args[2].data, args[2].len);
      if (!f)
        resp_null_bulk();
      else
        resp_bulk(f->value, f->vlen);
    }
  } else if (strcmp(cmd, "HDEL") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s)
      resp_integer(0);
    else if (s->type != T_HASH)
      resp_error(WRONGTYPE_MSG);
    else {
      int removed = 0;
      for (int i = 2; i < argc; i++)
        removed += hash_del(&s->hash, args[i].data, args[i].len);
      if (s->hash.count == 0) {
        slot_clear(s);
        DB.count--;
      }
      resp_integer(removed);
    }
  } else if (strcmp(cmd, "HGETALL") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s) {
      resp_array_header(0);
    } else if (s->type != T_HASH)
      resp_error(WRONGTYPE_MSG);
    else {
      int live = (int)s->hash.count;
      if (live == 0)
        resp_array_header(0);
      else {
        HashField **fields = malloc(sizeof(HashField *) * (size_t)live);
        int k = 0;
        for (size_t i = 0; i < s->hash.cap; i++)
          if (s->hash.entries[i].used == 1)
            fields[k++] = &s->hash.entries[i];
        qsort(fields, (size_t)live, sizeof(HashField *), cmp_seq);
        resp_array_header(live * 2);
        for (int i = 0; i < live; i++) {
          resp_bulk(fields[i]->field, fields[i]->flen);
          resp_bulk(fields[i]->value, fields[i]->vlen);
        }
        free(fields);
      }
    }
  } else if (strcmp(cmd, "HEXISTS") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s)
      resp_integer(0);
    else if (s->type != T_HASH)
      resp_error(WRONGTYPE_MSG);
    else
      resp_integer(hash_get(&s->hash, args[2].data, args[2].len) ? 1 : 0);
  } else if (strcmp(cmd, "HLEN") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s)
      resp_integer(0);
    else if (s->type != T_HASH)
      resp_error(WRONGTYPE_MSG);
    else
      resp_integer((long long)s->hash.count);
  } else if (strcmp(cmd, "SADD") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (s && s->type != T_SET)
      resp_error(WRONGTYPE_MSG);
    else {
      if (!s) {
        hm_set_set(&DB, args[1].data, args[1].len, 0);
        s = hm_get(&DB, args[1].data, args[1].len);
      }
      int added = 0;
      for (int i = 2; i < argc; i++)
        added += set_add(&s->set, args[i].data, args[i].len);
      resp_integer(added);
    }
  } else if (strcmp(cmd, "SMEMBERS") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s)
      resp_array_header(0);
    else if (s->type != T_SET)
      resp_error(WRONGTYPE_MSG);
    else {
      int n = (int)s->set.count;
      if (n == 0) {
        resp_array_header(0);
      } else {
        const char **items = malloc(sizeof(char *) * (size_t)n);
        int *lens = malloc(sizeof(int) * (size_t)n);
        int k = 0;
        for (size_t i = 0; i < s->set.cap; i++)
          if (s->set.entries[i].used == 1) {
            items[k] = s->set.entries[i].data;
            lens[k] = s->set.entries[i].len;
            k++;
          }
        encode_array(items, lens, n);
        free(items);
        free(lens);
      }
    }
  } else if (strcmp(cmd, "SISMEMBER") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s)
      resp_integer(0);
    else if (s->type != T_SET)
      resp_error(WRONGTYPE_MSG);
    else
      resp_integer(set_get(&s->set, args[2].data, args[2].len) ? 1 : 0);
  } else if (strcmp(cmd, "SCARD") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s)
      resp_integer(0);
    else if (s->type != T_SET)
      resp_error(WRONGTYPE_MSG);
    else
      resp_integer((long long)s->set.count);
  } else if (strcmp(cmd, "SREM") == 0) {
    expire_if_needed_impl(args[1].data, args[1].len);
    Slot *s = hm_get(&DB, args[1].data, args[1].len);
    if (!s)
      resp_integer(0);
    else if (s->type != T_SET)
      resp_error(WRONGTYPE_MSG);
    else {
      int removed = 0;
      for (int i = 2; i < argc; i++)
        removed += set_remove(&s->set, args[i].data, args[i].len);
      if (s->set.count == 0) {
        slot_clear(s);
        DB.count--;
      }
      resp_integer(removed);
    }
  }
  fflush(stdout);
}

/* ============================================================
 * Main
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
