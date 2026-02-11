#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct Entry Entry;

#ifndef LDAP_SUCCESS
#define LDAP_SUCCESS 0
#endif
#ifndef LDAP_CONSTRAINT_VIOLATION
#define LDAP_CONSTRAINT_VIOLATION 19
#endif

#define CONF_PATH "/etc/ldap/check_password.conf"

struct cfg {
  int minPoints;
  int minUpper;
  int minLower;
  int minDigit;
  int minPunct;
  int minLength;
};

static void cfg_defaults(struct cfg *c) {
  memset(c, 0, sizeof(*c));
}

static int parse_int(const char *s, int *out) {
  char *end = NULL;
  long v = strtol(s, &end, 10);
  if (end == s) {
    return -1;
  }
  if (v < 0) {
    v = 0;
  }
  *out = (int)v;
  return 0;
}

static void cfg_load(struct cfg *c) {
  FILE *f = fopen(CONF_PATH, "r");
  if (!f) {
    return;
  }

  char line[256];
  while (fgets(line, sizeof(line), f)) {
    char *hash = strchr(line, '#');
    if (hash) {
      *hash = '\0';
    }
    char *p = line;
    while (*p && isspace((unsigned char)*p)) {
      ++p;
    }
    if (*p == '\0') {
      continue;
    }

    char key[64];
    char val[64];
    if (sscanf(p, "%63s %63s", key, val) != 2) {
      continue;
    }
    int v = 0;
    if (parse_int(val, &v) != 0) {
      continue;
    }

    if (strcasecmp(key, "minPoints") == 0) {
      c->minPoints = v;
    } else if (strcasecmp(key, "minUpper") == 0) {
      c->minUpper = v;
    } else if (strcasecmp(key, "minLower") == 0) {
      c->minLower = v;
    } else if (strcasecmp(key, "minDigit") == 0) {
      c->minDigit = v;
    } else if (strcasecmp(key, "minPunct") == 0) {
      c->minPunct = v;
    } else if (strcasecmp(key, "minLength") == 0) {
      c->minLength = v;
    }
  }

  fclose(f);
}

static int fail(char **ppErrStr, const char *msg) {
  if (ppErrStr) {
    *ppErrStr = strdup(msg);
  }
  return LDAP_CONSTRAINT_VIOLATION;
}

int check_password(char *pPasswd, char **ppErrStr, Entry *pEntry) {
  (void)pEntry;

  if (!pPasswd || *pPasswd == '\0') {
    return fail(ppErrStr, "Password is empty");
  }

  struct cfg cfg;
  cfg_defaults(&cfg);
  cfg_load(&cfg);

  size_t len = strlen(pPasswd);
  if (cfg.minLength > 0 && (int)len < cfg.minLength) {
    return fail(ppErrStr, "Password is too short");
  }

  int upper = 0;
  int lower = 0;
  int digit = 0;
  int punct = 0;
  for (const unsigned char *p = (const unsigned char *)pPasswd; *p; ++p) {
    if (isupper(*p)) {
      upper++;
    } else if (islower(*p)) {
      lower++;
    } else if (isdigit(*p)) {
      digit++;
    } else if (ispunct(*p)) {
      punct++;
    }
  }

  if (cfg.minUpper > 0 && upper < cfg.minUpper) {
    return fail(ppErrStr, "Password needs more uppercase letters");
  }
  if (cfg.minLower > 0 && lower < cfg.minLower) {
    return fail(ppErrStr, "Password needs more lowercase letters");
  }
  if (cfg.minDigit > 0 && digit < cfg.minDigit) {
    return fail(ppErrStr, "Password needs more digits");
  }
  if (cfg.minPunct > 0 && punct < cfg.minPunct) {
    return fail(ppErrStr, "Password needs more punctuation");
  }

  int points = 0;
  if (upper > 0) {
    points++;
  }
  if (lower > 0) {
    points++;
  }
  if (digit > 0) {
    points++;
  }
  if (punct > 0) {
    points++;
  }
  if (cfg.minPoints > 0 && points < cfg.minPoints) {
    return fail(ppErrStr, "Password does not meet complexity requirements");
  }

  return LDAP_SUCCESS;
}

int init_module(int argc, char *argv[]) {
  (void)argc;
  (void)argv;
  return 0;
}
