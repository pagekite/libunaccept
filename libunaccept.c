/* libunaccept - Adds simple network-based ACLs to the accept call, via
 *               LD_PRELOAD.
 * */
#ifndef RTLD_NEXT
#  define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <syslog.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>

#define ALLOW   0x00000001
#define DENY    0x00000002
#define TARPIT  0x00000004
#define BY_HOST 0x40000000
#define VERBOSE 0x80000000

int accept(int s, struct sockaddr *addr, socklen_t *addrlen);
static void _libunaccept_configure(void) __attribute__((constructor));

int (*lua_libc_accept)(int s, struct sockaddr *, socklen_t *);
int lua_configured = 0;
int lua_blocking = 0;
int lua_syslog = 0;

/* Rules variables */
int LUA_MAX_RULES = 100;
struct lua_rule {
  int policy;
  in_addr_t network;
  in_addr_t netmask;
  char *hostname;
} *lua_rules;
int lua_num_rules = 0;
char *lua_rulefile = "/etc/libunaccept.rc";
time_t lua_rules_mtime = 0;

/* Tarpitting variables*/
int LUA_TARPIT_SIZE = 100;
int *lua_tarpit = NULL;
int lua_num_tarpit = 0;


int _libunaccept_log(int priority, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  if (lua_syslog) {
    vsyslog(priority, format, args);
  } else {
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
  }
  va_end(args);
}

int _libunaccept_resize_tarpit(int size)
{
  int i;

  if (size == LUA_TARPIT_SIZE) return 1;

  if (lua_tarpit != NULL)
  {
    for (i = 0; i < LUA_TARPIT_SIZE; i++)
    {
      if (lua_tarpit[i])
        close(lua_tarpit[i]);
    }
    free(lua_tarpit);
    lua_tarpit = NULL;
  }

  LUA_TARPIT_SIZE = size;
  if (LUA_TARPIT_SIZE > 0)
  {
    if (NULL == (lua_tarpit = malloc(LUA_TARPIT_SIZE * sizeof(int))))
    {
      _libunaccept_log(LOG_ERR,
                       "libunaccept: malloc() failed: %s",
                       strerror(errno));
      return 0;
    }
    memset(lua_tarpit, 0, LUA_TARPIT_SIZE * sizeof(int));
  }
  return 1;
}

int _libunaccept_resize_rules(int size)
{
  int i;
  struct lua_rule *new_rules;

  if (size == LUA_MAX_RULES) return 1;

  if (NULL == (new_rules = malloc(size * sizeof(struct lua_rule))))
  {
    _libunaccept_log(LOG_ERR,
                     "libunaccept: malloc() failed: %s",
                     strerror(errno));
    return 0;
  }
  if (new_rules && lua_rules)
  {
    for (i = 0; i < lua_num_rules; i++)
    {
       if (lua_rules[i].hostname)
         free(lua_rules[i].hostname);
    }
    free(lua_rules);
  }
  lua_num_rules = 0;
  lua_rules = new_rules;
  LUA_MAX_RULES = size;
  return 1;
}

static void _libunaccept_configure()
{
  char *c;

  if ((NULL == (c = getenv("UNACCEPT_RULES"))) || (*c == '\0'))
  {
    _libunaccept_log(LOG_NOTICE,
                     "libunaccept: warning: UNACCEPT_RULES unset, using %s!",
                     lua_rulefile);
  }
  else
  {
    lua_rulefile = c;
  }

  if (NULL != (c = getenv("UNACCEPT_BLOCKING")))
    lua_blocking = (0 != strcasecmp(c, "0"));

  if (NULL != (c = getenv("UNACCEPT_TARPIT_SIZE")))
  {
    if (sscanf(c, "%d", &LUA_TARPIT_SIZE) != 1)
    {
      _libunaccept_log(LOG_ERR,
                       "libunaccept: FATAL: Bad UNACCEPT_TARPIT_SIZE: %s", c);
      exit(1);
    }
  }
  _libunaccept_resize_tarpit(LUA_TARPIT_SIZE);

  *(void **)(&lua_libc_accept) = dlsym(RTLD_NEXT, "accept");
  if (dlerror())
  {
    _libunaccept_log(LOG_ERR,
                     "libunaccept: FATAL: Couldn't find original accept()!\n");
    exit(1);
  }

  lua_configured = 1;
}

int _libunaccept_strtopolicy(char *s)
{
  int policy = 0;

  if (strcasestr(s, "verbose")) policy |= VERBOSE;
  if (strcasestr(s, "host")) policy |= BY_HOST;

  if (strcasestr(s, "allow"))
  {
    policy |= ALLOW;
  }
  else if (strcasestr(s, "deny"))
  {
    policy |= DENY;
  }
  else if (strcasestr(s, "tarpit"))
  {
    policy |= TARPIT;
  }

  return policy;
}

void _libunaccept_load_rules()
{
  FILE *fd;
  char line[80], first[80], second[80], third[80], fourth[80];
  struct in_addr network;
  struct in_addr netmask;
  struct stat filestat;
  int matched;
  int lines;
  int value;
  int num_rules_last = 0;

  if (stat(lua_rulefile, &filestat) < 0)
  {
    _libunaccept_log(LOG_WARNING,
                     "libunaccept: failed to stat(%s): %s",
                     lua_rulefile, strerror(errno));
    lua_num_rules = 0;
    return;
  }

  /* Short circuit if nothing has changed. */
  if (filestat.st_mtime == lua_rules_mtime) return;

  if (NULL == (fd = fopen(lua_rulefile, "r")))
  {
    perror("libunaccept: failed to open UNACCEPT_RULES file");
    return;
  }
  else
  {
    lines = lua_num_rules = 0;

    /* Resize the rules DB to roughly match the size of the config file.
     *
     * Magic number: 11 is the number of characters in "denyhost a\n",
     * which is the shortest possible rule at the moment.
     */
    if (!_libunaccept_resize_rules(filestat.st_size / 11))
      return;

    while (NULL != fgets(line, 79, fd))
    {
      lines++;
      if (*line == '#' || *line == '\0' || *line == '\n') continue;

      num_rules_last = lua_num_rules;
      if (2 == sscanf(line, "%s %s %s", first, second, third))
      {
        if (0 == strcasecmp(first, "tarpit_size") &&
            (value = strtol(second, NULL, 10)))
        {
          _libunaccept_resize_tarpit(value);
          continue;
        }
        else if (0 == strcasecmp(first, "blocking") &&
                 ((value = strtol(second, NULL, 10)) || (!errno)))
        {
          lua_blocking = value;
          continue;
        }
        else if (0 == strcasecmp(first, "syslog") &&
                 ((value = strtol(second, NULL, 10)) || (!errno)))
        {
          lua_syslog = value;
          continue;
        }
        else if ((value = _libunaccept_strtopolicy(first)) & BY_HOST)
        {
          if (lua_rules[lua_num_rules].hostname = malloc(1+strlen(second)))
          {
            strcpy(lua_rules[lua_num_rules].hostname, second);
            lua_rules[lua_num_rules++].policy = value;
          }
        }
      }
      else if (3 == sscanf(line, "%s %s %s %s", first, second, third, fourth))
      {
        if (lua_num_rules >= LUA_MAX_RULES)
        {
          _libunaccept_log(LOG_WARNING,
                           "libunaccept: Line %d, too many rules!  Max is %d.",
                           lines, LUA_MAX_RULES);
          fclose(fd);
          return;
        }
        if (inet_aton(second, &network) &&
            inet_aton(third,  &netmask) &&
            ((network.s_addr & netmask.s_addr) == network.s_addr))
        {
          lua_rules[lua_num_rules].network = network.s_addr;
          lua_rules[lua_num_rules].netmask = netmask.s_addr;
          lua_rules[lua_num_rules].hostname = NULL;
          if (lua_rules[lua_num_rules].policy = _libunaccept_strtopolicy(first))
            lua_num_rules++;
        }
      }

      if (num_rules_last == lua_num_rules)
      {
        _libunaccept_log(LOG_WARNING,
                         "libunaccept: Line %d, invalid rule: %s", lines, line);
      }
    }
    fclose(fd);
    lua_rules_mtime = filestat.st_mtime;
  }

  _libunaccept_log(LOG_NOTICE, "libunaccept: configured from %s", lua_rulefile);
}

int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
  struct sockaddr_in *sin;
  struct hostent *hinfo;
  struct hostent nullinfo, unsetinfo;
  char *addr_str;
  int res;
  int match;
  int got_hinfo;
  int i;

  if (!lua_configured) _libunaccept_configure();

  nullinfo.h_name = "no-reverse-dns";
  unsetinfo.h_name = "<unset>";
  do
  {
    _libunaccept_load_rules();

    res = (*lua_libc_accept)(s, addr, addrlen);

    if ((res <= 0) || (lua_num_rules < 1) || (addr->sa_family != AF_INET))
      return res;

    hinfo = &unsetinfo;
    got_hinfo = 0;
    for (i = 0; i < lua_num_rules; i++)
    {
      sin = (struct sockaddr_in *) addr;

      match = 0;
      if (lua_rules[i].policy & BY_HOST)
      {
        if (!got_hinfo)
        {
          got_hinfo++;
          hinfo = gethostbyaddr(&sin->sin_addr.s_addr,
                                sizeof(sin->sin_addr.s_addr), AF_INET);
          if (hinfo == NULL)
            hinfo = &nullinfo;
        }
        match = (NULL != strcasestr(hinfo->h_name, lua_rules[i].hostname));
      }
      else
      {
        match = ((sin->sin_addr.s_addr & lua_rules[i].netmask) == lua_rules[i].network);
      }

      if (match)
      {
        if (lua_rules[i].policy & ALLOW)
        {
          if ((lua_rules[i].policy & VERBOSE) || (lua_syslog > 1))
            _libunaccept_log(LOG_INFO,
                             "libunaccept: Connect from %s/%s allowed, rule %d.",
                             inet_ntoa(sin->sin_addr.s_addr), hinfo->h_name, i);
          break;
        }
        else if (lua_rules[i].policy & DENY)
        {
          if ((lua_rules[i].policy & VERBOSE) || (lua_syslog > 1))
            _libunaccept_log(LOG_INFO,
                             "libunaccept: Connect from %s/%s denied, rule %d.",
                             inet_ntoa(sin->sin_addr.s_addr), hinfo->h_name, i);
          close(res);
          errno = ECONNABORTED;
          res = -1;
          break;
        }
        else if (lua_rules[i].policy & TARPIT)
        {
          if ((lua_rules[i].policy & VERBOSE) || (lua_syslog > 1))
            _libunaccept_log(LOG_INFO,
                             "libunaccept: Connect from %s/%s tarpitted, rule %d.",
                             inet_ntoa(sin->sin_addr.s_addr), hinfo->h_name, i);

          /* Tarpitting is simple: we just keep up to LUA_TARPIT_SIZE
           * victims open at a time, but otherwise ignore them. */
          if (lua_tarpit[lua_num_tarpit]) close(lua_tarpit[lua_num_tarpit]);
          lua_tarpit[lua_num_tarpit] = res;
          lua_num_tarpit += 1;
          lua_num_tarpit %= LUA_TARPIT_SIZE;
          errno = ECONNABORTED;
          res = -1;
          break;
        }
      }
    }

    /* If we get this far, we had a connection and have checked rules.
     *
     * If something was denied or tarpitted, we have res < 0; in blocking
     * mode, that means accept() again, if not blocking return to the app.
     */
  }
  while (lua_blocking && (res < 0));

  return res;
}
