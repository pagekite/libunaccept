/* libunaccept - Add IP/DNS ACLs to the accept call (activate via LD_PRELOAD).
** Copyright 2011, Bjarni R. Einarsson <http://bre.klaki.net/>
*
* This program is free software: you can redistribute it and/or modify it under
* the terms of the  GNU  Affero General Public License as published by the Free
* Software Foundation, either version 3 of the License, or (at your option) any
* later version.
*
* See the file COPYING for details.
*******************************************************************************/
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

int (*_libunaccept_libc_accept)(int s, struct sockaddr *, socklen_t *);
int _libunaccept_configured = 0;
int _LIBUNACCEPT_BLOCKING = 0;
int _libunaccept_syslog = 0;

/* Rules variables */
int _libunaccept_max_rules = 100;
struct _libunaccept_rule {
  int policy;
  in_addr_t network;
  in_addr_t netmask;
  char *hostname;
} *_libunaccept_rules;
int _libunaccept_num_rules = 0;
int _libunaccept_rules_lock = 0;
char *_LIBUNACCEPT_RULES = "/etc/libunaccept.d";
time_t _libunaccept_rules_mtime = 0;

/* Tarpitting variables*/
int _LIBUNACCEPT_TARPIT_SIZE = 100;
int *_libunaccept_tarpit = NULL;
int _libunaccept_num_tarpit = 0;


int _libunaccept_log(int priority, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  if (_libunaccept_syslog) {
    if (_libunaccept_syslog > 0) vsyslog(priority, format, args);
  } else {
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
  }
  va_end(args);
}

int _libunaccept_resize_tarpit(int size)
{
  int i;

  if (size == _LIBUNACCEPT_TARPIT_SIZE) return 1;

  if (_libunaccept_tarpit != NULL)
  {
    for (i = 0; i < _LIBUNACCEPT_TARPIT_SIZE; i++)
    {
      if (_libunaccept_tarpit[i])
        close(_libunaccept_tarpit[i]);
    }
    free(_libunaccept_tarpit);
    _libunaccept_tarpit = NULL;
  }

  _LIBUNACCEPT_TARPIT_SIZE = size;
  if (_LIBUNACCEPT_TARPIT_SIZE > 0)
  {
    if (NULL == (_libunaccept_tarpit = malloc(_LIBUNACCEPT_TARPIT_SIZE * sizeof(int))))
    {
      _libunaccept_log(LOG_ERR,
                       "libunaccept: malloc() failed: %s",
                       strerror(errno));
      return 0;
    }
    memset(_libunaccept_tarpit, 0, _LIBUNACCEPT_TARPIT_SIZE * sizeof(int));
  }
  return 1;
}

int _libunaccept_resize_rules(int size)
{
  int i;
  struct _libunaccept_rule *new_rules;

  if (size == _libunaccept_max_rules) return 1;

  if (NULL == (new_rules = malloc(size * sizeof(struct _libunaccept_rule))))
  {
    _libunaccept_log(LOG_ERR,
                     "libunaccept: malloc() failed: %s",
                     strerror(errno));
    return 0;
  }
  if (new_rules && _libunaccept_rules)
  {
    for (i = 0; i < _libunaccept_num_rules; i++)
    {
       if (_libunaccept_rules[i].hostname)
         free(_libunaccept_rules[i].hostname);
    }
    free(_libunaccept_rules);
  }
  _libunaccept_num_rules = 0;
  _libunaccept_rules = new_rules;
  _libunaccept_max_rules = size;
  return 1;
}

static void _libunaccept_configure()
{
  char *c;

  /* Note: We have a miniscule race condition here if two threads decide
   * to configure at the exact same time. But if they do, it *should* still
   * be harmless, aside from a potential tarpit buffer memory leak.
   */
  if (_libunaccept_configured) return;

  if ((NULL == (c = getenv("LIBUNACCEPT_RULES"))) || (*c == '\0'))
  {
    _libunaccept_log(LOG_NOTICE,
                     "libunaccept: warning: LIBUNACCEPT_RULES unset, using %s!",
                     _LIBUNACCEPT_RULES);
  }
  else
  {
    _LIBUNACCEPT_RULES = c;
  }

  if (NULL != (c = getenv("LIBUNACCEPT_BLOCKING")))
    _LIBUNACCEPT_BLOCKING = (0 != strcasecmp(c, "0"));

  if (NULL != (c = getenv("LIBUNACCEPT_OPENLOG")))
    openlog(c, LOG_PID, LOG_DAEMON);

  if (NULL != (c = getenv("LIBUNACCEPT_TARPIT_SIZE")))
  {
    if (sscanf(c, "%d", &_LIBUNACCEPT_TARPIT_SIZE) != 1)
    {
      _libunaccept_log(LOG_ERR,
                       "libunaccept: FATAL: Bad LIBUNACCEPT_TARPIT_SIZE: %s", c);
      exit(1);
    }
  }
  _libunaccept_resize_tarpit(_LIBUNACCEPT_TARPIT_SIZE);

  *(void **)(&_libunaccept_libc_accept) = dlsym(RTLD_NEXT, "accept");
  if (dlerror())
  {
    _libunaccept_log(LOG_ERR,
                     "libunaccept: FATAL: Couldn't find original accept()!\n");
    exit(1);
  }

  _libunaccept_configured = 1;
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

void _libunaccept_load_rules(unsigned short port)
{
  FILE *fd;
  char fn[1024], line[80], first[80], second[80], third[80], fourth[80];
  struct in_addr network;
  struct in_addr netmask;
  struct stat filestat;
  int matched;
  int lines;
  int value;
  int num_rules_last = 0;

  /* FIXME: We have a bit of a race condition here... */
  if (++_libunaccept_rules_lock != 1) {
    _libunaccept_rules_lock--;
    return;
  }

  /* Make sure our rulefile or ruledir exists */
  if (stat(_LIBUNACCEPT_RULES, &filestat) < 0)
  {
    _libunaccept_log(LOG_WARNING,
                     "libunaccept: failed to stat(%s): %s",
                     fn, strerror(errno));
    _libunaccept_rules_lock--;
    return;
  }

  /* If it is a directory, go looking for a usable config file. */
  fn[sizeof(fn)-1] = '\0';
  if (S_ISDIR(filestat.st_mode))
  {
    /* First, look for a file named port_<PORTNUM>.rc */
    snprintf(fn, sizeof(fn)-1, "%s/port_%hu.rc", _LIBUNACCEPT_RULES, port);

    if (stat(fn, &filestat) < 0)
      /* If it does not exist, look for default.rc */
      snprintf(fn, sizeof(fn)-1, "%s/default.rc", _LIBUNACCEPT_RULES);

    if (stat(fn, &filestat) < 0)
    {
      /* If it still does not exist, just panic. */
      _libunaccept_log(LOG_WARNING,
                       "libunaccept: failed to stat(%s): %s",
                       fn, strerror(errno));
      _libunaccept_rules_lock--;
      return;
    }
  }
  else
  {
    /* Otherwise, treat the _LIBUNACCEPT_RULES as a file. */
    strncpy(fn, _LIBUNACCEPT_RULES, sizeof(fn)-1);
  }

  /* Short circuit if nothing has changed. */
  if (filestat.st_mtime == _libunaccept_rules_mtime) return;

  if (NULL == (fd = fopen(fn, "r")))
  {
    _libunaccept_log(LOG_ERR,
                     "libunaccept: failed to open %s: %s",
                     fn, strerror(errno));
    _libunaccept_rules_lock--;
    return;
  }
  else
  {
    lines = _libunaccept_num_rules = 0;

    /* Resize the rules DB to roughly match the size of the config file.
     *
     * Magic number: 11 is the number of characters in "denyhost a\n",
     * which is the shortest possible rule at the moment.
     */
    if (!_libunaccept_resize_rules(filestat.st_size / 11))
    {
      _libunaccept_rules_lock--;
      return;
    }

    while (NULL != fgets(line, 79, fd))
    {
      lines++;
      if (*line == '#' || *line == '\0' || *line == '\n') continue;

      num_rules_last = _libunaccept_num_rules;
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
          _LIBUNACCEPT_BLOCKING = value;
          continue;
        }
        else if (0 == strcasecmp(first, "syslog") &&
                 ((value = strtol(second, NULL, 10)) || (!errno)))
        {
          _libunaccept_syslog = value;
          continue;
        }
        else if ((value = _libunaccept_strtopolicy(first)) & BY_HOST)
        {
          if (_libunaccept_rules[_libunaccept_num_rules].hostname = malloc(1+strlen(second)))
          {
            strcpy(_libunaccept_rules[_libunaccept_num_rules].hostname, second);
            _libunaccept_rules[_libunaccept_num_rules++].policy = value;
          }
        }
      }
      else if (3 == sscanf(line, "%s %s %s %s", first, second, third, fourth))
      {
        if (_libunaccept_num_rules >= _libunaccept_max_rules)
        {
          _libunaccept_log(LOG_WARNING,
                           "libunaccept: Line %d, too many rules!  Max is %d.",
                           lines, _libunaccept_max_rules);
          fclose(fd);
          _libunaccept_rules_lock--;
          return;
        }
        if (inet_aton(second, &network) &&
            inet_aton(third,  &netmask) &&
            ((network.s_addr & netmask.s_addr) == network.s_addr))
        {
          _libunaccept_rules[_libunaccept_num_rules].network = network.s_addr;
          _libunaccept_rules[_libunaccept_num_rules].netmask = netmask.s_addr;
          _libunaccept_rules[_libunaccept_num_rules].hostname = NULL;
          if (_libunaccept_rules[_libunaccept_num_rules].policy = _libunaccept_strtopolicy(first))
            _libunaccept_num_rules++;
        }
      }

      if (num_rules_last == _libunaccept_num_rules)
      {
        _libunaccept_log(LOG_WARNING,
                         "libunaccept: Line %d, invalid rule: %s", lines, line);
      }
    }
    fclose(fd);
    _libunaccept_rules_mtime = filestat.st_mtime;
  }

  _libunaccept_log(LOG_NOTICE, "libunaccept: configured from %s", fn);
  _libunaccept_rules_lock--;
}

int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
  struct sockaddr_in *sin;
  struct sockaddr_in our_end;
  struct hostent *hinfo;
  struct hostent nullinfo, unsetinfo;
  socklen_t our_end_len;
  char *addr_str;
  int res;
  int match;
  int got_hinfo;
  int i;

  if (!_libunaccept_configured) _libunaccept_configure();

  nullinfo.h_name = "no-reverse-dns";
  unsetinfo.h_name = "<unset>";
  do
  {
    res = (*_libunaccept_libc_accept)(s, addr, addrlen);
    if ((res <= 0) || (addr->sa_family != AF_INET)) return res;

    our_end_len = sizeof(our_end);
    getsockname(s, &our_end, &our_end_len);
    _libunaccept_load_rules(ntohs(our_end.sin_port));

    if (_libunaccept_num_rules < 1) return res;

    sin = (struct sockaddr_in *) addr;
    hinfo = &unsetinfo;
    got_hinfo = 0;
    for (i = 0; i < _libunaccept_num_rules; i++)
    {
      match = 0;
      if (_libunaccept_rules[i].policy & BY_HOST)
      {
        if (!got_hinfo)
        {
          got_hinfo++;
          hinfo = gethostbyaddr(&sin->sin_addr.s_addr,
                                sizeof(sin->sin_addr.s_addr), AF_INET);
          if (hinfo == NULL)
            hinfo = &nullinfo;
        }
        match = (NULL != strcasestr(hinfo->h_name, _libunaccept_rules[i].hostname));
      }
      else
      {
        match = ((sin->sin_addr.s_addr & _libunaccept_rules[i].netmask) == _libunaccept_rules[i].network);
      }

      if (match)
      {
        if (_libunaccept_rules[i].policy & ALLOW)
        {
          if ((_libunaccept_rules[i].policy & VERBOSE) || (_libunaccept_syslog > 1))
            _libunaccept_log(LOG_INFO,
                             "libunaccept: Connect from %s/%s allowed, rule %d.",
                             inet_ntoa(sin->sin_addr.s_addr), hinfo->h_name, i);
          break;
        }
        else if (_libunaccept_rules[i].policy & DENY)
        {
          if ((_libunaccept_rules[i].policy & VERBOSE) || (_libunaccept_syslog > 1))
            _libunaccept_log(LOG_INFO,
                             "libunaccept: Connect from %s/%s denied, rule %d.",
                             inet_ntoa(sin->sin_addr.s_addr), hinfo->h_name, i);
          close(res);
          errno = ECONNABORTED;
          res = -1;
          break;
        }
        else if (_libunaccept_rules[i].policy & TARPIT)
        {
          if ((_libunaccept_rules[i].policy & VERBOSE) || (_libunaccept_syslog > 1))
            _libunaccept_log(LOG_INFO,
                             "libunaccept: Connect from %s/%s tarpitted, rule %d.",
                             inet_ntoa(sin->sin_addr.s_addr), hinfo->h_name, i);

          /* Tarpitting is simple: we just keep up to _LIBUNACCEPT_TARPIT_SIZE
           * victims open at a time, but otherwise ignore them. */
          if (_libunaccept_tarpit[_libunaccept_num_tarpit]) close(_libunaccept_tarpit[_libunaccept_num_tarpit]);
          _libunaccept_tarpit[_libunaccept_num_tarpit] = res;
          _libunaccept_num_tarpit += 1;
          _libunaccept_num_tarpit %= _LIBUNACCEPT_TARPIT_SIZE;
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
  while (_LIBUNACCEPT_BLOCKING && (res < 0));

  return res;
}
