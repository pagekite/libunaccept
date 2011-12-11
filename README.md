# libunaccept #

`Libunaccept` is a minimal user-space firewall written in C, which allows both
IP network and DNS-based policies for TCP/IP servers. It can be enabled for
any Linux application without the need to recompile, by using `LD_PRELOAD`
library injection.

The primary goals are simplicity, speed and enabling automated reconfiguration.

Possible uses:

   1. Restrict access to your SMTP server to reduce spam.
   2. Manage incoming DDoS attacks.


## Installation ##

The standard:

    make
    make install

... will install `libunaccept.so` in `/usr/local/lib`, create
`/etc/libunaccept.d/` and install a default policy (which does nothing).

Running `make uninstall` will remove the binary but leave the files in `/etc/`
intact.


## Activation ##

To activate `libunaccept` for a system daemon, the easiest way on modern
Linux distributions is to add the following lines to one of the scripts which
are sourced by the service SysV init startup script:

    # Enable the libunaccept user-space firewall.
    export LIBUNACCEPT_RULES=/etc/libunaccept.d
    export LD_PRELOAD=/usr/local/lib/libunaccept.so

On Debian, it is usually easiest to inject those lines into a file named
`/etc/default/SERVICE`.

On modern RedHat or Fedora distributions, most packages will work if you add
those lines to a file named `/etc/sysconfig/SERVICE`.


## Configuration ##

`Libunaccept` can be configured using a combination of environment
variables and configuration files.  The environment variables are evaluated
first and are used to set defaults, including where to load the configuration
files from.

### Environment Variables ###

`Libunaccept` recognizes the following environment variables:

    LIBUNACCEPT_RULES=/etc/libunaccept.d

    LIBUNACCEPT_OPENLOG=        # provide a name to explicitly open syslog
    LIBUNACCEPT_BLOCKING=0      # or 1 to enable blocking mode
    LIBUNACCEPT_TARPIT_SIZE=100 # max number of connections to keep hanging

Default values for each variable are shown above.

The most important of these is the `LIBUNACCEPT_RULES` variable, as it tells
the library where to load policies from.  It can point either to a directory
or an individual file.

### Policy File Names ###

`Libunaccept` will consult a policy (configuration) file for instructions
every time someone connects to the wrapped service.

Which file it loads depends on the port being listend on and the value of the
`LIBUNACCEPT_RULES` environment variable (`/etc/libunaccept.d` by default).
For example, assuming we are protecting a service listening on port 25, the
files checked would be, in order of preference:

   1. `$LIBUANCCEPT_RULES/port_25.rc`
   2. `$LIBUANCCEPT_RULES/default.rc`
   3. `$LIBUANCCEPT_RULES`

Note that only one of these files is ever used at a time, the first match
wins.  The third option only applies if the `LIBUNACCEPT_RULES` points to a
file, the other two are attempted if it points to a directory.

Also note that `Libunaccept` will cache the parsed policy in RAM and will
only re-parse if the file modification time changes.  This of course only
helps if the `accept()` call takes place in a long-lived process.

### Writing Policies ###

`Libunaccept` policies should be familiar to anyone used to configuring a
firewall.  They are simply a list of rules which are checked in order; the
first rule that matches is applied and processing is finished.

In `libunaccept` a rule consists of a condition and a policy.  The current
policies are:

   * `allow` accepts matching connections
   * `deny` rejects matching connectiosn
   * `tarpit` ignores connections, but leaves the clients hanging (for a while)

In addition, policies can have modifiers:

   * `verbose` logs all matches to syslog
   * `host` applie this rule to host-names instead of IP addresses

Conditions are either host names fragments or IPv4 addresses and subnet masks
in dotted quad notation.

This is probably best illustrated with an example:

    allow               127.0.0.0  255.0.0.0
    allow:verbose       1.2.3.0    255.255.255.0
    tarpit:verbose      1.2.4.0    255.255.255.0
    deny:verbose:host   .evil.com
    deny:verbose:host   no-reverse-dns
    allow               0.0.0.0    0.0.0.0

A few notes about hostname matching:

   1. Hostname matching rules are *not* regular expressions, they are simply
      case insensitive substring matches.  The rule `.com` will match the
      hostname `www.computer.cn`, so be careful and think about which order
      you want rules to be evaluated.
   2. The `no-reverse-dns` string is a special case which matches hosts that
      don't have reverse DNS entries.
   3. Hostname matches require a DNS, lookup which may significantly slow
      down the wrapped application, unless `accept()` is invoked on a separate
      thread.  Stick to IP-address rules only if performance is critical.


### Global settings ###

In addition to the rules, `libunaccept` configuration files may include
the following settings:

   * `tarpit_size N` overrides `LIBUNACCEPT_TARPIT_SIZE`
   * `blocking N` overrides `LIBUNACCEPT_BLOCKING`
   * `syslog N` controls logging: `0=off`, `1=on`, `2=verbose`

Example:

    # Verbose configuration with a small tarpit buffer
    syslog 2
    blocking 0
    tarpit_size 25


## TODOs and Ideas ##

Patches or pull requests for the following features would be awesome.  They
are ordered roughly by estimated complexity:

   1. IPv6 support
   2. HTTP 500 or HTTP redirect policies
   3. Regular expression support for hostname matches
   4. Automatic rate limiting
   5. Use `redis` for coordinated rate limiting / dynamic policies
   6. Wrap `recv*` and `write` and impose policies on read/written data

It would also be nice if more eyeballs would consider whether `libunaccept`
is "thread safe enough". :-)


## History and Related Projects ##

Originally written in 2006 but never released, `libunaccept`, was resurrected
from obscurity for DDoS management at [PageKite](https://pagekite.net/) and
as an experimental spam reduction tool for the author's personal SMTP server
([blog post](http://bre.klaki.net/blog/2011/12/09/)).

If you use `libunaccept` for something neat, let us know and we'll add a
link to this document.


## Credits and License ##

Libunaccept is Copyright 2011, Bjarni R. Einarsson <http://bre.klaki.net/>

This program is free software: you can redistribute it and/or modify it under
the terms of the  GNU  Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

See the file COPYING for details.

