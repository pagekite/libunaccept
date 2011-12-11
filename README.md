# libunaccept #

`Libunaccept` is a minimal user-space firewall written in C, which allows
both IP network and DNS-based policies for TCP/IP servers.  It can be enabled
for any application without the need to recompile, by using `LD_PRELOAD`
library injection.

The primary goals are simplicity, speed and enabling automated reconfiguration.

Possible uses:

   1. Restrict access to your SMTP server to reduce spam.
   2. Manage incoming DDoS attacks.


## Installation ##

The standard:

    make
    make install

will install `libunaccept.so` in `/usr/local/lib`, create `/etc/libunaccept.d/`
and install a default configuration (which does nothing).

Running `make uninstall` will remove the binary but leave the files in `/etc/`
intact.


## Activation ##

To activate `libunaccept` for a system daemon, the easiest way on modern
Linux distributions is to add the following lines to one of the scripts
which are sourced by the service SysV init startup script:

    # Enable the libunaccept user-space firewall.
    export UNACCEPT_RULES=/etc/libunaccept.d
    export LD_PRELOAD=/usr/local/lib/libunaccept.so

On Debian, it is usually easiest to inject those lines into a file named
`/etc/default/SERVICE`.

On modern RedHat or Fedora distributions, most packages will work if you
add those lines to a file named `/etc/sysconfig/SERVICE`.


## Related projects ##

`Libunaccept` is beening resurrected from obscurity for use as a DDoS
management system at [PageKite](https://pagekite.net/) and an experimental
spam reduction tool for the author's personal SMTP server
([blog post](http://bre.klaki.net/blog/2011/12/11)).

If you use `libunaccept` for something neat, let us know and we'll add a
link to this document.


## Credits and License ##

Libunaccept is Copyright 2011, Bjarni R. Einarsson <http://bre.klaki.net/>

This program is free software: you can redistribute it and/or modify it under
the terms of the  GNU  Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

See the file COPYING for details.

