Socks
=====

This programs combines several utilities for working with SOCKS proxies.

Compiling
---------

There is no specific dependency for this project. Just run:

    $ make

`cat` and `serve` modes
-----------------------

In these mods, socks will connect to the first specified address; if
this address is a SOCKS proxy, it will then establish a connexion to
the second address through this proxy. The process is repeated until
the target host (last specified address).

The `cat` mode is similar to `netcat` (the `cat` of TCP and UDP): data
is read from the program's input and sent through the chain; the received
data is transmitted to the program's output.

The `serve` mode acts as a redirection proxy to a single address. It is
similar to:

    $ mkfifo fifo
    $ ./socks CHAIN < fifo | nc -lp SERVER_PORT > fifo

`check` mode
------------

socks can check a list of SOCKS proxies. It will attempt to build a chain
like the other modes would, but skips the unresponsive ones (no connection
or data not going though) and report the working ones. It is best to end
the list with a target host as in `cat` or `serve` in order to have the
last proxy checked for data transmission as well as connection.

Licence
-------

This program is distributed under the GPL licence (see
[LICENCE.md](LICENCE.md) file). The credits for markdown formatting goes
to https://github.com/IQAndreas/markdown-licenses
