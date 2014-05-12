#
# fuseflt - A FUSE filesystem with file conversion filters
#
# Copyright (c) 2007 Theodoros V. Kalamatianos <nyb@users.sourceforge.net>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published by
# the Free Software Foundation.
#

prefix := /usr/local
bindir := $(prefix)/bin

DEBUG :=
CFLAGS := -O2 -Wall $(DEBUG)



# Yes, I am lazy...
VER := $(shell head -n 1 NEWS | cut -d : -f 1)



all: fuseflt

%: %.c
	$(CC) $(shell pkg-config fuse --cflags --libs) $(CFLAGS) -lcfg+ -DVERSION=\"$(VER)\" $< -o $@

install: all
	install -D -m755 fuseflt $(bindir)/fuseflt

clean:
	rm -f *.o fuseflt
