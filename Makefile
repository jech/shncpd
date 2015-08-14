PREFIX = /usr/local
MANDIR = $(PREFIX)/share/man

CDEBUGFLAGS = -Os -g -Wall

DEFINES = $(PLATFORM_DEFINES)

CFLAGS = $(CDEBUGFLAGS) $(DEFINES) $(EXTRA_DEFINES)

LDLIBS = -lbsd

SRCS = shncpd.c state.c send.c receive.c ra.c dhcpv4.c prefix.c \
       trickle.c kernel.c util.c

OBJS = shncpd.o state.o send.o receive.o ra.o dhcpv4.o prefix.o \
       trickle.o kernel.o util.o

shncpd: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o shncpd $(OBJS) $(LDLIBS)

.SUFFIXES: .man

.PHONY: all install install.minimal uninstall clean

all: shncpd shncpd.man

install.minimal: shncpd
	-rm -f $(TARGET)$(PREFIX)/bin/shncpd
	mkdir -p $(TARGET)$(PREFIX)/bin
	cp -f shncpd $(TARGET)$(PREFIX)/bin

install: install.minimal all
	mkdir -p $(TARGET)$(MANDIR)/man8
	cp -f shncpd.man $(TARGET)$(MANDIR)/man8/shncpd.8

uninstall:
	-rm -f $(TARGET)$(PREFIX)/bin/shncpd
	-rm -f $(TARGET)$(MANDIR)/man8/shncpd.8

clean:
	-rm -f shncpd shncpd.html *.o *~ core TAGS gmon.out
