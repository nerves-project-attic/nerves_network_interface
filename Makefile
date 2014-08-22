# Variables to override
#
# CC            C compiler
# CROSSCOMPILE	crosscompiler prefix, if any
# CFLAGS        compiler flags for compiling all C files
# ERL_PATH      the path to the erlang installation (e.g., /usr/lib/erlang)
# ERL_CFLAGS    additional compiler flags for files using Erlang header files
# ERL_EI_LIBDIR path to libei.a
# LDFLAGS       linker flags for linking all binaries
# ERL_LDFLAGS   additional linker flags for projects referencing Erlang libraries
# MIX           path to mix
# SUDO_ASKPASS  path to ssh-askpass when modifying ownership of net_basic
# SUDO          path to SUDO. If you don't want the privileged parts to run, set to "true"

# Note: If crosscompiling, either ERL_PATH or both ERL_CFLAGS and ERL_LDFLAGS need
#       to be specified or you'll get the host erl's versions and the linking step
#       will fail.
ERL_PATH ?= $(shell erl -noshell -eval "io:format(\"~s\", [code:root_dir()])." -s init stop)
ERL_CFLAGS ?= -I$(ERL_PATH)/usr/include

ERL_EI_LIBDIR ?= $(ERL_PATH)/usr/lib
ERL_LDFLAGS ?= -L$(ERL_EI_LIBDIR) -lei

LDFLAGS += -lmnl
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter
CC ?= $(CROSSCOMPILER)gcc
MIX ?= mix
SUDO_ASKPASS ?= /usr/bin/ssh-askpass
SUDO ?= sudo

all: compile

compile:
	$(MIX) compile

test:
	$(MIX) test

%.o: %.c
	$(CC) -c $(ERL_CFLAGS) $(CFLAGS) -o $@ $<

priv/net_basic: src/erlcmd.o src/net_basic.o
	mkdir -p priv
	$(CC) $^ $(ERL_LDFLAGS) $(LDFLAGS) -o $@
	# setuid root net_basic so that it can configure network interfaces
	SUDO_ASKPASS=$(SUDO_ASKPASS) $(SUDO) -- sh -c 'chown root:root $@; chmod +s $@'

clean:
	$(MIX) clean
	rm -f priv/net_basic src/*.o

.PHONY: all compile test clean
