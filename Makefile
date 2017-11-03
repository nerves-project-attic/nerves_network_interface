# Variables to override
#
# CC            C compiler. MUST be set if crosscompiling
# CROSSCOMPILE	crosscompiler prefix, if any
# CFLAGS        compiler flags for compiling all C files
# ERL_PATH      the path to the erlang installation (e.g., /usr/lib/erlang)
# ERL_CFLAGS    additional compiler flags for files using Erlang header files
# ERL_EI_LIBDIR path to libei.a (Required for crosscompile)
# LDFLAGS       linker flags for linking all binaries
# ERL_LDFLAGS   additional linker flags for projects referencing Erlang libraries
# SUDO_ASKPASS  path to ssh-askpass when modifying ownership of netif
# SUDO          path to SUDO. If you don't want the privileged parts to run, set to "true"

# Check that we're on a supported build platform
ifeq ($(CROSSCOMPILE),)
    # Not crosscompiling, so check that we're on Linux.
    ifneq ($(shell uname -s),Linux)
        $(warning nerves_network_interface only works on Linux, but crosscompilation)
        $(warning is supported by defining $$CROSSCOMPILE and $$ERL_EI_LIBDIR.)
        $(warning See Makefile for details. If using Nerves,)
        $(warning this should be done automatically.)
        $(warning .)
        $(warning Skipping C compilation unless targets explicitly passed to make.)
	DEFAULT_TARGETS = priv
    endif
endif
DEFAULT_TARGETS ?= priv priv/netif

# Note: If crosscompiling, either ERL_PATH or both ERL_CFLAGS and ERL_LDFLAGS need
#       to be specified or you'll get the host erl's versions and the linking step
#       will fail.
ERL_PATH ?= $(shell erl -noshell -eval "io:format(\"~s\", [code:root_dir()])." -s init stop)
ERL_CFLAGS ?= -I$(ERL_PATH)/usr/include

ERL_EI_LIBDIR ?= $(ERL_PATH)/usr/lib
ERL_LDFLAGS ?= -L$(ERL_EI_LIBDIR) -lei

LDFLAGS += -lmnl
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter -pedantic


# Unfortunately, depending on the system we're on, we need
# to specify -std=c99 or -std=gnu99. The later is more correct,
# but it fails to build on many setups.
# NOTE: Need to call sh here since file permissions are not preserved
#       in hex packages.
ifeq ($(shell CC=$(CC) sh src/test-c99.sh),yes)
CFLAGS += -std=c11 -D_XOPEN_SOURCE=600
else
CFLAGS += -std=c11
endif

# If not cross-compiling, then run sudo by default
ifeq ($(origin CROSSCOMPILE), undefined)
SUDO_ASKPASS ?= /usr/bin/ssh-askpass
SUDO ?= sudo
else
# If cross-compiling, then permissions need to be set some build system-dependent way
SUDO ?= true
endif

.PHONY: all clean

all: $(DEFAULT_TARGETS)

%.o: %.c
	$(CC) -c $(ERL_CFLAGS) $(CFLAGS) -o $@ $<

priv:
	mkdir -p priv

priv/netif: src/erlcmd.o src/netif.o
	$(CC) $^ $(ERL_LDFLAGS) $(LDFLAGS) -o $@
	# setuid root net_basic so that it can configure network interfaces
	SUDO_ASKPASS=$(SUDO_ASKPASS) $(SUDO) -- sh -c 'chown root:root $@; chmod +s $@'

clean:
	rm -f priv/netif src/*.o
