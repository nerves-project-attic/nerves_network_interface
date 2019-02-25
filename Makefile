# Makefile for building port binary
#
# Makefile targets:
#
# all/install   build and install the port binary
# clean         clean build products and intermediates
#
# Variables to override:
#
# CC               C compiler. MUST be set if crosscompiling
# CROSSCOMPILE	   crosscompiler prefix, if any
# MIX_COMPILE_PATH path to the build's ebin directory
# CFLAGS           compiler flags for compiling all C files
# ERL_CFLAGS       additional compiler flags for files using Erlang header files
# ERL_EI_LIBDIR    path to libei.a (Required for crosscompile)
# LDFLAGS          linker flags for linking all binaries
# ERL_LDFLAGS      additional linker flags for projects referencing Erlang libraries
# SUDO_ASKPASS     path to ssh-askpass when modifying ownership of netif
# SUDO             path to SUDO. If you don't want the privileged parts to run, set to "true"

PREFIX = $(MIX_COMPILE_PATH)/../priv
BUILD = $(MIX_COMPILE_PATH)/../obj
BIN = $(PREFIX)/netif

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
	BIN :=
    endif
endif

LDFLAGS += -lmnl
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter -pedantic

# Set Erlang-specific compile and linker flags
ERL_CFLAGS ?= -I$(ERL_EI_INCLUDE_DIR)
ERL_LDFLAGS ?= -L$(ERL_EI_LIBDIR) -lei

# Unfortunately, depending on the system we're on, we need
# to specify -std=c99 or -std=gnu99. The later is more correct,
# but it fails to build on many setups.
# NOTE: Need to call sh here since file permissions are not preserved
#       in hex packages.
ifeq ($(shell CC=$(CC) sh src/test-c99.sh),yes)
CFLAGS += -std=c99 -D_XOPEN_SOURCE=600
else
CFLAGS += -std=gnu99
endif

# If not cross-compiling, then run sudo by default
ifeq ($(origin CROSSCOMPILE), undefined)
SUDO_ASKPASS ?= /usr/bin/ssh-askpass
SUDO ?= sudo
else
# If cross-compiling, then permissions need to be set some build system-dependent way
SUDO ?= true
endif

SRC = src/erlcmd.c src/netif.c
OBJ = $(SRC:src/%.c=$(BUILD)/%.o)

calling_from_make:
	mix compile

all: install

install: $(PREFIX) $(BUILD) $(BIN)

$(OBJ): Makefile

$(BUILD)/%.o: src/%.c
	$(CC) -c $(ERL_CFLAGS) $(CFLAGS) -o $@ $<


$(BIN): $(OBJ)
	$(CC) $^ $(ERL_LDFLAGS) $(LDFLAGS) -o $@
	# setuid root net_basic so that it can configure network interfaces
	SUDO_ASKPASS=$(SUDO_ASKPASS) $(SUDO) -- sh -c 'chown root:root $@; chmod +s $@'

$(PREFIX) $(BUILD):
	mkdir -p $@

clean:
	$(RM) $(BIN) $(BUILD)/*.o

.PHONY: all clean calling_from_make install
