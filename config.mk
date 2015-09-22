###############################################################################
# Config                                                                      #
#                                                                             #
# [XHYVE_CONFIG_ASSERT] VMM asserts (disable for release builds?)             #
# [XHYVE_CONFIG_TRACE]  VMM event tracer                                      #
# [XHYVE_CONFIG_STATS]  VMM event profiler                                    #
###############################################################################

###############################################################################
# Toolchain                                                                   #
###############################################################################

CC := clang
AS := clang
LD := clang
STRIP := strip
DSYM := dsymutil

# Default to /usr/sbin/iasl for historic reasons
IASL ?= $(shell which iasl)
ifeq ($(IASL),)
IASL = /usr/sbin/iasl
endif

ENV := \
  LANG=en_US.US-ASCII

###############################################################################
# DEFINES                                                                     #
###############################################################################

DEFINES := \
	-DXHYVE_CONFIG_ASSERT \
	-DBHYVE_ASL_COMPILER=$(IASL)

###############################################################################
# CFLAGS                                                                      #
###############################################################################

CFLAGS_OPT := \
  -Os \
  -flto \
  -fstrict-aliasing

CFLAGS_WARN := \
  -Weverything \
  -Werror \
  -Wno-unknown-warning-option \
  -Wno-reserved-id-macro \
  -pedantic

CFLAGS_DIAG := \
  -fmessage-length=152 \
  -fdiagnostics-show-note-include-stack \
  -fmacro-backtrace-limit=0 \
  -fcolor-diagnostics

CFLAGS_DBG := \
  -g

CFLAGS := \
  -arch x86_64 \
  -x c \
  -std=c11 \
  -fno-common \
  -fvisibility=hidden \
  $(DEFINES) \
  $(CFLAGS_OPT) \
  $(CFLAGS_WARN) \
  $(CFLAGS_DIAG) \
  $(CFLAGS_DBG)

###############################################################################
# LDFLAGS                                                                     #
###############################################################################

LDFLAGS_DBG := \
  -Xlinker -object_path_lto

LDFLAGS := \
  -arch x86_64 \
  -framework Hypervisor \
  -framework vmnet \
  $(LDFLAGS_DBG)
