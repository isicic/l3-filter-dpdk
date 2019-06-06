#   BSD LICENSE
#
#   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

CC = cc
# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc
include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = file

# all source are stored in SRCS-y
SRCS-y := main.c l3fwd_em.c 

CFLAGS += -I$(SRCDIR)
CFLAGS += -I '/usr/local/lib'
CFLAGS += -O3 $(USER_FLAGS)
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -g
CFLAGS += -DLOOKUP_METHOD=$(LOOKUP_METHOD)

ifdef COUNT_CYCLES
CFLAGS += -DCOUNT_CYCLES=$(COUNT_CYCLES)
endif

ifdef KEY_SIZE
CFLAGS += -DKEY_SIZE=$(KEY_SIZE)
endif

ifdef EXPECTED_KEYS
CFLAGS += -DEXPECTED_KEYS=$(EXPECTED_KEYS)
endif

ifdef EM_HASH_LOOKUP_COUNT
CFLAGS += -DEM_HASH_LOOKUP_COUNT=$(EM_HASH_LOOKUP_COUNT)
endif

ifdef COUNT_BULK
CFLAGS += -DCOUNT_BULK=$(COUNT_BULK)
endif

CFLAGS += -mmovbe
CFLAGS += -I '/home/ivans/sources/dpdk-stable-17.11.1/lib/librte_hash/'

include $(RTE_SDK)/mk/rte.extapp.mk
