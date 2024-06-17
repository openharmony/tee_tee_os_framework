# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

TARGET_IS_ARM64 = y

# API_LEVEL which indicates the GP API version of TA
# API_LEVEL=2 indicates GP 1.1.1 which is the current version of the partner
# API_LEVEL=3 indicates GP 1.2 which is the version we both going to support
# If no API_LEVEL is specified, API of GP 1.1.1 will be taken
CFLAGS += -DAPI_LEVEL=3 
CFLAGS += -DFWDENGINE=USE_DF
CFLAGS += -DBCKENGINE=USE_DF
CFLAGS += -DSLICELEN_50K=51200
CFLAGS += -DSLICELEN_100K_GR200B=102400+200
CFLAGS += -DSLICELEN_250K_GR8B=256000+8
CFLAGS += -DSLICELEN_250K_GR200B=256000+200
CFLAGS += -DSLICELEN_500K=512000
CFLAGS += -DSLICELEN_1M=1024000
CFLAGS += -DDATA50K_LE64B=51200-64
CFLAGS += -DDATA50K_GR64B=51200+64
CFLAGS += -DDATA50K_GR16B=51200+16
CFLAGS += -DDATA50K_LE16B=51200-16
CFLAGS += -DDATA100K_LE1B=102400-1
CFLAGS += -DDATA100K_GR500B=102400+500
CFLAGS += -DDATA250K_LE8B=256000-8
CFLAGS += -DDATA250K_LE128B=256000-128
CFLAGS += -DDATA250K_GR10B=256000+10
CFLAGS += -DDATA250K_GR200B=256000+200
CFLAGS += -DDATA500K_LE1B=512000-1
CFLAGS += -DDATA500K_LE128B=512000-128
CFLAGS += -DDATA500K_LE16B=512000-16
CFLAGS += -DDATA500K_GR1B=512000+1
CFLAGS += -DDATA1M_GR1B=1024000+1
CFLAGS += -DDATA1M_GR16B=1024000+16
CFLAGS += -DDATA1M_LE1B=1024000-1
CFLAGS += -DDATA1M_LE16B=1024000-16
CFLAGS += -DDATA2M=1024000*2 

include ../../../build/mk/common.mk

SRC += $(wildcard ./src/*.c)
SRC += $(wildcard ./src/cases/*.c)
SRC += $(wildcard ./src/data/*.c)
SRC += $(wildcard ./src/monad/*.c)

# set header directory
INCLUDEDIR += -I../utils/include  -I../utils/cmd_id -I./src/cases -I./src/data -I./src/monad -I./src

# set target
COBJS := $(SRC:%.c=%.o)
TARGET = $(COBJS)

libcombine: $(TARGET)
	$(LD) $(LDFLAGS) $(TARGET) $(EXTRAO) -o libcombine.so

src/%.o: ./src/%.c
	$(CC) $(CFLAGS)  $(INCLUDEDIR) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS)  $(INCLUDEDIR) -c $< -o $@

clean:
	rm -f $(COBJS) *.so *.sec
