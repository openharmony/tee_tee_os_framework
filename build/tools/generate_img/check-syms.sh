#!/bin/bash
# Usage: check-syms.sh TA.elf libc.so libtee.so
# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# add ignored syms to IGNORED
IGNORED=$(echo cfi_disabled; echo llvm_gcov_init; echo llvm_gcov_reset; echo llvm_gcov_dump;)
# add undefined syms to UNDEF
UNDEF=$(objdump -T "$1" | grep '\*UND\*' | egrep -o '[^ ]+$')

# add defined syms to ALLDEF
# ALLDEF for check:
# libc_shared_a32.so             libc_shared_a32.so
# libtee_shared_a32.so           libtee_shared.so
# libdrv_shared_a32.so           libdrv_shared.so
ALLDEF="$IGNORED\n"
DEF_NUM=1
for i in $* ; do
if [ $DEF_NUM -gt 1 ] ; then
DEF[$DEF_NUM]=$(objdump -T "$i" | grep -v '\*UND\*' | egrep -o '[^ ]+$')
ALLDEF=${ALLDEF}"${DEF[$DEF_NUM]}\n"
fi
let DEF_NUM++
done

# check undefined syms
for sym in $UNDEF ; do
if ! (echo -e "$ALLDEF" | grep -qs "^$sym$") ; then
echo "$(basename $1) contains undefined symbol $sym"
exit 1
fi
done
exit 0
