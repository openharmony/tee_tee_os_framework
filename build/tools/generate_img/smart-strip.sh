#!/bin/bash
# Get the elf file, judge 32 or 64, and strip off some symbol information and debugging information to make the file smaller
# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
set -e

strip_file() {
	STRIP_OPTION="-d -x -p"
	is_elf=$(file "$1" | grep ELF)
	if [ "x${is_elf}" = x ]; then
		# not a ELF file
		return
	fi
	if (echo "$1" | grep '\.so$') ; then
		STRIP_OPTION="-s -p"
	fi
	set +o errexit
	is_arm=$(readelf -h "$1" 2>/dev/null | grep -E "Machine:.*(ARM|AArch64)")
	is_a32=$(readelf -h "$1" 2>/dev/null | grep "Class:.*ELF32")
	is_a64=$(readelf -h "$1" 2>/dev/null | grep "Class:.*ELF64")
	is_obj=$(readelf -h "$1" 2>/dev/null | grep "Type:.*REL")
	if [ "x${is_obj}" != x ]; then
		STRIP_OPTION="-d -p"
	fi
	set -o errexit
	if [ "x${is_arm}" != x ]; then
		IS_A32=0
		IS_A64=0
		if [ "x${is_a32}" != x ]; then
			IS_A32=1
		fi
		if [ "x${is_a64}" != x ]; then
			IS_A64=1
		fi

		ls -l "$1"
		if [ "$IS_A32" = 1 ]; then
			"${STRIP}" ${STRIP_OPTION} "$1"
		fi

		if [ "$IS_A64" = 1 ]; then
			"${STRIP}" ${STRIP_OPTION} "$1"
		fi
		ls -l "$1"
	fi
}

for fn in $*; do
	strip_file "$fn"
done
