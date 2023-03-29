#
# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
#

set(TARGET_NAME test_time_api.elf)

list(APPEND ta_src
    src/test_time_api_func.c
    src/test_time_api_main.c
)

ta_compile_pub(
    ELF_NAME
    ${TARGET_NAME}

    SRC_LIST
    ${ta_src}

    INCLUDE_DIRS

    COMPILE_OPTS

    COMPILE_DEFS
    API_LEVEL=3
)
