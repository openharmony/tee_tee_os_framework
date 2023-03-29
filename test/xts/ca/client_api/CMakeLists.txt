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

set(ca_sources)
list(APPEND ca_sources
    src/initializecontext_test.cpp
    src/opensession_test.cpp
    src/invokecommand_test.cpp
    src/closesession_test.cpp
    src/finalizecontext_test.cpp
    src/allocatesharedmemory_test.cpp
    src/registersharedmemory_test.cpp
    src/releasesharedmemory_test.cpp
)

ca_compile_pub(
    TEST_NAME
    client_api

    SRC_LIST
    ${ca_sources}

    INCLUDE_DIRS
    common

    COMPILE_OPTS
    COMPILE_DEFS
)

