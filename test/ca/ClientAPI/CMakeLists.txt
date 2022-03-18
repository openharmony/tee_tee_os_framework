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
    initializecontext_test.cpp
    opensession_test.cpp
    invokecommand_test.cpp
    closesession_test.cpp
    finalizecontext_test.cpp
    allocatesharedmemory_test.cpp
    registersharedmemory_test.cpp
    releasesharedmemory_test.cpp
)

ca_compile_pub(
    TEST_NAME
    client_api_ca

    SRC_LIST
    ${ca_sources}

    INCLUDE_DIRS
    common

    COMPILE_OPTS
    COMPILE_DEFS
)

