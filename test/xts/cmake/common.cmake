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


set(TEE_TEST_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(REPO_ROOT_DIR ${TEE_TEST_ROOT_DIR}/../../../..)
set(TEE_DEV_KIT_DIR ${TEE_TEST_ROOT_DIR}/../../tee_dev_kit)

set(TEE_BUILD_OUT_DIR ${TEE_TEST_ROOT_DIR}/output)
set(LIBRARY_OUTPUT_PATH ${TEE_BUILD_OUT_DIR})

if ("${TARGET_IS_ARM64}" STREQUAL "")
    set(TARGET_IS_ARM64 n)
endif()

include(${TEE_TEST_ROOT_DIR}/cmake/ta.cmake)
