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

include(${TEE_DEV_KIT_DIR}/ddk/build/cmake/common.cmake)

set(PUB_DRV_INCLUDE_DIRS)
list(APPEND PUB_DRV_INCLUDE_DIRS
    ${TEE_DEV_KIT_DIR}/ddk/include
    ${TEE_DEV_KIT_DIR}/sdk/include/TA
    ${TEE_DEV_KIT_DIR}/sdk/include/TA/ext
    ${TEE_TEST_ROOT_DIR}/utils/include
    ${TEE_TEST_ROOT_DIR}/utils/cmd_id
    /usr/include/aarch64-linux-android
)

set(PUB_DRV_COMPILE_OPTS)
list(APPEND PUB_DRV_COMPILE_OPTS
    -Wall
    -Werror
    -fstack-protector-all
    --target=aarch64-linux-android21
    -fvisibility=default
    -fno-exceptions
    -fno-common
)

set(PUB_DRV_COMPILE_DEFS)
list(APPEND PUB_DRV_COMPILE_DEFS
    # Test Macros Here
)

macro(drv_compile_pub)
    cmake_parse_arguments(
        DRV
        ""
        ""
        "ELF_NAME;SRC_LIST;INCLUDE_DIRS;COMPILE_OPTS;COMPILE_DEFS"
        ${ARGN}
    )

    message("DRV_ELF_NAME = ${DRV_ELF_NAME}")
    message("DRV_SRC_LIST = ${DRV_SRC_LIST}")
    message("DRV_INCLUDE_DIRS = ${DRV_INCLUDE_DIRS}")
    message("DRV_COMPILE_OPTS = ${DRV_COMPILE_OPTS}")
    message("DRV_COMPILE_DEFS = ${DRV_COMPILE_DEFS}")

    add_executable(${DRV_ELF_NAME})
    target_sources(${DRV_ELF_NAME} PRIVATE
        ${DRV_SRC_LIST}
    )

    target_include_directories(${DRV_ELF_NAME} PRIVATE 
        ${DRV_INCLUDE_DIRS}
        ${PUB_DRV_INCLUDE_DIRS}
    )

    target_compile_options(${DRV_ELF_NAME} PRIVATE 
        ${DRV_COMPILE_OPTS}
        ${PUB_DRV_COMPILE_OPTS}
    )

    target_compile_definitions(${DRV_ELF_NAME} PRIVATE 
        ${DRV_COMPILE_DEFS}
        ${PUB_DRV_COMPILE_DEFS}
    )

    target_link_options(${DRV_ELF_NAME} PRIVATE
        -v
        -s
        -nostdlib
        -Wl,--discard-all
        -Wl,-z,text
        -Wl,-z,now
        -Wl,-z,relro
        -Wl,-shared
        -Wl,-z,noexecstack
    )
    target_link_directories(${DRV_ELF_NAME} PRIVATE
        ${TEE_TEST_ROOT_DIR}/bin
    )

    target_link_libraries(${DRV_ELF_NAME} PRIVATE
    )
endmacro()
