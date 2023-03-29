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

include(${TEE_DEV_KIT_DIR}/sdk/build/cmake/common.cmake)

set(PUB_TA_INCLUDE_DIRS)
list(APPEND PUB_TA_INCLUDE_DIRS
    ${TEE_TEST_ROOT_DIR}/utils/include
    ${TEE_TEST_ROOT_DIR}/utils/cmd_id
)

macro(ta_compile_pub)
    cmake_parse_arguments(
        TA
        ""
        ""
        "ELF_NAME;SRC_LIST;INCLUDE_DIRS;COMPILE_OPTS;COMPILE_DEFS"
        ${ARGN}
    )

    add_library(${TA_ELF_NAME} SHARED)
    target_sources(${TA_ELF_NAME} PRIVATE
        ${TA_SRC_LIST}
        ${SDK_C_SOURCES}
    )

    target_include_directories(${TA_ELF_NAME} PRIVATE
        ${PUB_TA_INCLUDE_DIRS}
        ${TA_INCLUDE_DIRS}
        ${COMMON_INCLUDES}
    )

    target_compile_options(${TA_ELF_NAME} PRIVATE 
        ${TA_COMPILE_OPTS}
        ${COMMON_CFLAGS}
    )

    target_compile_definitions(${TA_ELF_NAME} PRIVATE 
        ${TA_COMPILE_DEFS}
    )

    target_link_options(${TA_ELF_NAME} PRIVATE
        -v
        ${COMMON_LDFLAGS}
    )

    target_link_directories(${TA_ELF_NAME} PRIVATE
        ${TEE_TEST_ROOT_DIR}/bin
    )

    target_link_libraries(${TA_ELF_NAME} PRIVATE
    )
endmacro()

macro(ta_entry_check)
    cmake_parse_arguments(
        SIGN
        ""
        ""
        "TARGET_NAME"
        ${ARGN}
    )

    add_custom_command(
        TARGET ${SIGN_TARGET_NAME} POST_BUILD
        COMMAND sh $ENV{TEE_BUILD_PATH}/build/tools/ta_entry_check.sh ${CMAKE_READELF} ${TEE_BUILD_OUT_DIR}/lib${SIGN_TARGET_NAME}.so n y ${TARGET_IS_ARM64}
    )
endmacro()
