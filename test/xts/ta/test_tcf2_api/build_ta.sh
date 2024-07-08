#!/bin/bash

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

set -e

export SOURCE_PATH=$(dirname $0)
export ABS_SOURCE_PATH=$(cd ${SOURCE_PATH};pwd)
export TEE_BUILD_PATH=${ABS_SOURCE_PATH}/../../../
SIGNTOOL_DIR=${TEE_BUILD_PATH}/build/tools
CUR_DIR=$(pwd)

build_clean()
{
    [ -d "output" ] && rm -rf output #clean
    make clean
}

cmake_build()
{
    echo "start cmake build target"
    build_clean

    mkdir -p output #create cmake_build file
    cd output

    CMAKE_TOOLCHAIN_FILE=${TEE_BUILD_PATH}/build/cmake/llvm_toolchain.cmake

    cmake \
          -DCMAKE_VERBOSE_MAKEFILE=on \
          -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \

    cmake --build . -j8
}

mk_build()
{
    echo "start make build target"
    build_clean
    make V=3 libcombine -j4
}

if [ "${1}" = "clean" ]; then
    build_clean
else
    #you can also use cmake_build here
    echo "do make compile"
    mk_build
#    python3 ${SIGNTOOL_DIR}/ta_check_undefined_symbol.py libcombine.so
    python3 -B ${SIGNTOOL_DIR}/signtool_sec.py --in_path ${CUR_DIR} --out_path ${CUR_DIR} --privateCfg ${SIGNTOOL_DIR}/../signkey/ta_sign_algo_config.ini
fi
