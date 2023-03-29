#!/bin/bash
# compile tee_os_framework
# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

FRAMEWORK_DIR=$(pwd)/../
make V=3 TOPDIR=${FRAMEWORK_DIR} O=${FRAMEWORK_DIR}/output PREBUILD_ROOT=${FRAMEWORK_DIR}/prebuild GEN_CONF_FILE -j
make V=3 TOPDIR=${FRAMEWORK_DIR} O=${FRAMEWORK_DIR}/output PREBUILD_ROOT=${FRAMEWORK_DIR}/prebuild install_headers -j
make V=3 TOPDIR=${FRAMEWORK_DIR} O=${FRAMEWORK_DIR}/output PREBUILD_ROOT=${FRAMEWORK_DIR}/prebuild libs -j
make V=3 TOPDIR=${FRAMEWORK_DIR} O=${FRAMEWORK_DIR}/output PREBUILD_ROOT=${FRAMEWORK_DIR}/prebuild tees -j
make V=3 TOPDIR=${FRAMEWORK_DIR} O=${FRAMEWORK_DIR}/output PREBUILD_ROOT=${FRAMEWORK_DIR}/prebuild package -j
