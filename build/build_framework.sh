#!/bin/bash
# compile tee_os_framework
FRAMEWORK_DIR=$(pwd)/../
make V=3 TOPDIR=${FRAMEWORK_DIR} O=${FRAMEWORK_DIR}/output PREBUILD_ROOT=${FRAMEWORK_DIR}/prebuild GEN_CONF_FILE -j
make V=3 TOPDIR=${FRAMEWORK_DIR} O=${FRAMEWORK_DIR}/output PREBUILD_ROOT=${FRAMEWORK_DIR}/prebuild install_headers -j
make V=3 TOPDIR=${FRAMEWORK_DIR} O=${FRAMEWORK_DIR}/output PREBUILD_ROOT=${FRAMEWORK_DIR}/prebuild libs -j
make V=3 TOPDIR=${FRAMEWORK_DIR} O=${FRAMEWORK_DIR}/output PREBUILD_ROOT=${FRAMEWORK_DIR}/prebuild tees -j
make V=3 TOPDIR=${FRAMEWORK_DIR} O=${FRAMEWORK_DIR}/output PREBUILD_ROOT=${FRAMEWORK_DIR}/prebuild package -j