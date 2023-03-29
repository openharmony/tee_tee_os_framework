#!/bin/bash
# clean for tee_os_framework
FRAMEWORK_DIR=$(pwd)/../
make TOPDIR=${FRAMEWORK_DIR} O=${FRAMEWORK_DIR}/output PREBUILD_ROOT=${FRAMEWORK_DIR}/prebuild clean -j