#!/bin/bash
# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
set -e

opensslpath="$1/openssl"
ln -s "${opensslpath}" ./

cd $opensslpath

# config and generate dso_conf.h
echo "before ./config "
./config
make include/crypto/dso_conf.h
cp "$2"/lib/teelib/libopenssl/include/opensslconf.h $opensslpath/include/openssl/
cp "$2"/lib/teelib/libopenssl/include/bn_conf.h $opensslpath/include/crypto/
patch -p1 < $2/lib/teelib/libopenssl/OpenSSL-customized-modification-unify.patch

