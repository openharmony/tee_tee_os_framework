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

third_party_ossl_path="$1/openssl"
copy_path="$2/lib/teelib/libopenssl/"
cp -r "${third_party_ossl_path}" "${copy_path}"

cd "${copy_path}/openssl"

# config and generate dso_conf.h
echo "before ./config "
chmod +x ./config
./config
make include/crypto/dso_conf.h

if [ "$CONFIG_CRYPTO_SOFT_ENGINE" == "openssl3" ]; then
    make include/openssl/asn1.h
    make include/openssl/asn1t.h
    make include/openssl/bio.h
    make include/openssl/cmp.h
    make include/openssl/cms.h
    make include/openssl/conf.h
    make include/openssl/crmf.h
    make include/openssl/crypto.h
    make include/openssl/err.h
    make include/openssl/lhash.h
    make include/openssl/ocsp.h
    make include/openssl/opensslv.h
    make include/openssl/pkcs7.h
    make include/openssl/pkcs12.h
    make include/openssl/safestack.h
    make include/openssl/srp.h
    make include/openssl/ui.h
    make include/openssl/x509.h
    make include/openssl/x509_vfy.h
    make include/openssl/x509v3.h
    make providers/common/include/prov/der_digests.h
    make providers/common/include/prov/der_ec.h
    make providers/common/include/prov/der_rsa.h
    make providers/common/include/prov/der_sm2.h
    make providers/common/include/prov/der_wrap.h
    make providers/common/der/der_rsa_gen.c
    make providers/common/der/der_wrap_gen.c
    cp "$2"/lib/teelib/libopenssl/include/opensslconf3.h ./include/openssl/opensslconf.h
    cp "$2"/lib/teelib/libopenssl/include/bn_conf.h ./include/crypto/
else
    cp "$2"/lib/teelib/libopenssl/include/opensslconf.h ./include/openssl/
    cp "$2"/lib/teelib/libopenssl/include/bn_conf.h ./include/crypto/
fi

