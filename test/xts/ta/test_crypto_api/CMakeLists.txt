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

set(TARGET_NAME test_crypto_api)

list(APPEND ta_src
    src/oh_crypto_entry.c
	src/cases/cases_ae_crypto_basic_cases.c
	src/cases/cases_asym_crypto_basic_cases.c
	src/cases/cases_asym_sign_basic_cases.c
	src/cases/cases_derive_basic_cases.c
	src/cases/cases_digest_crypto_basic_cases.c
	src/cases/cases_entry.c
	src/cases/cases_mac_crypto_basic_cases.c
	src/cases/cases_sym_crypto_basic_cases.c
	src/data/alg_map_data.c
	src/data/key_object_database.c
	src/monad/monad_actions.c
	src/monad/monad_inverse_map.c
    src/monad/monad_run.c
)

ta_compile_pub(
    ELF_NAME
    ${TARGET_NAME}

    SRC_LIST
    ${ta_src}

    INCLUDE_DIRS

    COMPILE_OPTS

    COMPILE_DEFS
    API_LEVEL=3
)
