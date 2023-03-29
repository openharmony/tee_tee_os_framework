#
# Copyright (C) 2023 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
#

set(TARGET_NAME test_libc_api.elf)

list(APPEND ta_src
    src/test_time_api_func.c
    src/test_time_api_main.c
    src/test_libc_string.c
    src/test_libc_pthread.c
    src/test_libc_mem.c
    src/test_libc_main.c
    src/test_libc_common_lib.c
    src/ta_case_work.c
    src/libc_func/pthread_attr_destroy_1_1.c
    src/libc_func/pthread_attr_destroy_2_1.c
    src/libc_func/pthread_attr_destroy_3_1.c
    src/libc_func/pthread_attr_getstack_1_1.c
    src/libc_func/pthread_attr_getstacksize_1_1.c
    src/libc_func/pthread_attr_init_1_1.c
    src/libc_func/pthread_attr_init_3_1.c
    src/libc_func/pthread_attr_init_4_1.c
    src/libc_func/pthread_attr_setstack_1_1.c
    src/libc_func/pthread_attr_setstack_2_1.c
    src/libc_func/pthread_attr_setstack_4_1.c
    src/libc_func/pthread_attr_setstack_6_1.c
    src/libc_func/pthread_attr_setstack_7_1.c
    src/libc_func/pthread_attr_setstacksize_1_1.c
    src/libc_func/pthread_attr_setstacksize_2_1.c
    src/libc_func/pthread_attr_setstacksize_4_1.c
    src/libc_func/pthread_cond_broadcast_1_1.c
    src/libc_func/pthread_cond_init_1_1.c
    src/libc_func/pthread_cond_wait_0_1.c
    src/libc_func/pthread_cond_wait_0_2.c
    src/libc_func/pthread_cond_wait_0_3.c
    src/libc_func/pthread_create_12_1.c
    src/libc_func/pthread_create_1_1.c
    src/libc_func/pthread_create_2_1.c
    src/libc_func/pthread_create_4_1.c
    src/libc_func/pthread_create_5_1.c
    src/libc_func/pthread_create_5_2.c
    src/libc_func/pthread_equal.c
    src/libc_func/pthread_exit_2_1.c
    src/libc_func/pthread_exit_3_1.c
    src/libc_func/pthread_getspecific_1_1.c
    src/libc_func/pthread_getspecific_1_1.c
    src/libc_func/pthread_getspecific_1_1.c
    src/libc_func/pthread_mutex_destroy_1_1.c
    src/libc_func/pthread_mutex_destroy_1_1_0.c
    src/libc_func/pthread_mutex_destroy_2_1.c
    src/libc_func/pthread_mutex_destroy_4_2.c
    src/libc_func/pthread_mutex_init_0_1.c
    src/libc_func/pthread_mutex_init_1_1.c
    src/libc_func/pthread_mutex_init_2_1_0.c
    src/libc_func/pthread_mutex_init_3_1.c
    src/libc_func/pthread_mutex_lock_0_2.c
    src/libc_func/pthread_mutex_lock_0_3.c
    src/libc_func/pthread_mutex_lock_1_1_0.c
    src/libc_func/pthread_mutex_trylock_0_1.c
    src/libc_func/pthread_mutex_trylock_1_1.c
    src/libc_func/pthread_mutex_trylock_4_1.c
    src/libc_func/pthread_mutex_unlock_1_1.c
    src/libc_func/pthread_mutexattr_getprotocol_1_1.c
    src/libc_func/pthread_mutexattr_gettype_1_1.c
    src/libc_func/pthread_mutexattr_gettype_1_1.c
    src/libc_func/pthread_once_1_3.c
    src/libc_func/pthread_setspecific_1_2.c
    src/libc_func/pthread_spin_destroy_0_1.c
    src/libc_func/pthread_spin_destroy_1_1.c
    src/libc_func/pthread_spin_destroy_3_1.c
    src/libc_func/pthread_spin_init_1_1.c
    src/libc_func/pthread_spin_init_4_1.c
    src/libc_func/pthread_spin_lock_0_1.c
    src/libc_func/pthread_spin_lock_0_2.c
    src/libc_func/pthread_spin_lock_0_3.c
    src/libc_func/pthread_spin_lock_3_1.c
    src/libc_func/pthread_spin_trylock_0_1.c
    src/libc_func/pthread_spin_trylock_1_1.c
    src/libc_func/pthread_spin_trylock_4_1.c
    src/libc_func/pthread_spin_trylock_4_1_0.c
    src/libc_func/pthread_spin_unlock_1_1.c
    src/libc_func/test-string.c
    src/libc_func/test_ctype.c
    src/libc_func/test_error.c
    src/libc_func/test_getpid.c
    src/libc_func/test_locale.c
    src/libc_func/test_math.c
    src/libc_func/test_mmap.c
    src/libc_func/test_multibyte.c
    src/libc_func/test_prng.c
    src/libc_func/test_pthread_key_create.c
    src/libc_func/test_sem.c
    src/libc_func/test_stdio.c
    src/libc_func/test_stdlib.c
    src/libc_func/test_time.c
    src/libc_func/tst-calloc.c
    src/libc_func/tst-malloc.c
    src/libc_func/tst_free.c
)

list(APPEND cflags
    -mfloat-abi=softfp
    -Wno-bitwise-op-parentheses
    -Wno-shift-op-parentheses
    -Wno-implicit-function-declaration
    -Wno-int-conversion
    -Wno-unused-parameter
)

ta_compile_pub(
    ELF_NAME
    ${TARGET_NAME}

    SRC_LIST
    ${ta_src}

    INCLUDE_DIRS

    COMPILE_OPTS
    ${cflags}

    COMPILE_DEFS
    API_LEVEL=3
)
