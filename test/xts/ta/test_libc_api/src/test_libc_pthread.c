/*
 * Copyright (C) 2023 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <test_libc_func.h>
#include "ta_case_work.h"

TEE_Result TestPthreadAttr(void)
{
    static CaseInfo pthreadAttrTestList[] = {
        CASE_REGISTOR(pthread_attr_destroy_1_1),
        CASE_REGISTOR(pthread_attr_destroy_2_1),
        CASE_REGISTOR(pthread_attr_destroy_3_1),
        CASE_REGISTOR(pthread_attr_getstack_1_1),
        CASE_REGISTOR(pthread_attr_getstacksize_1_1),
        CASE_REGISTOR(pthread_attr_init_1_1),
        CASE_REGISTOR(pthread_attr_init_3_1),
        CASE_REGISTOR(pthread_attr_init_4_1),
        CASE_REGISTOR(pthread_attr_setstack_1_1),
        CASE_REGISTOR(pthread_attr_setstack_2_1),
        CASE_REGISTOR(pthread_attr_setstack_4_1),
        CASE_REGISTOR(pthread_attr_setstack_6_1),
        CASE_REGISTOR(pthread_attr_setstack_7_1),
        CASE_REGISTOR(pthread_attr_setstacksize_1_1),
        CASE_REGISTOR(pthread_attr_setstacksize_2_1),
        CASE_REGISTOR(pthread_attr_setstacksize_4_1),
    };

    CaseRunner(pthreadAttrTestList, number_of(pthreadAttrTestList));
    return CaseReporter(pthreadAttrTestList, number_of(pthreadAttrTestList));
}

TEE_Result TestPthreadBaseFunc(void)
{
    static CaseInfo pthreadBaseFuncList[] = {
        CASE_REGISTOR(pthread_create_1_1),
        CASE_REGISTOR(pthread_create_2_1),
        CASE_REGISTOR(pthread_create_4_1),
        CASE_REGISTOR(pthread_create_5_1),
        CASE_REGISTOR(pthread_create_5_2),
        CASE_REGISTOR(pthread_create_12_1),
        CASE_REGISTOR(pthread_exit_2_1),
        CASE_REGISTOR(pthread_exit_3_1),
        CASE_REGISTOR(pthread_once_1_3),
        CASE_REGISTOR(test_pthread_equal),
        CASE_REGISTOR(pthread_getspecific_1_1),
        CASE_REGISTOR(pthread_setspecific_1_2),
        CASE_REGISTOR(test_pthread_key_create),
    };

    CaseRunner(pthreadBaseFuncList, number_of(pthreadBaseFuncList));
    return CaseReporter(pthreadBaseFuncList, number_of(pthreadBaseFuncList));
}

TEE_Result TestPthreadMutexLock(void)
{
    static CaseInfo pthreadMutexLockList[] = {
        CASE_REGISTOR(pthread_mutex_init_1_1),
        CASE_REGISTOR(pthread_mutex_init_2_1_0),
        CASE_REGISTOR(pthread_mutex_lock_0_2),
        CASE_REGISTOR(pthread_mutex_lock_0_3),
        CASE_REGISTOR(pthread_mutex_lock_1_1_0),
        CASE_REGISTOR(pthread_mutex_trylock_0_1),
        CASE_REGISTOR(pthread_mutex_trylock_1_1),
        CASE_REGISTOR(pthread_mutex_trylock_4_1),
        CASE_REGISTOR(pthread_mutex_unlock_1_1),
        CASE_REGISTOR(pthread_mutex_destroy_1_1_0),
        CASE_REGISTOR(pthread_mutex_destroy_2_1),
        CASE_REGISTOR(pthread_mutex_destroy_4_2),
        CASE_REGISTOR(pthread_mutexattr_getprotocol_1_1),
        CASE_REGISTOR(pthread_mutexattr_gettype_1_1),
    };

    CaseRunner(pthreadMutexLockList, number_of(pthreadMutexLockList));
    return CaseReporter(pthreadMutexLockList, number_of(pthreadMutexLockList));
}

TEE_Result TestPthreadSpinLock(void)
{
    static CaseInfo pthreadSpinLockList[] = {
        CASE_REGISTOR(pthread_spin_destroy_1_1),
        CASE_REGISTOR(pthread_spin_init_1_1),
        CASE_REGISTOR(pthread_spin_lock_0_1),
        CASE_REGISTOR(pthread_spin_lock_0_3),
        CASE_REGISTOR(pthread_spin_trylock_0_1),
        CASE_REGISTOR(pthread_spin_trylock_1_1),
        CASE_REGISTOR(pthread_spin_trylock_4_1),
        CASE_REGISTOR(pthread_spin_unlock_1_1), 
    };

    CaseRunner(pthreadSpinLockList, number_of(pthreadSpinLockList));
    return CaseReporter(pthreadSpinLockList, number_of(pthreadSpinLockList));
}

TEE_Result TestPthreadCond(void)
{
    static CaseInfo pthreadCondTestList[] = {
        CASE_REGISTOR(pthread_cond_init_1_1),
        CASE_REGISTOR(pthread_cond_wait_0_1),
        CASE_REGISTOR(pthread_cond_wait_0_2),
        CASE_REGISTOR(pthread_cond_wait_0_3),
        CASE_REGISTOR(pthread_cond_broadcast_1_1),
    };

    CaseRunner(pthreadCondTestList, number_of(pthreadCondTestList));
    return CaseReporter(pthreadCondTestList, number_of(pthreadCondTestList));
}

TEE_Result TestSem(void)
{
    static CaseInfo semTestList[] = {
        CASE_REGISTOR(test_sem),
    };

    CaseRunner(semTestList, number_of(semTestList));
    return CaseReporter(semTestList, number_of(semTestList));
}
