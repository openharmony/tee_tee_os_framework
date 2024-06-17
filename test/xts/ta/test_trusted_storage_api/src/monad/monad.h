/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef MONAD_H
#define MONAD_H
#include "test_trusted_storage_api_defines.h"
// monad_run.c
int MonadRun2(TestVector *tv);

// monad_actions.c
// ir init
int IRSetUp(IntermediateReprestation *ir);
int IRTearDown(IntermediateReprestation *ir);
// common operations
int CreatePersistentObject(IntermediateReprestation *ir);
int DeletePersistentObject(IntermediateReprestation *ir);
int OpenPersistentObject(IntermediateReprestation *ir);
int CloseObject(IntermediateReprestation *ir);
int SyncPersistentObject(IntermediateReprestation *ir);
int SeekObject(IntermediateReprestation *ir);
int WriteObject(IntermediateReprestation *ir);
int ReadObject(IntermediateReprestation *ir);
int CheckReadBuffer(IntermediateReprestation *ir);

int TruncateObject(IntermediateReprestation *ir);
int RenameObject(IntermediateReprestation *ir);
int GetObjectInfo(IntermediateReprestation *ir);
int CheckObjectSize(IntermediateReprestation *ir);
int InfoObjectData(IntermediateReprestation *ir);
int CheckInfoObject(IntermediateReprestation *ir);

int CreateMultiObject(IntermediateReprestation *ir);
int DeleteMultiObject(IntermediateReprestation *ir);
int AllocateEnumerator(IntermediateReprestation *ir);
int FreeEnumerator(IntermediateReprestation *ir);
int ResetEnumerator(IntermediateReprestation *ir);
int StartEnumerator(IntermediateReprestation *ir);
int EnumerateAllObject(IntermediateReprestation *ir);

int AllocateTransientObject(IntermediateReprestation *ir);
int FreeTransientObject(IntermediateReprestation *ir);
int RestrictObjectUsage(IntermediateReprestation *ir);
int ResetObject(IntermediateReprestation *ir);
int CheckObjectUsage(IntermediateReprestation *ir);

int InitRefAttr(IntermediateReprestation *ir);
int InitValueAttr(IntermediateReprestation *ir);
int PopulateTransientObject(IntermediateReprestation *ir);
int CopyObjectAttr(IntermediateReprestation *ir);
int GetObjectBufferAttr(IntermediateReprestation *ir);
int GetObjectValueAttr(IntermediateReprestation *ir);
int CheckAttr(IntermediateReprestation *ir);
int GenerateKey(IntermediateReprestation *ir);

// monad_inverse_map.c
int CopyReversElementList(MonadReversibilityProperty *dest, uint32_t *destSize);
int DisbalanceGroupElement(MonadReversibilityProperty *list, uint32_t listSize, ActionEntryType element);
int BalanceGroupElement(MonadReversibilityProperty *list, uint32_t listSize, ActionEntryType inverseElement);
int BalanceGroupElementList(IntermediateReprestation *ir);

#endif //  end MONAD_H