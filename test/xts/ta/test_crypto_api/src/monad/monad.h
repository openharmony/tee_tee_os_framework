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
#include "test_crypto_api_types.h"
#include "test_crypto_data.h"
#include "tee_crypto_api.h"
// monad_run.c
int MonadRun2(TestVector *tv);

// monad_actions.c
// ir init
int IRSetUp(IntermediateReprestation *ir);
int IRTearDown(IntermediateReprestation *ir);
// common operations
int GlbFree(IntermediateReprestation *ir);
int GlbAlloc(IntermediateReprestation *ir);
int GlbGetInfo(IntermediateReprestation *ir);
int GlbGetInfoMulti(IntermediateReprestation *ir);
int GlbReset(IntermediateReprestation *ir);
int GlbS1S2(IntermediateReprestation *ir);
int GlbS1S2Null(IntermediateReprestation *ir);
int GlbCopy(IntermediateReprestation *ir);
int GlbCopyRpl(IntermediateReprestation *ir);
int GlbIsAlgSprt(IntermediateReprestation *ir);
// digest operations
int DIUpdateFwd(IntermediateReprestation *ir);
int DIDofinalFwd(IntermediateReprestation *ir);
int DIUpdateBck(IntermediateReprestation *ir);
int DIDofinalBck(IntermediateReprestation *ir);
// symmetric cipher operations
int SCInitFwd(IntermediateReprestation *ir);
int SCUpdateFwd(IntermediateReprestation *ir);
int SCDofinalFwd(IntermediateReprestation *ir);
int SCInitBck(IntermediateReprestation *ir);
int SCUpdateBck(IntermediateReprestation *ir);
int SCDofinalBck(IntermediateReprestation *ir);
// mac operations
int MInitFwd(IntermediateReprestation *ir);
int MUpdateFwd(IntermediateReprestation *ir);
int MComputeFwd(IntermediateReprestation *ir);
int MInitBck(IntermediateReprestation *ir);
int MUpdateBck(IntermediateReprestation *ir);
int MCapareBck(IntermediateReprestation *ir);
// ae opeartions
int AEInitFwd(IntermediateReprestation *ir);
int AEUpdateAadFwd(IntermediateReprestation *ir);
int AEUpdateAadMtlFwd(IntermediateReprestation *ir);
int AEUpdateFwd(IntermediateReprestation *ir);
int AEUpdate0Fwd(IntermediateReprestation *ir);
int AEInitBck(IntermediateReprestation *ir);
int AEUpdateAadBck(IntermediateReprestation *ir);
int AEUpdateAadMtlBck(IntermediateReprestation *ir);
int AEUpdateBck(IntermediateReprestation *ir);
int AEUpdate0Bck(IntermediateReprestation *ir);
int AEEncFinalFwd(IntermediateReprestation *ir);
int AEEncFinalOmtFwd(IntermediateReprestation *ir);
int AEDoFinalBck(IntermediateReprestation *ir);
int AEDoFinalOmtBck(IntermediateReprestation *ir);
// asymmetric crypto operations
int ASEncryFwd(IntermediateReprestation *ir);
int ASDecryBck(IntermediateReprestation *ir);
// asymmetric sign operations
int ASSignFwd(IntermediateReprestation *ir);
int ASVerifyBck(IntermediateReprestation *ir);
// derive operations
int DRDeriveFwd(IntermediateReprestation *ir);
int DRDeriveBck(IntermediateReprestation *ir);

// monad_inverse_map.c
int CopyReversElementList(MonadReversibilityProperty *dest, uint32_t *destSize);
int DisbalanceGroupElement(MonadReversibilityProperty *list, uint32_t listSize, ActionEntryType element);
int BalanceGroupElement(MonadReversibilityProperty *list, uint32_t listSize, ActionEntryType inverseElement);
int BalanceGroupElementList(IntermediateReprestation *ir);

#endif //  end MONAD_H