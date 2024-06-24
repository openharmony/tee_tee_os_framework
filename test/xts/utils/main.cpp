/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <vector>
#include <string>
#include <iostream>

#include "gtest/gtest.h"
using namespace std;

static int IsTEESupport()
{
    FILE *fp = popen("pidof teecd", "r");
    char buffer[10] = { 0 };
    if (fgets(buffer, 10, fp) == NULL)
        return 1;
    else
        return 0;
}

int main(int32_t argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);
    int rc = IsTEESupport();
    if (rc == 1) {
        printf("[========]this device not support TEE, so test stop!\n");
        return 1;
    }

    return RUN_ALL_TESTS();
}
