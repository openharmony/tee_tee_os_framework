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

#ifndef __TEST_LOG_H__
#define __TEST_LOG_H__

#define __FILENAME__ (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1):__FILE__)

#define TEST_PRINT_INFO(fmt, ...)                                                   \
do {                                                                                \
        fprintf(stdout, "[Info] [%s, %d] " fmt "\n", __FILENAME__, __LINE__, ##__VA_ARGS__);   \
} while (0)

#define TEST_PRINT_ERROR(fmt, ...)                                                  \
do {                                                                                \
        fprintf(stderr, "[Err] [%s, %d] " fmt "\n", __FILENAME__, __LINE__, ##__VA_ARGS__);   \
} while (0)

#endif
