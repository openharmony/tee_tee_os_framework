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

#ifndef __TEE_BN_CONF_H
# define __TEE_BN_CONF_H

/* Only one for the following should be defined */
#  if defined(__arm) || defined(__arm__)
#  define THIRTY_TWO_BIT
#  undef SIXTY_FOUR_BIT_LONG
#  undef SIXTY_FOUR_BIT
#  elif defined(__aarch64__)
#  undef SIXTY_FOUR_BIT_LONG
#  undef THIRTY_TWO_BIT
#  define SIXTY_FOUR_BIT
#  endif

#endif
