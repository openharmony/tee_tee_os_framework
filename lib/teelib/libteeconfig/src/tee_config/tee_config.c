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
#include "tee_config.h"
#include <sys/priorities.h> /* for HM_PRIO_TEE_* */

static struct drv_frame_info g_drv_frame_configs[] = {
#if defined(TEE_SUPPORT_DRV_SERVER_64BIT) || defined(TEE_SUPPORT_DRV_SERVER_32BIT)
    { "drvmgr", AC_SID_DRVMGR, 0, 0, 0, DRVMGR, true },
    { "drvmgr_multi", AC_SID_DRVMGR, 0, 0, 0, DRVMGR, false },
#endif
};

const uint32_t g_drv_frame_num = sizeof(g_drv_frame_configs) / sizeof(g_drv_frame_configs[0]);

uint32_t get_drv_frame_nums(void)
{
    return g_drv_frame_num;
}

struct drv_frame_info *get_drv_frame_infos(void)
{
    return g_drv_frame_configs;
}
