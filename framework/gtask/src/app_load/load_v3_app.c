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
#include "load_v3_app.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <securec.h>
#include <sys/mman.h>
#include <dyn_conf_dispatch_inf.h>
#include "tee_log.h"

#ifdef DYN_TA_SUPPORT_V3
static bool overflow_check(uint32_t a, uint32_t b)
{
    if (a > UINT32_MAX_VALUE - b)
        return true;
    return false;
}


TEE_Result tee_secure_get_img_size_v3(const uint8_t *share_buf, uint32_t buf_len, uint32_t *size)
{
    ta_image_hdr_v3_t image_hdr_v3;

    if (share_buf == NULL || size == NULL) {
        tloge("bad parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (buf_len <= sizeof(ta_image_hdr_v3_t)) {
        tloge("img buf len is 0x%x too small\n", buf_len);
        return TEE_ERROR_GENERIC;
    }
    errno_t rc = memcpy_s(&image_hdr_v3, sizeof(image_hdr_v3), share_buf, sizeof(ta_image_hdr_v3_t));
    if (rc != EOK) {
        tloge("copy is failed\n");
        return TEE_ERROR_SECURITY;
    }

    if (overflow_check(image_hdr_v3.context_len, sizeof(ta_image_hdr_v3_t)))
        return TEE_ERROR_GENERIC;
    if (image_hdr_v3.context_len + sizeof(ta_image_hdr_v3_t) > MAX_IMAGE_LEN) {
        tloge("image hd error context len: 0x%x\n", image_hdr_v3.context_len);
        tloge("image hd error ta hd len: 0x%x\n", sizeof(ta_image_hdr_v3_t));
        return TEE_ERROR_GENERIC;
    }

    *size = image_hdr_v3.context_len + sizeof(ta_image_hdr_v3_t);
    return TEE_SUCCESS;
}
#endif
