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
#include <string.h>
#include <stdint.h>

const char *g_config_product_ou     = "Production";
const char *g_config_development_ou = "Development";
const char *g_config_cn             = "Config";

const char *get_config_cert_cn(void)
{
    return g_config_cn;
}

const char *get_config_cert_ou_prod(void)
{
    return g_config_product_ou;
}

const char *get_config_cert_ou_dev(void)
{
    return g_config_development_ou;
}
