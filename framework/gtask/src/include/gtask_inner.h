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
#ifndef GTASK_CORE_GTASK_INNER_H
#define GTASK_CORE_GTASK_INNER_H

#include <dlist.h>
#include <ipclib.h>
#include "mem_page_ops.h" /* paddr_t */
#include "ta_framework.h"
#include "sys_timer.h"
#include <drv.h>

#define GT_ERR_OK             0
#define GT_ERR_END_CMD        (-1)
#define GT_ERR_CMD_NO_HANDLED (-2)

#define CMD_TYPE_NS_TO_SECURE     0x1
#define CMD_TYPE_SECURE_TO_SECURE 0x2
#define CMD_TYPE_SECURE_CONFIG    0xf

#define MAX_SESSION_ID TA_SESSION_MAX

#define GT_SHARED_CMD_QUEUES_SIZE 0x1000

#define TA_REGION_RELEASE   0U
#define TA_REGION_FOR_REUSE 1U

#define DEFAULT_TASK_PRIO     10
#define DEFAULT_MSG_QUEUE_NUM 2
#define LOAD_ALL_TASKS        NULL
#define PER_USER_RANGE        (100000) /* multi user range */

/* judge return value is error */
#define is_err_ret(result) \
    (((result == TEE_SUCCESS) || (result == TEE_PENDING) || (result == TEE_PENDING2)) ? false : true)

#define MAX_SMC_CMD 18

/* support linux DECLEAR_BITMAP ops */
#undef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#undef BITS_PER_BYTE
#define BITS_PER_BYTE 8
#undef BITS_PER_LONG
#define BITS_PER_LONG 64
#undef BITS_TO_LONGS
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(uint64_t))
#undef BIT_MASK
#define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))
#undef BIT_WORD
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
#undef DECLEAR_BITMAP
#define DECLEAR_BITMAP(name, bits) uint64_t name[BITS_TO_LONGS(bits)]

static inline void set_bit(int nr, volatile uint64_t *addr)
{
    uint64_t mask = BIT_MASK(nr);
    uint64_t *p   = ((uint64_t *)addr) + BIT_WORD(nr);
    *p |= mask;
}

static inline void clear_bit(int nr, volatile uint64_t *addr)
{
    uint64_t mask = BIT_MASK(nr);
    uint64_t *p   = ((uint64_t *)addr) + BIT_WORD(nr);
    *p &= ~mask;
}

static inline int test_bit(int nr, const volatile uint64_t *addr)
{
    return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG - 1)));
}

typedef struct {
    DECLEAR_BITMAP(in_bitmap, MAX_SMC_CMD);
    DECLEAR_BITMAP(doing_bitmap, MAX_SMC_CMD);
    DECLEAR_BITMAP(out_bitmap, MAX_SMC_CMD);

    uint32_t smc_lock;
    volatile uint32_t last_in;
    smc_cmd_t in[MAX_SMC_CMD];
    volatile uint32_t last_out;
    smc_cmd_t out[MAX_SMC_CMD];
} nwd_cmd_t;

#define MAGIC_SIZE   16
#define MAGIC_STRING "Trusted-magic"

#define SHIFT_OFFSET 32
#define PARAM_CNT 5

/*
 * One encrypted block, which is aligned with CIPHER_BLOCK_BYTESIZE bytes
 * Head + Payload + Padding
 */
struct encryption_head {
    int8_t magic[MAGIC_SIZE];
    uint32_t payload_len;
};

#define NUM_OF_SO                   1
#define KIND_OF_SO                  2
#define MAX_SHA_256_SZ              32
#define HASH_PLAINTEXT_SIZE         (MAX_SHA_256_SZ + sizeof(struct encryption_head))
#define CIPHER_KEY_BYTESIZE         32 /* AES-256 key size */
#define CIPHER_BLOCK_BYTESIZE       16 /* AES-CBC cipher block size */
#define HASH_PLAINTEXT_ALIGNED_SIZE ALIGN_UP(HASH_PLAINTEXT_SIZE, CIPHER_BLOCK_BYTESIZE)
#define IV_BYTESIZE                 16 /* AES-CBC encryption initialization vector size */

struct ta2ta_info_t {
    int handle;
    bool is_load_worked; /* indicate if sec file agent has worked */
};

#define INVALID_SERVICE_INDEX  (-1)
#define ERROR_SESSION_ID       (-1)
#define INVALID_SESSION_HANDLE (-1)

#define NOTIFY_MEM_SIZE   (4 * 1024)

/* session context contain of service index(high 16 bits) and session id(low 16 bits) */
#define set_session_context_bit(index, id)    ((index << 16) | (id & 0x0000ffff))
#define service_index_of_context(context) (context >> 16)
#define session_id_of_context(context)    (context & 0x0000ffff)

#define GLOBAL_TSK_ID 0
#define SMCMGR_PID    6
#define REET_TSK_ID   SMCMGR_PID
#define TASK_ID_NULL    0xFFFFFFFF

struct command_state {
    uint32_t cmd_id;
    uint32_t dev_id;
    uint32_t ta2ta_from_taskid;
    bool ta2ta_start;
    bool ta2ta_switch;
    bool ta2ta_done;
    bool started;
};

struct service_attr {
    bool build_in;
    bool ta_64bit;
    uint32_t img_type;
};

/* list head of agent */
struct agent_control {
    uint32_t id;
    /* State of the agent, locked by TA */
    bool locked;
    uint64_t buffer;
    paddr_t phys_buffer;
    uint32_t size;
    struct session_struct *locking_session;
    /* The sessions waiting list */
    struct dlist_node waiting_sessions;
    /* Part of the global agent list */
    struct dlist_node list;
    /* Part of the locked agents in the session object */
    struct dlist_node session_list;
};

#endif /* GTASK_CORE_GTASK_INNER_H */
