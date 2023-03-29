#ifndef __TEE_MSG_TYPE_H_
#define __TEE_MSG_TYPE_H_
#include <stdint.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)    (sizeof(a) / sizeof ((a)[0]))
#endif
typedef union {
    struct {
        uint8_t        msg_class;
        uint8_t        msg_flags;
        uint16_t    msg_id;
        uint32_t    msg_size;
    } __attribute__((packed)) send;

    struct {
        int64_t        ret_val;
        uint32_t    msg_size;
        uint32_t    reserve;
    } __attribute__((packed)) reply;
} msg_header;

#endif