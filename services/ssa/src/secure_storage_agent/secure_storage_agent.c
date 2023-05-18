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
#include <sys/mman.h>
#include <mem_ops.h>
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_init.h"
#include "tee_ext_api.h"
#include "tee_ss_agent_api.h"
#include "tee_mem_mgmt_api.h"
#include "sfs_internal.h"
#include "sfs.h"
#include "agent.h"
#include "securec.h"
#include "ipclib.h"
#include "ssa_enumerator.h"
#include "tee_internal_task_pub.h"
#include "ssa_fs.h"
#include <huk_service_msg.h>
#include <ipclib_hal.h>

bool g_is_ssa_reg = false;

/* structure for files of TAs */
static client_t g_clients[SRV_MAX_CLIENTS];

/* structure for files of TEE_OBJECT_STORAGE_PRIVATE */
static file_link_t g_private_storage[MAX_PRIVATE_OPEN_FILES];

struct ss_msg_queue_t g_ssa_msg_queue;

uint32_t g_global_handle;
uint32_t g_permsrv_handle;

static uint32_t g_arch_version = SFS_ARCH_VERSION_SSA;

TEE_UUID g_ssa_uuid = TEE_SERVICE_SSA;

static client_t *get_sender_client_proc(uint32_t sender, char dead)
{
    uint32_t i;

    for (i = 0; i < SRV_MAX_CLIENTS; i++) {
        if (g_clients[i].task_id == sender && g_clients[i].dead == dead)
            return &g_clients[i];
    }
    return NULL;
}

client_t *get_sender_client(uint32_t sender)
{
    return get_sender_client_proc(sender, 0);
}

bool is_client_register(uint32_t sender)
{
    client_t *client = get_sender_client(sender);
    if (client == NULL)
        return false;

    return true;
}

static client_t *unreg_get_sender_client(uint32_t sender)
{
    client_t *client = NULL;

    client = get_sender_client_proc(sender, 1);
    if (client == NULL)
        client = get_sender_client_proc(sender, 0);

    return client;
}

/* register TA. */
void register_uuid(uint32_t sender, TEE_UUID uuid, uint32_t user_id, bool ssa_enum_enable)
{
    uint32_t i;
    errno_t rc;

    for (i = 0; i < SRV_MAX_CLIENTS; i++) {
        if (g_clients[i].task_id == 0) {
            rc = memset_s((void *)(&g_clients[i]), sizeof(g_clients[i]), 0, sizeof(client_t));
            if (rc != EOK)
                tloge("memset client %u failed, %x", i, rc);

            g_clients[i].task_id          = sender;
            g_clients[i].user_id          = user_id;
            g_clients[i].ssa_enum_enable  = ssa_enum_enable;
            rc = memmove_s(&g_clients[i].uuid, sizeof(g_clients[i].uuid), &uuid, sizeof(TEE_UUID));
            if (rc != EOK)
                tloge("memmove failed %x\n", rc);

            break;
        }
    }
    if (i >= SRV_MAX_CLIENTS)
        tloge("sfs register uuid session memory overflow, sender is 0x%x!\n", sender);
}
static void pre_unregister_remove_hmipccachech(const union ssa_agent_msg *msg, uint32_t sender)
{
    uint32_t res_code;

    if (msg == NULL) {
        tloge(" invalid msg\n");
        return;
    }

    if (sender == g_global_handle) {
        tlogd("unregister task: %x\n", msg->reg.taskid);
        (void)ipc_release_from_taskid(msg->reg.taskid, 0);
    } else {
        res_code = ipc_hunt_by_name(PERMSRV_SAVE_FILE, &g_permsrv_handle);
        if (res_code != 0) {
            g_permsrv_handle = 0;
            tlogd("hunt by permsrv name error... %x\n", res_code);
            return;
        }
        if (sender == g_permsrv_handle) {
            tlogd("unregister task: %x\n", msg->reg.taskid);
            (void)ipc_release_from_taskid(msg->reg.taskid, 0);
            (void)ipc_release_by_name(PERMSRV_SAVE_FILE);
        }
    }

    return;
}

char pre_unregister_uuid(const union ssa_agent_msg *msg, uint32_t sender)
{
    client_t *tmp_client = NULL;
    uint32_t i;
    uint32_t files_count;
    errno_t rc;

    if (msg == NULL) {
        tloge("pre UnRegisterUUID invalid msg\n");
        return 0;
    }

    tlogd("preunregister  0x%x  from %x\n", msg->reg.taskid, sender);

    /* 1. search the client whitch is not dead */
    tmp_client = get_sender_client_proc(msg->reg.taskid, 0);
    if (tmp_client == NULL) {
        tloge("Illegal client, not found any undead client  sndr is 0x%x\n", sender);
        return 0;
    }

    /* 2. check if this client havn't open file , then remove it at once. or mark is as dead */
    files_count = 0;

    for (i = 0; i < MAX_CLIENT_OPEN_FILES; i++) {
        if (tmp_client->file_instance[i].file_link != NULL)
            files_count++;
    }

    if (files_count == 0) {
        pre_unregister_remove_hmipccachech(msg, sender);

        rc = memset_s((void *)tmp_client, sizeof(client_t), 0, sizeof(client_t));
        if (rc != EOK)
            tloge("memset tmp client failed, %x\n", rc);
    } else {
        tmp_client->dead = 1;
        tlogd("mark the client is dead.\n");
    }

    return tmp_client->dead;
}

/* unregister TA. */
void unregister_uuid(uint32_t sender, const char *name)
{
    uint32_t i;
    errno_t rc;
    meta_data_t *meta = NULL;
    client_t *client = unreg_get_sender_client(sender);

    tlogd("unregister start 0x%x\n", sender);

    if (client == NULL) {
        tloge("Illegal client, sender is 0x%x\n", sender);
        return;
    }

    client->dead = 1;

    (void)ipc_release_from_taskid(sender, 0);
    (void)ipc_release_by_name(name);

    for (i = 0; i < MAX_CLIENT_OPEN_FILES; i++) {
        if ((client->file_instance[i].file_link) == NULL) {
            continue;
        }

        if (client->file_instance[i].file_link->link_count == 0) {
            client->file_instance[i].file_link = NULL;
            continue;
        }

        tlogd("force clean %u\n", i + 1);

        client->file_instance[i].file_link->link_count--;
        if (client->file_instance[i].file_link->link_count == 0) {
            meta = client->file_instance[i].file_link->sfd->meta_data;
            (void)ssa_close(client->file_instance[i].file_link->sfd);
            client->file_instance[i].file_link->sfd = 0;
            free_meta_data(&meta);
        }

        client->file_instance[i].file_link = NULL;
    }

    rc = memset_s((void *)&(client->uuid), sizeof(client->uuid), 0, sizeof(TEE_UUID));
    if (rc != EOK)
        tlogw("memset failed, %x\n", rc);

    client->task_id         = 0;
    client->dead            = 0;
    client->ssa_enum_enable = false;
    tlogd("Done\n");
}

bool is_enum_enable(const TEE_UUID *uuid)
{
    uint32_t i;
    bool find = true;

    if (uuid == NULL)
        return false;

    for (i = 0; i < SRV_MAX_CLIENTS; i++) {
        find = (TEE_MemCompare(uuid, &(g_clients[i].uuid), sizeof(TEE_UUID)) == 0) && g_clients[i].ssa_enum_enable;
        if (find)
            return true;
    }

    return false;
}
static uint32_t get_sender_userid(uint32_t sender)
{
    client_t *client = get_sender_client(sender);

    if (client == NULL) {
        uint32_t i_count;
        uint32_t count = 0;
        tloge("dump userid  the client array!\n");
        for (i_count = 0; i_count < SRV_MAX_CLIENTS; i_count++)
            if (g_clients[i_count].task_id != 0) {
                tloge("%uth taskid %x uuid %x dead is %x!\n", i_count, g_clients[i_count].task_id,
                      g_clients[i_count].uuid.timeLow, g_clients[i_count].dead);
                count++;
            }
        tloge("Illegal client, sndr is 0x%x, count is 0x%x!\n", sender, count);
        return 0;
    }

    return (client->user_id);
}

TEE_UUID *get_sender_uuid(uint32_t sender)
{
    client_t *client = get_sender_client(sender);

    if (client == NULL) {
        uint32_t i_count;
        uint32_t count = 0;
        tloge("dump uuid the client array!\n");
        for (i_count = 0; i_count < SRV_MAX_CLIENTS; i_count++)
            if (g_clients[i_count].task_id != 0) {
                tloge("%uth taskid %x uuid %x dead is %x!\n", i_count, g_clients[i_count].task_id,
                      g_clients[i_count].uuid.timeLow, g_clients[i_count].dead);
                count++;
            }
        tloge("Illegal client, sndr is 0x%x, count is 0x%x!\n", sender, count);
        return 0;
    }

    return (&client->uuid);
}

TEE_UUID *get_current_uuid(void)
{
    return (&g_ssa_uuid);
}

/* check shared accesses.
 * see: TEE Internal Core API Specification - Public Review v1.2.0.1
 *          Paragraph: 5.8.3 Persistent Object Sharing Rules
 * Multiple handles may be opened on the same object simultaneously using the functions
 * TEE_OpenPersistentObject or TEE_CreatePersistentObject, but sharing MUST be explicitly allowed.
 *  More precisely, at any one time the following constraints apply: If more than one handle is opened
 *  on the same object, and if any of these object handles was opened with the
 *  flag TEE_DATA_FLAG_ACCESS_READ, then all the object handles MUST have been opened with the
 *  flag TEE_DATA_FLAG_SHARE_READ. There is a corresponding constraint with the
 *  flags TEE_DATA_FLAG_ACCESS_WRITE and TEE_DATA_FLAG_SHARE_WRITE.
 *  Accessing an object with write-meta rights is exclusive and can never be shared.
 */
bool check_shared_access(const struct sfd_t *sfd, uint32_t flags)
{
    bool status = true;

    if (sfd == NULL)
        return false;
    tlogd("start prev:%x - this: %x \n", sfd->flags, flags);
    /*
     * shared read access is allowed only if both (the first an this one)
     * has TEE_DATA_FLAG_SHARE_READ set
     */
    if ((flags & TEE_DATA_FLAG_ACCESS_READ) && !(sfd->flags & flags & TEE_DATA_FLAG_SHARE_READ)) {
        tlogd("shared read - no access\n");
        status = false;
    }
    /*
     * shared write access is allowed only if both (the first an this one)
     * has TEE_DATA_FLAG_SHARE_WRITE set
     */
    if ((flags & TEE_DATA_FLAG_ACCESS_WRITE) && !(sfd->flags & flags & TEE_DATA_FLAG_SHARE_WRITE)) {
        tlogd("shared write - no access\n");
        status = false;
    }
    /* shared access is not allowed with TEE_DATA_FLAG_ACCESS_WRITE_META */
    if ((flags & TEE_DATA_FLAG_ACCESS_WRITE_META) || (sfd->flags & TEE_DATA_FLAG_ACCESS_WRITE_META)) {
        tlogd("write meta - no access\n");
        status = false;
    }

    if (flags == 0) {
        tlogd("flags - no access\n");
        status = false;
    }

    return status;
}
/*
 * check if there is already opened file descriptor for this file.
 * if there is, return pointer to it. Otherwise return null.
 */
static file_link_t *find_already_open(const meta_data_t *meta)
{
    uint32_t i;

    if (meta == NULL || (meta->file_id) == NULL)
        return NULL;

    for (i = 0; i < MAX_PRIVATE_OPEN_FILES; i++) {
        if (g_private_storage[i].link_count) {
            if ((TEE_MemCompare(&g_private_storage[i].sfd->meta_data->uuid, &meta->uuid, sizeof(TEE_UUID)) == 0) &&
                (g_private_storage[i].first_opened) &&
                (g_private_storage[i].sfd->meta_data->file_id_len == meta->file_id_len) &&
                (TEE_MemCompare(g_private_storage[i].sfd->meta_data->file_id, meta->file_id, meta->file_id_len) == 0)) {
                tlogd("file has been opened in %u\n", i);
                return &g_private_storage[i];
            }
        }
    }

    return NULL;
}

/*
 * There is no open file file descriptor for this file.
 * We create a new one and also create a new file instance of client
 */
uint32_t create_file_instance_to_client(uint32_t sender, struct sfd_t *sfd)
{
    uint32_t k;
    file_link_t *flink = NULL;
    client_t *client   = get_sender_client(sender);
    bool temp          = false;

    if (client == NULL || sfd == NULL) {
        tloge("Illegal client or sfd\n");
        return 0;
    }

    for (k = 0; k < MAX_PRIVATE_OPEN_FILES; k++) {
        if (g_private_storage[k].link_count == 0) {
            flink = &g_private_storage[k];
            break;
        }
    }

    if (flink == NULL) {
        tloge("Too many open files\n");
        return 0;
    }

    for (uint32_t i = 0; i < MAX_CLIENT_OPEN_FILES; i++) {
        if (client->file_instance[i].file_link != NULL)
            continue;

        client->file_instance[i].file_link               = flink;
        client->file_instance[i].seek_position           = 0;
        client->file_instance[i].file_link->sfd          = sfd;
        client->file_instance[i].file_link->link_count   = 1;
        client->file_instance[i].file_link->first_opened = true;
        /* check the first opened obj */
        for (uint32_t j = 0; j < MAX_PRIVATE_OPEN_FILES; j++) {
            if (k == j)
                continue;
            if (g_private_storage[j].link_count == 0)
                continue;

            temp = (sfd->meta_data->file_id_len == g_private_storage[j].sfd->meta_data->file_id_len) &&
                    (TEE_MemCompare(sfd->meta_data->file_id, g_private_storage[j].sfd->meta_data->file_id,
                                    sfd->meta_data->file_id_len) == 0) &&
                    (TEE_MemCompare(&g_private_storage[j].sfd->meta_data->uuid, &sfd->meta_data->uuid,
                                    sizeof(TEE_UUID)) == 0);
            if (temp) {
                client->file_instance[i].file_link->first_opened = false;
                break;
            }
        }
        return i + 1;
    }

    tloge("Too many open files\n");
    return 0;
}

/*
 * Close the file. If there are no more instances of this file
 * then internal file handle of file is closed.
 */
void close_file_from_client(uint32_t sender, uint32_t obj)
{
    tlogd("start\n");
    client_t *client = get_sender_client(sender);
    meta_data_t *meta = NULL;

    if (client == NULL) {
        tloge("Illegal client\n");
        return;
    }

    if ((obj == 0) || (obj > MAX_CLIENT_OPEN_FILES)) {
        tloge("illegal objID 0x%x\n", obj);
        return;
    }
    if (client->file_instance[obj - 1].file_link == NULL) {
        tloge("non-existing instance for object %u\n", obj);
        return;
    }

    tlogd("file %s\n", client->file_instance[obj - 1].file_link->sfd->meta_data->file_id);
    tlogd("link_count %d\n", client->file_instance[obj - 1].file_link->link_count);

    if (client->file_instance[obj - 1].file_link->link_count == 0)
        return;

    client->file_instance[obj - 1].file_link->link_count--;

    if (client->file_instance[obj - 1].file_link->link_count == 0) {
        tlogd("No more links to file, close it\n");

        meta = client->file_instance[obj - 1].file_link->sfd->meta_data;
        (void)ssa_close(client->file_instance[obj - 1].file_link->sfd);
        client->file_instance[obj - 1].file_link->sfd = 0;

        free_meta_data(&meta);
        /* filelink is not in use anymore, it can be free */
        client->file_instance[obj - 1].file_link->first_opened = false;
    } else {
        /* there is other instance(s) for this file, handler must not be closed. */
        tlogd("More links to file, Sync only\n");
        /* do sync() if obj has write access */
        if (client->file_instance[obj - 1].file_link->sfd->flags & TEE_DATA_FLAG_ACCESS_WRITE) {
            if (ssa_sync(client->file_instance[obj - 1].file_link->sfd) != TEE_SUCCESS)
                tlogd("ssa sync return error\n");
        }
    }

    tlogd("remove obj from 0x%x/%u\n", sender, obj);
    client->file_instance[obj - 1].file_link = 0;

    return;
}

static uint32_t get_file_handle(meta_data_t *meta, uint32_t sndr,
                                uint32_t flags, struct sfd_t **sfd, TEE_Result *error)
{
    uint32_t handle;

    if (error == NULL)
        return 0;

    if (sfd == NULL || meta == NULL) {
        *error = TEE_ERROR_BAD_PARAMETERS;
        return 0;
    }

    set_meta_data_verion(meta, SFS_ARCH_VERSION_SSA);
    *sfd = ssa_open(meta, flags, error);
    if (*error == TEE_SUCCESS) {
        tlogd("open success version C\n");
        handle = create_file_instance_to_client(sndr, *sfd);
        if (handle == 0) {
            (void)ssa_close(*sfd);
            *sfd   = NULL;
            *error = TEE_ERROR_STORAGE_EMFILE;
        }
        return handle;
    }

    return 0;
}

/*
 * try to open file.
 * First checks if file is already opened, if it is, use
 * existing secure file descriptor (SFD) and create new file instance that contains
 * existing SFD.
 * If file is not open, create a new SFD and file instance for it.
 *
 * This will allow that TA can open same object several times and all the opens
 * are always in sync.
 *
 * see TEE Internal Core API Specification - Public Review v1.2.0.1
 * Paragraph 5.8.1 TEE_OpenPersistentObject
 * ...
 * Multiple handles may be opened on the same object simultaneously, but sharing MUST
 * be explicitly allowed as described in section 5.8.3.
 */
uint32_t open_file(meta_data_t *meta, uint32_t sndr, uint32_t flags, struct sfd_t **sfd, TEE_Result *error)
{
    uint32_t handle;

    if (error == NULL)
        return 0;

    if (sfd == NULL || meta == NULL) {
        *error = TEE_ERROR_BAD_PARAMETERS;
        return 0;
    }

    file_link_t *flink = find_already_open(meta);
    if (flink != NULL && flink->sfd != NULL) {
        if (!check_shared_access(flink->sfd, flags)) {
            *error = TEE_ERROR_ACCESS_CONFLICT;
            return 0;
        }
    }

    handle = get_file_handle(meta, sndr, flags, sfd, error);
    return handle;
}

/*
 * Delete file from storage.
 * obj is an index of open files of TA.
 * TEE Internal Core API Specification - Public Review v1.2.0.1
 * 5.8.5 TEE_CloseAndDeletePersistentObject1
 * Deleting an object is atomic; once this function returns, the object is definitely deleted
 * and no more open handles for the object exist. This SHALL be the case even if the object or
 * the storage containing it have become corrupted
 */
TEE_Result delete_file(uint32_t sender, uint32_t obj)
{
    tlogd("start %u\n", obj);
    client_t *client = get_sender_client(sender);
    meta_data_t *meta = NULL;
    TEE_Result ret;

    if (client == NULL) {
        tloge("Illegal client for sender 0x%x\n", sender);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((obj == 0) || (obj > MAX_CLIENT_OPEN_FILES)) {
        tloge("illegal obj 0x%x\n", obj);
        return TEE_SUCCESS;
    }

    /* check that file link exist. */
    if ((client->file_instance[obj - 1].file_link) == NULL)
        return TEE_SUCCESS;

    tlogd("link count 0x%x/%u %d\n", sender, obj, client->file_instance[obj - 1].file_link->link_count);

    if ((client->file_instance[obj - 1].file_link->sfd) == NULL)
        return TEE_SUCCESS;

    meta = client->file_instance[obj - 1].file_link->sfd->meta_data;
    ret  = ssa_close_and_delete(client->file_instance[obj - 1].file_link->sfd, true);
    if (ret != TEE_SUCCESS)
        tloge("ssa_close_and_delete fail, ret %x\n", ret);

    client->file_instance[obj - 1].file_link->sfd = NULL;

    free_meta_data(&meta);

    if (client->file_instance[obj - 1].file_link->link_count) {
        client->file_instance[obj - 1].file_link->link_count--;
        /* file descriptor have to be released by each instances until it can  be reused */
        tlogd("there are still %d users of deleted file\n", client->file_instance[obj - 1].file_link->link_count);
    }
    client->file_instance[obj - 1].file_link = NULL;

    return ret;
}

struct ssa_caller_info_t {
    uint32_t sndr;
    uint32_t user_id;
};
struct ssa_caller_info_t g_caller_info = { 0 };
static TEE_Result set_ssa_caller_info(uint32_t sndr, uint32_t cmd)
{
    TEE_Result ret;

    if (g_permsrv_handle == 0) {
        if (ipc_hunt_by_name(PERMSRV_SAVE_FILE, &g_permsrv_handle) != 0)
            g_permsrv_handle = 0;
    }

    /* only unreg msg from globaltask need process. */
    if (sndr == g_global_handle && cmd != TEE_TASK_CLOSE_TA_SESSION && cmd != SS_AGENT_LOAD_MANAGE_INFO)
        return TEE_SUCCESS;

    ret = set_caller_info_proc(sndr, cmd);
    if (ret != TEE_SUCCESS)
        return ret;

    g_caller_info.sndr = sndr;

    if (g_permsrv_handle != 0 && sndr == g_permsrv_handle)
        g_caller_info.user_id = 0;
    else
        g_caller_info.user_id = get_sender_userid(sndr);

    return TEE_SUCCESS;
}

uint32_t get_ree_user_id(void)
{
    return g_caller_info.user_id;
}

int ssa_map_from_task(uint32_t in_task_id, uint64_t va_addr, uint32_t size, uint32_t out_task_id, uintptr_t *vm_addr)
{
    (void)out_task_id;
    uint64_t out_addr;
    int ret;

    /* It will definitely not be NULL, do we really need to check every param ? */
    if (vm_addr == NULL)
        return -1;

    ret = map_sharemem(in_task_id, va_addr, size, &out_addr);
    if (ret == 0) {
        *vm_addr = (uintptr_t)out_addr;
        if (*vm_addr == 0)
            return -1;
    } else {
        tloge("map initialData from %u fail\n", in_task_id);
        return ret;
    }

    return 0;
}
void ssa_unmap_from_task(uint32_t task_id, uintptr_t va_addr, uint32_t size, bool mapped)
{
    (void)task_id;
    if (mapped == false) {
        tlogd("ssa_unmap_from_task map is false");
        return;
    }

    (void)munmap((void *)va_addr, size);
}

static void ssa_write_attributes(const uint8_t *attributes, uint32_t attributes_len, struct sfd_t *sfd,
                                 uint32_t arch_version, TEE_Result *error)
{
    uint32_t ret;

    (void)arch_version;
    if (attributes == 0 || attributes_len == 0) {
        /* no need to write attributes, not error */
        *error = TEE_SUCCESS;
        return;
    }

    /* write attribute */
    ret = ssa_write(attributes, attributes_len, sfd, error);
    if ((ret != attributes_len) || (*error != TEE_SUCCESS)) {
        tloge("write attributes fail, error:0x%x", *error);
        *error = TEE_ERROR_GENERIC;
        return;
    }
    sfd->attr_size = attributes_len;

    *error = TEE_SUCCESS;
}

static void ssa_write_initial_data(const uint8_t *initial_data, uint32_t data_len, struct sfd_t *sfd,
                                   TEE_Result *error)
{
    uint32_t ret;

    if (initial_data == 0 || data_len == 0) {
        /* no need to write initial data, not error */
        *error = TEE_SUCCESS;
        return;
    }

    /* write initial data */
    ret = ssa_write(initial_data, data_len, sfd, error);
    if ((ret != data_len) || (*error != TEE_SUCCESS)) {
        tloge("write initialData fail, error:0x%x", *error);
        *error = TEE_ERROR_GENERIC;
        return;
    }

    *error = TEE_SUCCESS;
}

static TEE_Result create_permission_check(const meta_data_t *meta, uint32_t flags)
{
    /* check if file with same name already exist. Bad news, we can't use TEE_DATA_FLAG_OVERWRITE in GP v1.1 */
    bool check_obj_fail = (meta->cur_encrypted_file_id == NULL) || (((TEE_DATA_FLAG_EXCLUSIVE & flags) != 0) &&
        (ssa_fs_faccess((char *)meta->cur_encrypted_file_id, F_OK, meta->storage_id) == 0));
    if (check_obj_fail) {
        tloge("file exists: conflict to recreate\n");
        return TEE_ERROR_ACCESS_CONFLICT;
    }

    /* check file with same name is already open. it is have to be opened by same TA */
    file_link_t *flink = find_already_open(meta);
    if (flink != NULL) {
        bool check_fail = (flink->sfd == NULL) || (!check_shared_access(flink->sfd, flags));
        if (check_fail) {
            tloge("no access to recreate!\n");
            return TEE_ERROR_ACCESS_CONFLICT;
        }
    }

    return TEE_SUCCESS;
}

void create_object(const struct create_obj_msg_t *create_obj, uint32_t sndr, const TEE_UUID *uuid,
                   struct sfd_t **sfd, uint32_t *obj, TEE_Result *error)
{
    bool check_param_invalid = (create_obj == NULL) || (uuid == NULL) || (sfd == NULL) ||
        (error == NULL) || (create_obj->object_id == 0) || (obj == NULL);
    if (check_param_invalid)
        return;

    meta_data_t *meta = create_meta_data((uint8_t *)(uintptr_t)create_obj->object_id, create_obj->obj_id_len,
                                         create_obj->storage_id, create_obj->flags, uuid, error, g_arch_version);
    if (meta == NULL) {
        tloge("meta create fail\n");
        return;
    }

    TEE_Result ret = create_permission_check(meta, create_obj->flags);
    if (ret != TEE_SUCCESS) {
        *error = ret;
        goto clean1;
    }

    *sfd = ssa_create(meta, create_obj->flags, error);
    if ((*sfd == NULL) || (*error != TEE_SUCCESS)) {
        tloge("create fail\n");
        goto clean1;
    }

    ssa_write_attributes((uint8_t *)(uintptr_t)create_obj->attributes, create_obj->attributes_len, *sfd,
                         meta->arch_version, error);
    if (*error != TEE_SUCCESS) {
        goto clean2;
    }

    ssa_write_initial_data((uint8_t *)(uintptr_t)create_obj->initial_data, create_obj->data_len, *sfd, error);
    if (*error != TEE_SUCCESS) {
        goto clean2;
    }

    (*sfd)->need_update_hmac = false;

    *error = ssa_write_mac(*sfd);
    if (*error != TEE_SUCCESS) {
        tloge("write mac fail %x", *error);
        goto clean2;
    }

    *obj = create_file_instance_to_client(sndr, *sfd);
    if (*obj == 0) {
        *error = TEE_ERROR_GENERIC;
        goto clean2;
    }

    return;
clean2:
    (void)ssa_close_and_delete(*sfd, false);
clean1:
    free_meta_data(&meta);
}

TEE_Result copy_and_check_file_name(const char *obj_id_in, uint32_t in_len, char *obj_id, uint32_t obj_len)
{
    int32_t rc;
    TEE_Result ret;

    if (obj_id_in == NULL || obj_id == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (obj_len == 0 || obj_len - 1 < in_len)
        return TEE_ERROR_BAD_PARAMETERS;

    rc = memcpy_s(obj_id, obj_len - 1, obj_id_in, in_len);
    if (rc != EOK) {
        tloge("file name copy failed!");
        return TEE_ERROR_SECURITY;
    }
    obj_id[obj_len - 1] = '\0';

    ret = check_file_name(obj_id);
    if (ret != TEE_SUCCESS)
        tloge("file name is invalid!");

    return ret;
}

#define WEAK __attribute__((weak))

#define BSS_START_MAGIC 0x12345678
#define BSS_END_MAGIC   0x87654321
WEAK UINT32 TA_BSS_START = BSS_START_MAGIC;
WEAK UINT32 TA_BSS_END   = BSS_END_MAGIC;

typedef void (*func_ptr)(void);
extern func_ptr WEAK __init_array_start[];
extern func_ptr WEAK __init_array_end[];

void ssa_file_process_abort(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    uint32_t obj;

    if (rsp == NULL)
        return;

    if (msg == NULL) {
        tloge("invalid msg!\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    obj = msg->write_obj.obj_index;

    file_instance_t *fpointer = get_file_pointer(sndr, obj);
    bool check_ptr_null = (fpointer == NULL) || (fpointer->file_link == NULL) || (fpointer->file_link->sfd == NULL);
    if (check_ptr_null) {
        tloge("get session Fail\n");
        return;
    }

    fpointer->file_link->sfd->need_update_hmac = false;
    fpointer->file_link->sfd->update_backup    = false;
    return;
}

void ssa_register_agent(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    uint64_t fs_agent_buffer = 0;

    if (rsp == NULL)
        return;

    if (msg == NULL) {
        tloge("invalid msg!\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    if (g_is_ssa_reg == true) {
        tloge("only allow registration once!\n");
        return;
    }

    if (sndr != g_global_handle) {
        tloge("not send fromb global  %x\n", sndr);
        return;
    }
    if (msg->reg_agent.agentid == TEE_FS_AGENT_ID) {
        if (task_map_ns_phy_mem(g_ssagent_handle, (uint64_t)msg->reg_agent.phys_addr,
            msg->reg_agent.size, &fs_agent_buffer)) {
            tloge("map fs agent buffer fail\n");
        } else {
            tlogd("map fs agent buffer from %x to %lx, size=%u\n", msg->reg_agent.phys_addr, fs_agent_buffer,
                  msg->reg_agent.size);
            (void)tee_fs_init((void *)(uintptr_t)fs_agent_buffer);
            g_is_ssa_reg = true;
        }
    } else {
        tloge("no need to config agentid: 0x%x\n", msg->reg_agent.agentid);
    }
    return;
}

void ssa_register_uuid(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    (void)rsp;

    if (msg == NULL) {
        tloge("ssa_register_uuid invalid msg\n");
        return;
    }

    /* must get the permsrv handle, because the permsrv may restart. other place don't need. */
    if (ipc_hunt_by_name(PERMSRV_SAVE_FILE, &g_permsrv_handle) != 0)
        g_permsrv_handle = 0;

    if (sndr == g_global_handle || sndr == g_permsrv_handle) {
        tlogd("register task: %x-%x\n", msg->reg.taskid, msg->reg.uuid.timeLow);
        register_uuid(msg->reg.taskid, msg->reg.uuid, msg->reg.userid, msg->reg.ssa_enum_enable);
    }
}

static void ssa_unregister_uuid(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    (void)rsp;

    if (msg == NULL) {
        tloge("ssa_unregister_uuid invalid msg\n");
        return;
    }

    if (ipc_hunt_by_name(PERMSRV_SAVE_FILE, &g_permsrv_handle) != 0)
        g_permsrv_handle = 0;

    if (sndr == g_global_handle) {
        tlogd("unregister task: %x\n", msg->reg.taskid);

        unregister_uuid(msg->reg.taskid, NULL);
    } else if (sndr == g_permsrv_handle) {
        tlogd("unregister task: %x\n", msg->reg.taskid);
        unregister_uuid(msg->reg.taskid, PERMSRV_SAVE_FILE);
    }
}

/*
 *  TA's main entry
 */
ssa_cmd_t g_ssa_cmd_tbl[] = {
    /* ssa register msg */
    {TEE_TASK_REGISTER_AGENT,           0,     NOT_FILE_OPERATION, NOT_FILE_MODIFY,  ssa_register_agent},
    {TEE_TASK_OPEN_TA_SESSION,              0,     NOT_FILE_OPERATION, NOT_FILE_MODIFY,  ssa_register_uuid},
    {TEE_TASK_CLOSE_TA_SESSION,            0,     NOT_FILE_OPERATION, NOT_FILE_MODIFY,  ssa_unregister_uuid},

    /* file opertion , need ssa register done. */
    {SS_AGENT_CREATE_OBJECT,            1,     FILE_OPERATION,     NOT_FILE_MODIFY,  ssa_create_object},
    {SS_AGENT_OPEN_OBJECT,              1,     FILE_OPERATION,     NOT_FILE_MODIFY,  ssa_open_object},
    {SS_AGENT_READ_OBJECT,              1,     FILE_OPERATION,     NOT_FILE_MODIFY,  ssa_read_object},
    {SS_AGENT_WRITE_OBJECT,             1,     FILE_OPERATION,     FILE_MODIFY,      ssa_write_object},
    {SS_AGENT_SEEK_OBJECT,              1,     FILE_OPERATION,     FILE_MODIFY,      ssa_seek_object},
    {SS_AGENT_TRUNCATE_OBJECT,          1,     FILE_OPERATION,     FILE_MODIFY,      ssa_truncate_object},
    {SS_AGENT_RENAME_OBJECT,            1,     FILE_OPERATION,     FILE_MODIFY,      ssa_rename_object},
    {SS_AGENT_GET_OBJECT_INFO,          1,     FILE_OPERATION,     NOT_FILE_MODIFY,  ssa_info_object},
    {SS_AGENT_GET_OBJECT_ATTRIBUTES,    1,     FILE_OPERATION,     NOT_FILE_MODIFY,  ssa_get_object_attr},
    {SS_AGENT_CLOSE_OBJECT,             1,     FILE_OPERATION,     NOT_FILE_MODIFY,  ssa_close_object},
    {SS_AGENT_SYNC_OBJECT,              1,     FILE_OPERATION,     NOT_FILE_MODIFY,  ssa_sync_object},
    {SS_AGENT_CLOSE_AND_DELETE_OBJECT,  1,     FILE_OPERATION,     NOT_FILE_MODIFY,  ssa_close_and_delete_object},
    {SS_AGENT_FILE_ABORT,               1,     FILE_OPERATION,     NOT_FILE_MODIFY,  ssa_file_process_abort},
    {SS_AGENT_GET_ENUM_FILE_SIZE,       1,      FILE_OPERATION,    NOT_FILE_MODIFY,  ssa_get_enum_file_size},
    {SS_AGENT_START_ENUMERATOR,         1,      FILE_OPERATION,    NOT_FILE_MODIFY,  ssa_start_enumerator},
};

uint32_t g_ssa_cmd_num = sizeof(g_ssa_cmd_tbl) / sizeof(g_ssa_cmd_tbl[0]);

ssa_cmd_t *ssa_find_cmd(uint32_t cmd)
{
    uint32_t i;

    for (i = 0; i < g_ssa_cmd_num; i++) {
        if (cmd != g_ssa_cmd_tbl[i].cmd) {
            continue;
        }

        break;
    }

    if (i >= g_ssa_cmd_num) {
        tloge("ssa cmd not in tbl or cmd is file operation : %x\n", cmd);
        return NULL;
    }

    return &g_ssa_cmd_tbl[i];
}

void init_global_param(void)
{
    (void)memset_s(g_clients, sizeof(g_clients), 0, sizeof(g_clients));
    (void)memset_s((void *)g_private_storage, sizeof(g_private_storage), 0, sizeof(g_private_storage));
    (void)memset_s((void *)(&g_ssa_msg_queue), sizeof(g_ssa_msg_queue), 0xFF, sizeof(g_ssa_msg_queue));
    g_ssa_msg_queue.in  = 0;
    g_ssa_msg_queue.out = 0;
}

static void task_entry_init(int32_t init_build)
{
    (void)init_build;
    g_is_ssa_reg = false;

    init_global_param();
}

static void ssa_cmd_proc(uint32_t cmd, uint32_t sndr, union ssa_agent_msg *msg)
{
    bool need_ack = false;
    uint32_t i;
    struct ssa_agent_rsp rsp;
    uint32_t res_code;

    (void)memset_s((void *)(&rsp), sizeof(rsp), 0, sizeof(rsp));

    for (i = 0; i < g_ssa_cmd_num; i++) {
        if (cmd != g_ssa_cmd_tbl[i].cmd)
            continue;

        need_ack = g_ssa_cmd_tbl[i].need_ack;

        if (g_ssa_cmd_tbl[i].is_file_oper == FILE_OPERATION && !g_is_ssa_reg) {
            tloge("ssa object cmd 0x%x: ssa is not register\n", cmd);
            rsp.ret = TEE_ERROR_STORAGE_NOT_AVAILABLE;
        } else if (g_ssa_cmd_tbl[i].fn != NULL) {
            g_ssa_cmd_tbl[i].fn(msg, sndr, &rsp);
            if (g_ssa_cmd_tbl[i].is_file_modify == FILE_MODIFY && rsp.ret != TEE_SUCCESS) {
                tloge("ssa object cmd 0x%x: file is dirty, process abort\n", cmd);
                ssa_file_process_abort(msg, sndr, &rsp);
            }
        } else {
            tloge("no process func for cmd 0x%x, from 0x%x", cmd, sndr);
        }
        break;
    }

    if (i >= g_ssa_cmd_num) {
        tloge("ssa cmd not in tbl: 0x%x, from 0x%x\n", cmd, sndr);
        return;
    }

    if (!need_ack)
        return;

    res_code = (uint32_t)ipc_msg_snd(cmd, sndr, (void *)&rsp, sizeof(struct ssa_agent_rsp));
    if (res_code != 0)
        tloge("msg snd error 0x%x\n", res_code);
}

static uint32_t ssa_receive_msg(uint32_t uw_timeout, uint32_t *puw_msg_id, void *msgp,
                                uint16_t size, uint32_t *puw_sender_pid)
{
    (void)uw_timeout;
    return ssa_get_msg(puw_msg_id, msgp, size, puw_sender_pid);
}

void *ssa_handle_msg(void *arg)
{
    TEE_Result ret;
    uint32_t cmd = 0;
    uint32_t sndr = 0;
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;
    (void)arg;
    uint32_t global_taskid;

    ret = ipc_hunt_by_name(GLOBAL_SERVICE_NAME, &global_taskid);
    if (ret != TEE_SUCCESS) {
        tloge("hunt by gb name error 0x%x\n", ret);
        return NULL;
    }
    g_global_handle = taskid_to_pid(global_taskid);
    set_global_handle(g_global_handle);

    while (1) {
        ret = memset_s(&msg, sizeof(msg), 0, sizeof(msg));
        if (ret != TEE_SUCCESS)
            tlogw("memset msg fail\n");

        ret = memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));
        if (ret != TEE_SUCCESS)
            tlogw("memset rsp fail\n");

        ret = ssa_receive_msg(OS_WAIT_FOREVER, (uint32_t *)(&cmd),
                              (uint8_t *)&msg, sizeof(union ssa_agent_msg), &sndr);
        if (ret != TEE_SUCCESS) {
            tloge("get msg failed 0x%x\n", ret);
            continue;
        }

        tlogd("-- SS Agent cmd: 0x%x from 0x%x\n", cmd, sndr);

        ret = set_ssa_caller_info(sndr, cmd);
        if (ret != TEE_SUCCESS) {
            tloge("set_ssa_caller_info fail, ret:0x%x", ret);
            continue;
        }

        ssa_cmd_proc(cmd, sndr, &msg);
    }
    tloge("Must not be here, ssa is close\n");
}

__attribute__((visibility("default"))) void tee_task_entry(int32_t init_build)
{
    uint32_t res_code;

    task_entry_init(init_build);

    tlogd("global_handle = 0x%x\n", g_global_handle);

    res_code = ipc_hunt_by_name(SSA_SERVICE_NAME, &g_ssagent_handle);
    if (res_code != 0) {
        tloge("hunt by ssa error 0x%x\n", res_code);
        return;
    }
    tlogd("ssaHandle = 0x%x\n", g_ssagent_handle);
    ssa_handle_msg(NULL);
}
