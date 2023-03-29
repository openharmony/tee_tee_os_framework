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

#ifndef LIBTEEOS_DLIST_H
#define LIBTEEOS_DLIST_H

#include <stddef.h>
#include <stdbool.h>

#ifndef array_size
#define array_size(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define offset_of(type, member) (unsigned long)(&(((type *)0)->member))
#ifndef container_of
#define container_of(ptr, type, member) (type *)(((void *)(ptr)) - offset_of(type, member))
#endif

/*
 * The dlist node structure
 * representing the head node and the body nodes of the dlist
 */
struct dlist_node {
    struct dlist_node *prev;
    struct dlist_node *next;
};

#define dlist_head(name) struct dlist_node name = { &(name), &(name) }
#define dlist_head_init(name) { \
        .next = &(name),        \
        .prev = &(name),        \
    }

/*
 * Initialize the empty dlist
 * PRE: a dlist_node struct for the head node, with unspecified field values
 * POST: the field set to point to the head node itself, thus initialized to be an empty dlist
 */
static inline void dlist_init(struct dlist_node *head)
{
    head->prev = head;
    head->next = head;
}

/*
 * Check if the dlist is empty
 * PRE: head points to the head node of a well formed dlist
 * POST: return 1 if the dlist is empty, return 0 if it is not
 */
static inline bool dlist_empty(const struct dlist_node *head)
{
    /* dlist is well formed, so only needs check the next ptr here */
    return (head->next == head);
}

/*
 * Get the first node of a dlist
 * PRE: head points to the head node of a well formed dlist
 * POST: return the pointer to the first node of the dlist if it's not empty, or to the head node if it's empty
 */
static inline struct dlist_node *dlist_get_first(const struct dlist_node *head)
{
    return head->next;
}

/*
 * Get the last node of a dlist
 * PRE: head points to the head node of a well formed dlist
 * POST: return the pointer to the last node of the dlist if it's not empty, or to the head node if it's empty
 */
static inline struct dlist_node *dlist_get_last(const struct dlist_node *head)
{
    return head->prev;
}

/*
 * Insert after a given position of the dlist
 * PRE: pos points to a node(can be the head node) in a well formed dlist, node points to a node to be inserted(not in
 * the dlist) POST: node has been inserted into the dlist after pos, the new dlist is well formed
 */
static inline void dlist_insert(struct dlist_node *pos, struct dlist_node *node)
{
    struct dlist_node *tmp = NULL;

    tmp        = pos->next;
    tmp->prev  = node;
    node->prev = pos;
    node->next = pos->next;
    pos->next  = node;
}

/*
 * Insert a new node at head of a dlist
 * PRE: head points to the head node of a well formed dlist, node points to the node to be inserted(not in the dlist)
 * POST: the new node has been inserted to the head of the dlist, the new dlist is well formed
 */
static inline void dlist_insert_head(struct dlist_node *node, struct dlist_node *head)
{
    dlist_insert(head, node);
}

/*
 * Insert a new node at tail of a dlist
 * PRE: head points to the head node of a well formed dlist, node points to the node to be inserted(not in the dlist)
 * POST: the new node has been inserted to the tail of the dlist, the new dlist is well formed
 */
static inline void dlist_insert_tail(struct dlist_node *node, const struct dlist_node *head)
{
    struct dlist_node *tmp = NULL;

    tmp = dlist_get_last(head);
    dlist_insert(tmp, node);
}

/*
 * Delete a node from a dlist
 * PRE: node points to a node in a well formed dlist
 * POST: node has been taken out of the dlist, the remaining dlist is still well formed
 */
static inline void dlist_delete(struct dlist_node *node)
{
    struct dlist_node *tmp = NULL;

    tmp       = node->prev;
    tmp->next = node->next;
    tmp       = node->next;
    tmp->prev = node->prev;
    dlist_init(node);
}

/*
 * Replace an old node in the dlist with a new node
 * PRE: old node points to a node in the dlist, new node points a node not in the dlist, dlist well formed
 * POST: the new node has been inserted into the dlist, the old node has been taken out, the dlist is still well formed
 */
static inline void dlist_replace(const struct dlist_node *old_node, struct dlist_node *new_node)
{
    struct dlist_node *tmp = NULL;

    new_node->prev = old_node->prev;
    new_node->next = old_node->next;
    tmp            = old_node->prev;
    tmp->next      = new_node;
    tmp            = old_node->next;
    tmp->prev      = new_node;
}

/*
 * Get the prev node of a dlist node or a dlist head
 * PRE: node points to a dlist head or a dlist node of a well formed dlist
 * POST: return the pointer to the prev node of the dlist node or the dlist head
 */
static inline struct dlist_node *dlist_get_prev(const struct dlist_node *node)
{
    return node->prev;
}

/*
 * Get the next node of a dlist node or a dlist head
 * PRE: node points to a dlist head or a dlist node of a well formed dlist
 * POST: return the pointer to the next node of the dlist node or the dlist head
 */
static inline struct dlist_node *dlist_get_next(const struct dlist_node *node)
{
    return node->next;
}

/* get the address of the containing struct */
#define dlist_entry(ptr, type, member) container_of(ptr, type, member)

/* dlist_fisrt_entry */
#define dlist_first_entry(ptr, type, member) dlist_entry((ptr)->next, type, member)

/* dlist_last_entry */
#define dlist_last_entry(ptr, type, member) dlist_entry((ptr)->prev, type, member)

/* get the address of the next containing struct on the dlist */
#define dlist_next_entry(pos, type, member) dlist_entry((pos)->member.next, type, member)

/* get the address of the previous containing struct on the dlist */
#define dlist_prev_entry(pos, type, member) dlist_entry((pos)->member.prev, type, member)

/* dlist for each node entry */
#define dlist_for_each(pos, head) \
    for ((pos) = ((head)->next); \
         (pos) != (head); (pos) = ((pos)->next))

#define dlist_for_each_prev(pos, head) \
    for ((pos) = ((head)->prev);     \
         (pos) != (head); (pos) = ((pos)->prev))

#define dlist_for_each_safe(pos, n, head)             \
    for ((pos) = ((head)->next), (n) = ((pos)->next); \
         (pos) != (head);                                \
         (pos) = (n), (n) = ((pos)->next))

/* dlist for each struct entry */
#define dlist_for_each_entry(pos, head, type, member)                               \
    for ((pos) = dlist_first_entry(head, type, member); &((pos)->member) != (head); \
         pos = dlist_next_entry(pos, type, member))

#define dlist_for_each_entry_safe(pos, n, head, type, member)                                      \
    for ((pos) = dlist_first_entry(head, type, member), (n) = dlist_next_entry(pos, type, member); \
         (&(pos)->member != (head)); (pos) = (n), (n) = dlist_next_entry(n, type, member))

#endif