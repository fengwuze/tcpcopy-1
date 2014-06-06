
#include <xcopy.h>

p_link_node
link_node_malloc(tc_pool_t *pool, void *data)
{
    p_link_node p;

    if (!pool->loop) {
        p = (p_link_node) tc_pcalloc(pool, sizeof(link_node));
    } else {
        p = (p_link_node) tc_palloc_loop(pool, sizeof(link_node));
        tc_memzero(p, sizeof(link_node));
    }

    if (p != NULL) {
        p->data = data;
    }

    return p;
}


link_list *
link_list_create(tc_pool_t *pool)
{
    link_list *l = (link_list *) tc_pcalloc(pool, sizeof(link_list));

    if (l != NULL) {
        l->size      = 0;
        l->head.next = &(l->head);
        l->head.prev = &(l->head);
    }

    return l;
}


int
link_list_clear(tc_pool_t *pool, link_list *l)
{
    int         count = 0;
    p_link_node p, next;

    p = l->head.next;
    while (p != &(l->head)) {
        next = p->next;
        count++;
        tc_pfree(pool, p);
        p = next;
    }   

    l->head.next = &(l->head);
    l->head.prev = &(l->head);
    l->size = 0;

    return count;

}


void
link_list_append_by_order(link_list *l, p_link_node p)
{
    p_link_node node, next;

    if (l->size > 0) {
        node = l->head.prev;
        next = node->next;
        while (node->data != NULL && after(node->key, p->key)) {
            next = node;
            node = node->prev;
        }
        node->next   = p;
        p->prev      = node;
        next->prev   = p;
        p->next      = next;
        l->size++;
    } else {
        link_list_append(l, p);
    }
}


