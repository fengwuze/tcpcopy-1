
#include <xcopy.h>

static void *tc_palloc_block(tc_pool_t *pool, size_t size);
static void *tc_palloc_large(tc_pool_t *pool, size_t size);


tc_pool_t *
tc_create_pool(size_t size, size_t pool_max)
{
    tc_pool_t  *p;

    if (size < TC_MIN_POOL_SIZE) {
        tc_log_info(LOG_ERR, 0, "pool size must be no less than:%uz", 
                TC_MIN_POOL_SIZE);
        size = TC_MIN_POOL_SIZE;
    }

    p = tc_memalign(TC_POOL_ALIGNMENT, size);
    if (p != NULL) {
        p->d.last = (u_char *) p + sizeof(tc_pool_t);
        p->d.end  = (u_char *) p + size;
        p->d.next = NULL;
        p->d.failed = 0;
        p->d.objs   = 0;
        p->d.cand_check = 0;
        p->d.need_check = 0;

        size = size - sizeof(tc_pool_t);
        
        if (pool_max && size >= pool_max) {
            p->max = pool_max;
        } else {
            p->max = (size < TC_MAX_ALLOC_FROM_POOL) ? 
                size : TC_MAX_ALLOC_FROM_POOL;
        }

        p->current = p;
        p->large = NULL;
    }
    
    return p;
}


void
tc_destroy_pool(tc_pool_t *pool)
{
    tc_pool_t          *p, *n;
    tc_pool_large_t    *l;

    for (l = pool->large; l; l = l->next) {

        if (l->alloc) {
            tc_free(l->alloc);
        }
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        tc_free(p);

        if (n == NULL) {
            break;
        }
    }
}


void *
tc_palloc(tc_pool_t *pool, size_t size)
{
    u_char            *m;
    tc_pool_t         *p;
    tc_mem_hid_info_t *hid;

    size = size + MEM_HID_INFO_SZ;

    if (size <= pool->max) {

        p = pool->current;

        do {
            m = tc_align_ptr(p->d.last, TC_ALIGNMENT);

            if ((size_t) (p->d.end - m) >= size) {
                p->d.objs++;
                p->d.last = m + size;
                hid = (tc_mem_hid_info_t *) m;
                hid->large = 0;
                hid->len = size;
                hid->released = 0;

                return m + MEM_HID_INFO_SZ;
            }

            p = p->d.next;

        } while (p);

        m = tc_palloc_block(pool, size);
        if (m != NULL) {
            hid = (tc_mem_hid_info_t *) m;
            hid->large = 0;
            hid->len = size;
            hid->released = 0;
            return m + MEM_HID_INFO_SZ;
        } else {
            return NULL;
        }
    }

    m = tc_palloc_large(pool, size);
    if (m != NULL) {
        hid = (tc_mem_hid_info_t *) m;
        hid->large = 1;
        hid->len = size;
        hid->released = 0;
        return m + MEM_HID_INFO_SZ;
    } else {
        return NULL;
    }
}


static bool tc_check_block_free(tc_pool_t *p)
{
    int                i;
    u_char            *m;
    tc_mem_hid_info_t *hid;

    if (p->fp) {
        m = (u_char *) p->fp;
        i = p->fn;
    } else {
        m = ((u_char *) p) + sizeof(tc_pool_t);
        m = tc_align_ptr(m, TC_ALIGNMENT);
        i = 0;
    }

    while (m < p->d.end) {
        hid = (tc_mem_hid_info_t *) m;
        if (!hid->released) {
            p->fp = hid;
            p->fn = i;
            tc_log_info(LOG_INFO, 0, "block check:%llu, index:%d not released", p, i);
            return false;
        }
        m += hid->len;
        m = tc_align_ptr(m, TC_ALIGNMENT);
        i++;

        if (i == p->d.objs) {
            break;
        }
    }

    return true;
}


static void *
tc_palloc_block(tc_pool_t *pool, size_t size)
{
    bool        reused;
    u_char     *m;
    size_t      psize;
    tc_pool_t  *p, *prev, *new, *current;

    p    = pool->d.next;
    prev = pool;

    reused = false;

    for (; p; p = p->d.next) {
        if (p->d.cand_check) {
            tc_log_info(LOG_INFO, 0, "main pool:%llu,tc_check_block_free:%llu", pool, p);
            if (tc_check_block_free(p)) {
                tc_log_info(LOG_INFO, 0, "main pool:%llu,block reused:%llu", pool, p);
                reused =true;
                m = (u_char *) p;
                new = p;
                prev->d.next = p->d.next;
                break;
            }
        }

        prev = p;
    }

    if (!reused) {
        psize = (size_t) (pool->d.end - (u_char *) pool);
        m = tc_memalign(TC_POOL_ALIGNMENT, psize);

        if (m == NULL) {
            return NULL;
        }
        new = (tc_pool_t *) m;
        new->d.end  = m + psize;
    }

    new->d.next = NULL;
    new->d.failed = 0;
    new->d.objs = 1;
    new->d.cand_check = 0;
    new->d.need_check = 1;
    new->fp = NULL;
    new->fn = 0;

    m += sizeof(tc_pool_t);
    m = tc_align_ptr(m, TC_ALIGNMENT);
    new->d.last = m + size;


    current = pool->current;

    for (p = current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) {
            if (p->d.need_check) {
                tc_log_info(LOG_INFO, 0, "set cand check:%llu", p);
                p->d.cand_check = 1;
            }
            current = p->d.next;
        }
    }

    p->d.next = new;

    pool->current = current ? current : new;

    return m;
}


static void *
tc_palloc_large(tc_pool_t *pool, size_t size)
{
    void              *p;
    tc_uint_t          n;
    tc_pool_large_t   *large;

    p = tc_alloc(size);
    if (p != NULL) {

        n = 0;

        for (large = pool->large; large; large = large->next) {
            if (large->alloc == NULL) {
                large->alloc = p;
                return p;
            }

            if (n++ > 3) {
                break;
            }
        }

        large = tc_palloc(pool, sizeof(tc_pool_large_t));
        if (large == NULL) {
            tc_free(p);
            return NULL;
        }

        large->alloc = p;
        large->next = pool->large;
        pool->large = large;
    }

    return p;
}


void *
tc_pmemalign(tc_pool_t *pool, size_t size, size_t alignment)
{
    void             *p;
    tc_pool_large_t  *large;

    p = tc_memalign(alignment, size);
    if (p != NULL) {

        large = tc_palloc(pool, sizeof(tc_pool_large_t));
        if (large == NULL) {
            tc_free(p);
            return NULL;
        }

        large->alloc = p;
        large->next = pool->large;
        pool->large = large;
    }

    return p;
}


tc_int_t
tc_pfree(tc_pool_t *pool, void *p)
{
    tc_pool_large_t   *l;
    tc_mem_hid_info_t *act_p;
    
    act_p = (tc_mem_hid_info_t *) ((unsigned char *) p - MEM_HID_INFO_SZ);

    if (act_p->large) {
        for (l = pool->large; l; l = l->next) {
            if (act_p == l->alloc) {
                tc_free(l->alloc);
                l->alloc = NULL;

                return TC_OK;
            }
        }
    } else {
        act_p->released = 1;
    }

    return TC_DELAYED;
}



void *
tc_pcalloc(tc_pool_t *pool, size_t size)
{
    void *p;

    p = tc_palloc(pool, size);
    if (p) {
        tc_memzero(p, size);
    }

    return p;
}


