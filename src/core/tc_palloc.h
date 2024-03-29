#ifndef _TC_PALLOC_H_INCLUDED_
#define _TC_PALLOC_H_INCLUDED_


#include <xcopy.h>

#define MEM_HID_INFO_SZ sizeof(tc_mem_hid_info_t)
typedef struct tc_pool_large_s  tc_pool_large_t;
typedef struct tc_pool_loop_s  tc_pool_loop_t;

struct tc_pool_large_s {
    tc_pool_large_t     *next;
    void                *alloc;
};

typedef struct {
    uint32_t len:18;
    uint32_t large:1;
    uint32_t released:1;
} tc_mem_hid_info_t;

typedef struct {
    u_char              *last;
    u_char              *end;
    tc_pool_t           *next;
    uint32_t             objs:16;
    uint32_t             failed:8;
    uint32_t             need_check:1;
    uint32_t             cand_check:1;
} tc_pool_data_t;


struct tc_pool_s {
    tc_pool_data_t         d;
    union {
        int max;
        int fn;
    };
    union {
        tc_pool_t         *current;
        time_t            last_check_time;
    };
    union {
        tc_mem_hid_info_t *fp;
        tc_pool_large_t   *large;
    };
};


void *tc_alloc(size_t size);
void *tc_calloc(size_t size);

tc_pool_t *tc_create_pool(size_t size, size_t pool_max);
void tc_destroy_pool(tc_pool_t *pool);

void *tc_palloc(tc_pool_t *pool, size_t size);
void *tc_pcalloc(tc_pool_t *pool, size_t size);
void *tc_pmemalign(tc_pool_t *pool, size_t size, size_t alignment);
tc_int_t tc_pfree(tc_pool_t *pool, void *p);



#endif /* _TC_PALLOC_H_INCLUDED_ */
