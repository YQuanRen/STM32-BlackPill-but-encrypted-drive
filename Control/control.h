#ifndef BP_CONTROL_H
#define BP_CONTROL_H
#include "journal.h"
#define BP_MAX_MESSAGE 256u
enum { BP_OK=0,BP_FORMAT=1,BP_STATE=2,BP_AUTH=3,BP_EXPIRED=4,BP_FAULT=5,BP_UNSUPPORTED=6,
       BP_IO=7,BP_HEADER=8,BP_BUSY=9 };
typedef int (*bp_authorize_fn)(void *,unsigned,const uint8_t *);
typedef struct {
    bp_journal *journal;
    bp_authorize_fn authorize;
    int (*storage)(void *,unsigned,const uint8_t *,size_t,uint8_t *,size_t *);
    void (*clear_user)(void *);
    void *user;
    uint64_t challenge_counter,rx,tx;
    uint32_t started,activity;
    uint8_t transcript[137],in_key[32],out_key[32]; /* T || D || H */
    unsigned operation;
    int pending,session,media;
} bp_control;
void bp_control_init(bp_control *,bp_journal *,bp_authorize_fn,void *);
/* Reset keeps the RAM freshness counter; suspend must not call this. */
void bp_control_reset(bp_control *);
void bp_control_tick(bp_control *,uint32_t);
size_t bp_control_request(bp_control *,const uint8_t *,size_t,uint8_t[256],uint32_t);
#endif
