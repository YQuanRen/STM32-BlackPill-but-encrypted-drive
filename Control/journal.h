#ifndef BP_JOURNAL_H
#define BP_JOURNAL_H
#include "crypto.h"
#define BP_BANK_SIZE 131072u
#define BP_RECORD_SIZE 128u
typedef struct {
    void *user;
    int (*read)(void *,unsigned,size_t,void *,size_t);
    int (*program)(void *,unsigned,size_t,const void *,size_t);
    int (*erase)(void *,unsigned);
} bp_flash;
typedef struct {
    bp_flash io;
    uint8_t identity[16],auth[32],volume[16];
    uint64_t epoch;
    unsigned mode, bank, next;
    int state; /* 0 virgin, 1 provisioned, 2 fault */
} bp_journal;
int bp_journal_boot(bp_journal *,const bp_flash *,const uint8_t[16]);
int bp_journal_enroll(bp_journal *,unsigned,const uint8_t[32]);
/* Called only by authenticated destructive setup after validating its proposal. */
int bp_journal_bind(bp_journal *,unsigned,const uint8_t[16]);
#endif
