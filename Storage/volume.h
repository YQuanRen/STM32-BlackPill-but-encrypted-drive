#ifndef BP_VOLUME_H
#define BP_VOLUME_H
#include "control.h"
#include "adiantum.h"
typedef struct {
    void *user;
    int (*describe)(void *,uint8_t[16],uint32_t *);
    int (*read)(void *,uint32_t,uint8_t[512]);
    int (*write)(void *,uint32_t,const uint8_t[512]);
} bp_disk;
typedef struct {
    bp_disk io;
    bp_journal *journal;
    adiantum_ctx cipher;
    uint8_t header[256],stage[288],scratch[512],verify[512];
    unsigned staged,state,mode;
    uint32_t physical,done;
    int unlocked;
} bp_volume;
void bp_volume_init(bp_volume *,bp_journal *,const bp_disk *);
void bp_volume_reset(bp_volume *);
int bp_volume_load(bp_volume *);
int bp_volume_authorize(void *,unsigned,const uint8_t *);
int bp_volume_command(void *,unsigned,const uint8_t *,size_t,uint8_t *,size_t *);
void bp_volume_step(bp_volume *);
int bp_volume_read(bp_volume *,uint32_t,uint8_t *,uint32_t);
int bp_volume_write(bp_volume *,uint32_t,const uint8_t *,uint32_t);
int bp_volume_ready(bp_volume *);
#endif
