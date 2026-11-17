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
/* Anti-forensic crypto-erase. Overwrites both on-card header copies (physical
 * sectors 0..15), destroying both wrapped-data-key copies, THEN wipes the
 * credential journal. For an encrypted (mode 2) volume this renders the data
 * permanently unrecoverable even with the correct file and password, because the
 * random data key existed only inside the now-destroyed wrapped-key field. For a
 * plaintext (mode 1) volume it removes the volume binding and credentials but does
 * NOT erase the data region; use the full secure-erase setup for that. Header
 * writes are verified and happen first, so an SD failure (BP_IO) leaves the
 * credential journal intact for a retry. */
int bp_volume_destroy(bp_volume *);
#endif
