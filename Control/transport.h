#ifndef BP_TRANSPORT_H
#define BP_TRANSPORT_H
#include "control.h"
typedef struct {
    uint8_t input[256],output[256];
    unsigned total,offset,id,out_total,out_offset,out_id;
    uint32_t started;
    int ready,processing;
} bp_transport;
/* Caller serializes these short copies against USB callbacks. */
void bp_transport_reset(bp_transport *);
int bp_transport_receive(bp_transport *,const uint8_t *,size_t,uint32_t);
size_t bp_transport_take(bp_transport *,uint8_t[256],unsigned *,uint32_t);
void bp_transport_publish(bp_transport *,const uint8_t *,size_t,unsigned);
void bp_transport_get(bp_transport *,uint8_t[64]);
#endif
