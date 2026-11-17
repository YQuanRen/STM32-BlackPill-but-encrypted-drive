/* Anti-forensic crypto-erase (DESTROY) firmware logic test.
 *
 * Builds against the in-tree journal/volume/control layers and the real BearSSL
 * primitives, so it exercises the actual firmware code paths (not a mock). It does
 * NOT run on hardware: it validates logic, not SD/flash power-loss behaviour.
 *
 * Two scenarios:
 *   A. Direct unit erase  - bp_volume_destroy() on a loaded encrypted volume.
 *   B. Full protocol erase - BEGIN(operation 3) / PROVE / SECURE(opcode 8) driven
 *      with a minimal in-test host client using the same crypto primitives.
 *
 * Build/run: see tests/antiforensic/run.sh
 */
#include "volume.h"
#include "control.h"
#include "journal.h"
#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ---- backing store (mirrors tests/storage/simulator.c, kept local so the test
 *      owns the destroy wiring and can inspect the disk) ---- */
#define SECTORS 64
static uint8_t flash[2][BP_BANK_SIZE], disk[SECTORS][512];
static uint8_t cid[16];
static bp_journal j;
static bp_volume v;
static bp_control c;
static uint32_t now;

static int fr(void *u, unsigned b, size_t o, void *p, size_t n){ (void)u; memcpy(p, flash[b]+o, n); return 1; }
static int fp(void *u, unsigned b, size_t o, const void *p, size_t n){
    (void)u; const uint8_t *s=p; for(size_t i=0;i<n;i++) flash[b][o+i]&=s[i]; return 1;
}
static int fe(void *u, unsigned b){ (void)u; memset(flash[b], 255, BP_BANK_SIZE); return 1; }
static int describe(void *u, uint8_t *p, uint32_t *n){ (void)u; memcpy(p, cid, 16); *n=SECTORS; return 1; }
static int sd_fail;
static int dr(void *u, uint32_t a, uint8_t *p){ (void)u; if(a>=SECTORS) return 0; memcpy(p, disk[a], 512); return 1; }
static int dw(void *u, uint32_t a, const uint8_t *p){ (void)u; if(sd_fail||a>=SECTORS) return 0; memcpy(disk[a], p, 512); return 1; }
static void clear(void *u){ bp_volume_reset(u); }
static int destroy(void *u){ return bp_volume_destroy(u); }

static int fails;
static void check(int cond, const char *msg){
    printf("  [%s] %s\n", cond?"PASS":"FAIL", msg);
    if(!cond) fails++;
}

static void boot(void){
    memset(flash, 255, sizeof(flash));
    memset(disk, 0xa5, sizeof(disk));
    memset(cid, 0x31, 16);
    sd_fail = 0;
    now = 0;
    bp_flash f = {0, fr, fp, fe};
    bp_disk d = {0, describe, dr, dw};
    bp_journal_boot(&j, &f, (const uint8_t[16]){1,2,3,4,5,6,7,8,9,10,11,12,0,0,0,0});
    bp_volume_init(&v, &j, &d);
    bp_control_init(&c, &j, bp_volume_authorize, &v);
    c.storage = bp_volume_command;
    c.clear_user = clear;
    c.destroy = destroy;
}

/* Build a ready (state 2) encrypted (mode 2) header for this card. The firmware
 * only validates the fixed KDF params and the data-key-check HMAC, not the Argon2
 * wrap itself, so a deterministic test key is sufficient. */
static void build_header(uint8_t h[256], const uint8_t auth[32], const uint8_t datakey[32],
                         const uint8_t volume_id[16], unsigned state){
    uint8_t a[124], kc[32];
    memset(h, 0, 256);
    memcpy(h, "BPVOL001", 8);
    bp_put(h+8, 2, 4);              /* version 2 */
    bp_put(h+12, state, 4);         /* 1 initializing, 2 ready */
    memcpy(h+16, j.identity, 16);
    memcpy(h+32, volume_id, 16);
    memcpy(h+48, cid, 16);
    bp_put(h+64, SECTORS, 8);
    bp_put(h+72, SECTORS-16, 8);
    bp_put(h+80, 2, 4);             /* mode 2 */
    bp_put(h+84, 512, 4);
    bp_put(h+88, 65536, 4); bp_put(h+92, 3, 4); bp_put(h+96, 1, 4);
    memset(h+100, 0x5a, 16);        /* salt   (opaque to firmware) */
    memset(h+116, 0x3c, 12);        /* nonce  (opaque to firmware) */
    memset(h+128, 0x77, 48);        /* wrapped key (opaque to firmware) */
    memcpy(a, h, 12); memcpy(a+12, h+16, 112);           /* AAD = h[0:12]||h[16:128] */
    bp_mac(datakey, "BP1/data-check", a, 124, kc);
    memcpy(h+176, kc, 32);
    bp_mac(auth, "BP1/header", h, 224, h+224);
}

static void write_headers(const uint8_t h[256]){
    for(unsigned i=0;i<16;i++){
        memset(disk[i], 0, 512);
        if(i%8==0) memcpy(disk[i], h, 256);
    }
}

static int headers_zeroed(void){
    for(unsigned i=0;i<16;i++)
        for(unsigned k=0;k<512;k++)
            if(disk[i][k]) return 0;
    return 1;
}

/* ---------- Scenario A: direct unit erase ---------- */
static void scenario_a(void){
    printf("Scenario A: direct bp_volume_destroy on a loaded encrypted volume\n");
    boot();
    uint8_t auth[32], datakey[32], vid[16];
    memset(auth, 0xA1, 32); memset(datakey, 0xD2, 32);
    for(unsigned i=0;i<16;i++) vid[i]=(uint8_t)(i+1);

    check(bp_journal_enroll(&j, 2, auth)==1, "enroll mode 2");
    check(bp_journal_bind(&j, 2, vid)==1, "bind volume id");

    uint8_t h[256];
    build_header(h, auth, datakey, vid, 2);
    write_headers(h);

    check(bp_volume_load(&v)==BP_OK, "valid encrypted volume loads before erase");

    int rc = bp_volume_destroy(&v);
    check(rc==BP_OK, "bp_volume_destroy returns OK");
    check(headers_zeroed(), "both header copies (sectors 0..15) are zeroed");

    /* Re-boot the journal from the (now erased) flash: it must read back virgin. */
    bp_flash f = {0, fr, fp, fe};
    bp_journal_boot(&j, &f, j.identity);
    check(j.state==0, "credential journal reads back virgin (state 0)");

    bp_volume_init(&v, &j, (const bp_disk[]){{0, describe, dr, dw}});
    check(bp_volume_load(&v)==BP_STATE, "volume no longer loads after credential wipe");
}

/* ---------- Scenario B: full authenticated protocol erase ---------- */
static uint32_t rid = 0x11223344;
static uint64_t htx, hrx;

static size_t req(uint8_t cmd, const uint8_t *payload, size_t n, uint8_t *out){
    uint8_t in[256];
    in[0]=1; in[1]=cmd; bp_put(in+2, rid, 4); bp_put(in+6, n, 2);
    if(n) memcpy(in+8, payload, n);
    return bp_control_request(&c, in, n+8, out, now);
}

static void scenario_b(void){
    printf("Scenario B: full BEGIN(op3)/PROVE/SECURE(DESTROY) protocol path\n");
    boot();
    uint8_t auth[32];
    memset(auth, 0x5e, 32);
    uint8_t epayload[49];
    memcpy(epayload, j.identity, 16); epayload[16]=2; memcpy(epayload+17, auth, 32);
    uint8_t out[256];
    check(req(2, epayload, 49, out)>0 && out[8]==BP_OK, "protocol enrollment succeeds");

    /* Leave non-zero bytes in the header sectors so the erase is observable. */
    for(unsigned i=0;i<16;i++) memset(disk[i], 0x99, 512);

    /* BEGIN, operation 3 (destroy). */
    uint8_t nonce[32]; for(unsigned i=0;i<32;i++) nonce[i]=(uint8_t)(0x40+i);
    uint8_t begin[33]; begin[0]=3; memcpy(begin+1, nonce, 32);
    size_t rn = req(3, begin, 33, out);
    check(rn>0 && out[8]==BP_OK, "BEGIN accepts operation 3 (destroy)");
    const uint8_t *bresp = out+9;   /* epoch(8) || counter(8) || D(32) */

    /* Rebuild transcript T exactly as the device did. */
    uint8_t T[73];
    memcpy(T, "BP1", 3); memcpy(T+3, j.identity, 16); T[19]=(uint8_t)j.mode; T[20]=3;
    memcpy(T+21, bresp, 16);        /* epoch || counter */
    memcpy(T+37, nonce, 32);
    bp_put(T+69, rid, 4);
    uint8_t D[32]; bp_mac(auth, "BP1/challenge", T, 73, D);
    check(bp_equal(D, bresp+16, 32), "device challenge D verifies");

    uint8_t TD[105]; memcpy(TD, T, 73); memcpy(TD+73, D, 32);
    uint8_t H[32]; bp_mac(auth, "BP1/host", TD, 105, H);

    /* PROVE. */
    rn = req(4, H, 32, out);
    check(rn>0 && out[8]==BP_OK, "PROVE confirms the session");
    uint8_t TDH[137]; memcpy(TDH, TD, 105); memcpy(TDH+105, H, 32);
    uint8_t devconf[32]; bp_mac(auth, "BP1/device", TDH, 137, devconf);
    check(bp_equal(devconf, out+9, 32), "device confirmation verifies");

    /* Derive directional session keys. */
    uint8_t salt[32], send_key[32], recv_key[32];
    bp_sha(TDH, 137, salt);
    bp_kdf(salt, 32, auth, 32, "BP1/host-to-device", 18, send_key, 32);
    bp_kdf(salt, 32, auth, 32, "BP1/device-to-host", 18, recv_key, 32);
    htx = hrx = 0;

    /* SECURE: protected opcode 8 (DESTROY), plaintext body = {0x08}. */
    uint8_t body[256]; size_t off=0;
    body[0]=1; body[1]=5; bp_put(body+2, ++rid, 4);
    uint8_t plain[1] = {8};
    uint8_t ct[1]; memcpy(ct, plain, 1);
    uint8_t ctr[8]; bp_put(ctr, htx, 8);
    bp_put(body+6, 1+24, 2);                 /* payload len = ct(1)+counter(8)+tag(16) */
    memcpy(body+8, ctr, 8);
    uint8_t nonce12[12]={0}; memcpy(nonce12+4, ctr, 8);
    uint8_t tag[16];
    bp_gcm(send_key, nonce12, body, 16, ct, 1, tag, 0);  /* aad = outer8||counter8 */
    memcpy(body+16, ct, 1); memcpy(body+17, tag, 16);
    off = 8+1+8+16;                           /* 33 */
    (void)off;
    rn = bp_control_request(&c, body, 33, out, now);
    check(rn>0, "SECURE(DESTROY) produced a response");

    /* Decrypt the response status. */
    uint8_t rctr[8]; memcpy(rctr, out+8, 8);
    uint8_t rnonce[12]={0}; memcpy(rnonce+4, rctr, 8);
    uint8_t status_ct[1]; memcpy(status_ct, out+16, 1);
    uint8_t rtag[16]; memcpy(rtag, out+17, 16);
    int ok = bp_gcm(recv_key, rnonce, out, 16, status_ct, 1, rtag, 1);
    check(ok, "protected response authenticates");
    check(ok && status_ct[0]==BP_OK, "DESTROY status is OK");

    check(headers_zeroed(), "header sectors zeroed via protocol path");

    uint8_t info[256];
    check(req(1, NULL, 0, info)>0 && info[8]==BP_OK && info[9+16]==0,
          "INFO reports virgin (state 0) after destroy");
}

/* ---------- Scenario C: fail-safe ordering on SD error ---------- */
static void scenario_c(void){
    printf("Scenario C: SD write failure must not wipe credentials (retryable)\n");
    boot();
    uint8_t auth[32], datakey[32], vid[16];
    memset(auth, 0xA1, 32); memset(datakey, 0xD2, 32);
    for(unsigned i=0;i<16;i++) vid[i]=(uint8_t)(i+1);
    bp_journal_enroll(&j, 2, auth);
    bp_journal_bind(&j, 2, vid);
    uint8_t h[256]; build_header(h, auth, datakey, vid, 2); write_headers(h);

    sd_fail = 1;
    int rc = bp_volume_destroy(&v);
    check(rc==BP_IO, "destroy reports BP_IO when the header cannot be overwritten");
    check(j.state==1, "credential journal stays provisioned after an SD failure");

    /* With the card healthy again, destroy must now complete. */
    sd_fail = 0;
    check(bp_volume_destroy(&v)==BP_OK, "retry after SD recovers completes the erase");
    check(headers_zeroed() && j.state==0, "headers zeroed and journal virgin on retry");
}

int main(void){
    scenario_a();
    scenario_b();
    scenario_c();
    printf(fails? "\nRESULT: %d check(s) FAILED\n" : "\nRESULT: all checks passed\n", fails);
    return fails? 1 : 0;
}
