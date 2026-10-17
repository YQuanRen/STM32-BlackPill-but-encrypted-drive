add_library(bp_control STATIC crypto.c journal.c control.c transport.c
    ../Crypto/bearssl/src/hash/sha2small.c
    ../Crypto/bearssl/src/mac/hmac.c
    ../Crypto/bearssl/src/kdf/hkdf.c
    ../Crypto/bearssl/src/aead/gcm.c
    ../Crypto/bearssl/src/symcipher/aes_ct_ctr.c
    ../Crypto/bearssl/src/hash/ghash_ctmul32.c
    ../Crypto/bearssl/src/codec/dec32be.c
    ../Crypto/bearssl/src/codec/enc32be.c
    ../Crypto/bearssl/src/codec/enc64be.c)
target_include_directories(bp_control PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ../Crypto/bearssl/inc ../Crypto/bearssl/src)
target_link_libraries(bp_control PUBLIC adiantum)
target_compile_features(bp_control PUBLIC c_std_11)
