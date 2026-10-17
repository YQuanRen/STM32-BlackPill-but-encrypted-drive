add_library(adiantum STATIC
    adiantum.c
    vendor/chacha.c vendor/nh.c vendor/poly1305.c
    vendor/aes_ct.c vendor/aes_ct_enc.c vendor/aes_ct_dec.c)
target_include_directories(adiantum PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(adiantum PUBLIC c_std_11)
