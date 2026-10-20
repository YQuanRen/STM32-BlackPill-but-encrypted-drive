add_library(bp_storage STATIC volume.c)
target_include_directories(bp_storage PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bp_storage PUBLIC bp_control)
