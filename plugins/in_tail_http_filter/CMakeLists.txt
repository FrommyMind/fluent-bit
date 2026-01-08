cmake_minimum_required(VERSION 3.11)

set(src tail_http_filter.c)

FLB_PLUGIN(in_tail_http_filter "${src}" "")

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../in_tail
)