cmake_minimum_required(VERSION 3.15)
project(wgcpp VERSION 1.0.0 LANGUAGES CXX)

add_library(wgcpp SHARED
    src/wginterface.cpp
    embeddable-wg-library/wireguard.c
    include/wginterface.h
    include/wgexception.h
    src/wgexception.cpp
    include/wgkey.h
    include/wgpresharedkey.h
    src/wgkey.cpp
    src/wgpresharedkey.cpp
    include/wgprivatekey.h
    src/wgprivatekey.cpp
    include/wgpublickey.h
    src/wgpublickey.cpp
    include/wgpeer.h
    src/wgpeer.cpp
    include/wgallowedip.h
    src/wgallowedip.cpp
    examples/example1.cpp
    include/wgendpoint.h
    src/wgendpoint.cpp
    examples/example2.cpp
)

target_include_directories(wgcpp
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/embeddable-wg-library
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

install(TARGETS wgcpp
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/ DESTINATION include)