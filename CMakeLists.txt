cmake_minimum_required(VERSION 3.15)
project(wgcpp VERSION 1.0.0 LANGUAGES CXX)

add_library(wgcpp SHARED

    embeddable-wg-library/wireguard.c
    include/wginterface.h
    include/wgexception.h
    src/wgexception.cpp
    include/wgkey.h
    include/wgpresharedkey.h


    include/wgprivatekey.h

    include/wgpublickey.h

    include/wgpeer.h

    include/wgallowedip.h

    include/wgendpoint.h

    include/threadsafety.h
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