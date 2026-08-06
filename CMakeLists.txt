cmake_minimum_required(VERSION 3.15)
project(wgcpp VERSION 1.0.0 LANGUAGES CXX)

add_library(wgcpp SHARED
    include/wginterface.hpp
    embeddable-wg-library/wireguard.c
    include/wginterface.h
    include/wgexception.h
    src/wgexception.cpp
    include/wgkey.h
    include/wgpresharedkey.h
    include/wgkey.hpp
    include/wgpresharedkey.hpp
    include/wgprivatekey.h
    include/wgprivatekey.hpp
    include/wgpublickey.h
    include/wgpublickey.hpp
    include/wgpeer.h
    include/wgpeer.hpp
    include/wgallowedip.h
    include/wgallowedip.hpp
    include/wgendpoint.h
    include/wgendpoint.hpp
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