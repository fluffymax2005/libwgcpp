cmake_minimum_required(VERSION 3.15)
project(wgcpp VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(wgcpp SHARED
    embeddable-wg-library/wireguard.c
    src/wgexception.cpp
    wgcppConfig.cmake.in
)

set_source_files_properties(
    embeddable-wg-library/wireguard.c PROPERTIES LANGUAGE C
)

target_sources(wgcpp PRIVATE
    include/wginterface.h
    include/wgexception.h
    include/wgkey.h
    include/wgpresharedkey.h
    include/wgprivatekey.h
    include/wgpublickey.h
    include/wgpeer.h
    include/wgallowedip.h
    include/wgendpoint.h
    include/threadsafety.h

    README.md
)

target_include_directories(wgcpp
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/embeddable-wg-library
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include/libwgcpp>
)

install(TARGETS wgcpp
    EXPORT wgcppTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(EXPORT wgcppTargets
    FILE wgcppTargets.cmake
    DESTINATION lib/cmake/wgcpp
)

install(DIRECTORY include/ DESTINATION include/libwgcpp)
install(FILES README.md DESTINATION share/doc/libwgcpp)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/wgcppConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wgcppConfig.cmake"
    INSTALL_DESTINATION lib/cmake/wgcpp
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wgcppConfig.cmake"
    DESTINATION lib/cmake/wgcpp
)

include(CPack)