cmake_minimum_required(VERSION 3.27)
project(sigme CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Point ida-cmake at our vendored IDA SDK and bootstrap.
set(ENV{IDASDK} "${CMAKE_CURRENT_SOURCE_DIR}/third_party/ida-sdk")
include(${CMAKE_CURRENT_SOURCE_DIR}/third_party/ida-cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

ida_add_plugin(sigme
    SOURCES
        Src/Plugin.cpp
        Src/Scanner.cpp
        Src/Scanner.h
)
