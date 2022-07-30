cmake_minimum_required(VERSION 3.4)
project(SHADOWD)

# Settings
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Version
set(SHADOWD_MAJOR_VERSION 2)
set(SHADOWD_MINOR_VERSION 2)
set(SHADOWD_PATCH_VERSION 0)
set(SHADOWD_VERSION
    ${SHADOWD_MAJOR_VERSION}.${SHADOWD_MINOR_VERSION}.${SHADOWD_PATCH_VERSION}
)

# Dependencies
find_package(OpenSSL REQUIRED)

set(Boost_USE_STATIC_LIBS OFF) 
set(Boost_USE_MULTITHREADED ON)  
set(Boost_USE_STATIC_RUNTIME OFF) 
find_package(Boost COMPONENTS REQUIRED
    program_options
    system
    thread
    regex unit_test_framework
)
include_directories(${Boost_INCLUDE_DIRS})

INCLUDE(CheckIncludeFiles)
CHECK_INCLUDE_FILES("dbi/dbi.h" HAVE_DBI_H)

if(NOT HAVE_DBI_H)
    message(FATAL_ERROR "libdbi is missing")
endif()

INCLUDE(CheckLibraryExists)
CHECK_LIBRARY_EXISTS(dbi dbi_initialize_r "" HAVE_DBI_NEW)

INCLUDE(CheckIncludeFileCXX)
CHECK_INCLUDE_FILE_CXX("cryptopp/hmac.h" HAVE_CRYPTOPP_H)

if(NOT HAVE_CRYPTOPP_H)
    message(FATAL_ERROR "libcryptopp is missing")
endif()

# Config
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/build_config.h
)
include_directories(${PROJECT_BINARY_DIR})

# Add source
add_subdirectory(src)

# Add unit tests
add_subdirectory(tests)

enable_testing()
add_test(NAME shadowd_tests COMMAND tests)

# Add misc
add_subdirectory(misc)
