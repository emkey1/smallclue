cmake_minimum_required(VERSION 3.10)

# Project Definition
project(smallclue C)

# Set C Standard (C99 or C11 recommended)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON) # Enable compiler-specific extensions (useful for POSIX/BSD functions)

# Options for build configuration
option(ENABLE_CURL "Enable curl support (requires libcurl)" ON)
option(ENABLE_IOS_TARGET "Enable iOS specific build flags (PSCAL_TARGET_IOS)" OFF)
option(WITH_EXSH "Include exsh shell integration" OFF)

# Add preprocessor definitions based on system
if(APPLE)
    add_definitions(-D__APPLE__)
    # For compatibility with Apple's availability macros if needed
    add_definitions(-D_DARWIN_C_SOURCE)
elseif(UNIX AND NOT APPLE)
    add_definitions(-D_POSIX_C_SOURCE=200809L)
    add_definitions(-D_XOPEN_SOURCE=700)
    add_definitions(-D_GNU_SOURCE) # For older glibc
endif()

if(ENABLE_IOS_TARGET)
    add_definitions(-DPSCAL_TARGET_IOS)
endif()

# Find dependencies
find_package(Threads REQUIRED)

if(ENABLE_CURL)
    find_package(CURL)
    if(CURL_FOUND)
        add_definitions(-DPSCAL_HAS_LIBCURL)
        include_directories(${CURL_INCLUDE_DIRS})
    else()
        message(WARNING "CURL not found. Building without curl support.")
        set(ENABLE_CURL OFF)
    endif()
endif()

# Include directories
# Assuming directory structure:
#   CMakeLists.txt
#   src/
#   common/ (required by core.c includes)
#   third-party/ (required by openssh_app.c)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/common
)

# Source files
set(SOURCES
    src/main.c
    src/core.c
    src/nextvi_app.c
    src/openssh_app.c
)

# Optional Integration source
# src/integration.c depends on vm/vm.h and backend_ast/builtin.h
# Only include if building with the full shell environment
if(WITH_EXSH)
    add_definitions(-DSMALLCLUE_WITH_EXSH)
    list(APPEND SOURCES src/integration.c)
    # You might need to add include paths for vm/ and backend_ast/ here
    # include_directories(${CMAKE_CURRENT_SOURCE_DIR}/vm)
endif()

# External Dependency Placeholders
# smallclue references symbols from OpenSSH (pscal_openssh_*) and Nextvi (nextvi_main_entry).
# These sources are NOT in the files you uploaded.
# You must add the source files for these libraries to the target, or link against them.
# Example:
# list(APPEND SOURCES third-party/nextvi/nextvi.c)
# list(APPEND SOURCES third-party/openssh/ssh.c ...)

# Define the Executable
add_executable(smallclue ${SOURCES})

# Link Libraries
target_link_libraries(smallclue PRIVATE Threads::Threads)

if(ENABLE_CURL)
    target_link_libraries(smallclue PRIVATE ${CURL_LIBRARIES})
endif()

if(APPLE)
    # Link against CoreFoundation or specific frameworks if iOS target functions require them
    # target_link_libraries(smallclue PRIVATE "-framework Foundation")
endif()

# Install instructions (optional)
install(TARGETS smallclue DESTINATION bin)
