#  Copyright 2020 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 3.12)
project(opsick_client C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

set(${PROJECT_NAME}_MAJOR 1)
set(${PROJECT_NAME}_MINOR 1)
set(${PROJECT_NAME}_PATCH 1)
set(${PROJECT_NAME}_VERSION_STRING "${${PROJECT_NAME}_MAJOR}.${${PROJECT_NAME}_MINOR}.${${PROJECT_NAME}_PATCH}")

option(${PROJECT_NAME}_DLL "Use as a DLL." OFF)
option(${PROJECT_NAME}_BUILD_DLL "Build as a DLL." OFF)
option(${PROJECT_NAME}_PACKAGE "Build the library and package it into a .tar.gz after successfully building." OFF)

if (${${PROJECT_NAME}_BUILD_DLL})
    add_compile_definitions("OPSICK_CLIENT_BUILD_DLL=1")
    set(${PROJECT_NAME}_DLL ON)
endif ()

if (${${PROJECT_NAME}_DLL})
    add_compile_definitions("OPSICK_CLIENT_DLL=1")
endif ()

option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)
option(pwcrypt_BUILD_ONLY_LIB "Do not build the pwcrypt CLI" ON)

set(${PROJECT_NAME}_PREV_BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS})

set(${PROJECT_NAME}_INCLUDE_DIR
        ${CMAKE_CURRENT_LIST_DIR}/include
        )

set(${PROJECT_NAME}_HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/opsick/opsick-client.h
        )

set(${PROJECT_NAME}_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/jsmn.h
        ${CMAKE_CURRENT_LIST_DIR}/src/opsick-client.c
        )

set(BUILD_SHARED_LIBS OFF)

if (NOT TARGET cecies)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/cecies cecies)
endif ()

if (NOT TARGET pwcrypt)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/pwcrypt pwcrypt)
endif ()

if (NOT TARGET orlp-ed25519)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/ed25519 ed25519)
endif ()

if (NOT TARGET glitchedhttps)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/glitchedhttps glitchedhttps)
endif ()

set(BUILD_SHARED_LIBS ${${PROJECT_NAME}_PREV_BUILD_SHARED_LIBS})

add_library(${PROJECT_NAME}
        ${${PROJECT_NAME}_HEADERS}
        ${${PROJECT_NAME}_SOURCES}
        )

if (${${PROJECT_NAME}_BUILD_DLL} OR BUILD_SHARED_LIBS)
    set_property(TARGET cecies PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET pwcrypt PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedtls PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedx509 PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedcrypto PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET orlp-ed25519 PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET glitchedhttps PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_target_properties(${PROJECT_NAME} PROPERTIES
            VERSION ${${PROJECT_NAME}_VERSION_STRING}
            SOVERSION ${${PROJECT_NAME}_MAJOR}
            )
endif ()

if (${${PROJECT_NAME}_PACKAGE})
    set_target_properties(${PROJECT_NAME} PROPERTIES
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"

            ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"

            ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            )

    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E copy ${CMAKE_CURRENT_LIST_DIR}/NOTICE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/NOTICE"
            )

    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E copy_directory ${CMAKE_CURRENT_LIST_DIR}/include "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/include"
            )

    string(TOLOWER "${PROJECT_NAME}-${${PROJECT_NAME}_VERSION_STRING}-${CMAKE_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz" ${PROJECT_NAME}_OUTPUT_ARCHIVE_FILENAME)

    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E tar "czvf" ${${PROJECT_NAME}_OUTPUT_ARCHIVE_FILENAME} ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}
            )
endif ()

target_link_libraries(${PROJECT_NAME}
        PUBLIC cecies
        PUBLIC pwcrypt
        PUBLIC orlp-ed25519
        PUBLIC glitchedhttps
        )

target_include_directories(${PROJECT_NAME}
        PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR}
        )
