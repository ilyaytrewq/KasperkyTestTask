
cmake_minimum_required(VERSION 3.19)
project(VirusScanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TESTS "Build unit tests" ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ------------------------
# Настройка OpenSSL
# ------------------------
set(OPENSSL_ROOT_DIR ${PROJECT_SOURCE_DIR}/openssl-3.5.3/x64)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
set(OPENSSL_LIBRARIES ${OPENSSL_ROOT_DIR}/lib)
set(OPENSSL_BIN_DIR ${OPENSSL_ROOT_DIR}/bin)

find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    message(STATUS "Found OpenSSL: ${OPENSSL_INCLUDE_DIR}, ${OPENSSL_LIBRARIES}")
else()
    message(FATAL_ERROR "OpenSSL not found in ${OPENSSL_ROOT_DIR}")
endif()

# ------------------------
# DLL (shared library) с основной логикой
# ------------------------
file(GLOB LIB_SOURCES
    ${PROJECT_SOURCE_DIR}/src/*.cpp
)

add_library(virus_scanner SHARED ${LIB_SOURCES})
target_include_directories(virus_scanner PUBLIC 
    ${PROJECT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)
target_compile_definitions(virus_scanner PRIVATE VIRUSSCANNER_EXPORTS)
target_link_libraries(virus_scanner PUBLIC OpenSSL::Crypto OpenSSL::SSL)

# ------------------------
# Основной исполняемый файл scanner
# ------------------------
add_executable(scanner scanner.cpp)
target_link_libraries(scanner PRIVATE virus_scanner)
target_include_directories(scanner PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# Копирование DLL файлов OpenSSL для scanner
add_custom_command(TARGET scanner POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${OPENSSL_BIN_DIR}/libcrypto-3-x64.dll"
        "${OPENSSL_BIN_DIR}/libssl-3-x64.dll"
        $<TARGET_FILE_DIR:scanner>
    COMMENT "Copying OpenSSL DLLs for scanner"
)

# ------------------------
# Тесты (GoogleTest)
# ------------------------
if (BUILD_TESTS)
    enable_testing()
    include(FetchContent)

    if(POLICY CMP0135)
      cmake_policy(SET CMP0135 NEW)
    endif()

    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG release-1.12.1
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(googletest)

    file(GLOB_RECURSE TEST_SRC CONFIGURE_DEPENDS
        ${PROJECT_SOURCE_DIR}/tests/*.cpp
    )

    if(TEST_SRC)
        add_executable(unit_tests ${TEST_SRC})
        target_include_directories(unit_tests PRIVATE 
            ${PROJECT_SOURCE_DIR}/include
            ${OPENSSL_INCLUDE_DIR}
        )
        target_link_libraries(unit_tests PRIVATE virus_scanner GTest::gtest_main)
        
        # Копирование DLL файлов OpenSSL для unit_tests
        add_custom_command(TARGET unit_tests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${OPENSSL_BIN_DIR}/libcrypto-3-x64.dll"
                "${OPENSSL_BIN_DIR}/libssl-3-x64.dll"
                $<TARGET_FILE_DIR:unit_tests>
            COMMENT "Copying OpenSSL DLLs for unit_tests"
        )
        
        add_test(NAME unit_tests COMMAND unit_tests)
    else()
        message(STATUS "No test source files found in ${PROJECT_SOURCE_DIR}/tests; skipping unit_tests target.")
    endif()
endif()