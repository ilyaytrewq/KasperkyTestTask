cmake_minimum_required(VERSION 3.19)
project(VirusScanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TESTS "Build unit tests" ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_compile_options(-Wall -Wextra -Wpedantic)

set(LIB_SOURCES
    src/VirusScaner.cpp
    src/TimeGuard.cpp
)
add_library(virus_core STATIC ${LIB_SOURCES})
target_include_directories(virus_core PUBLIC ${PROJECT_SOURCE_DIR}/include)

find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    target_link_libraries(virus_core PUBLIC OpenSSL::Crypto)
else()
    message(WARNING "OpenSSL not found; MD5-related code may fail to link")
endif()

add_executable(scanner scanner.cpp)
target_link_libraries(scanner PRIVATE virus_core)
target_include_directories(scanner PRIVATE ${PROJECT_SOURCE_DIR}/include)

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
        target_include_directories(unit_tests PRIVATE ${PROJECT_SOURCE_DIR}/include)
        target_link_libraries(unit_tests PRIVATE virus_core GTest::gtest_main)
        add_test(NAME unit_tests COMMAND unit_tests)
    else()
        message(STATUS "No test source files found in ${PROJECT_SOURCE_DIR}/tests; skipping unit_tests target.")
    endif()
endif()