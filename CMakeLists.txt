cmake_minimum_required(VERSION 3.16)
project(VirusScanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(SRC
    scanner.cpp
    src/VirusScaner.cpp
    src/TimeGuard.cpp
)

add_executable(scanner ${SRC})

target_include_directories(scanner PRIVATE ${PROJECT_SOURCE_DIR}/include)

find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    target_link_libraries(scanner PRIVATE OpenSSL::Crypto)
else()
    message(WARNING "OpenSSL not found; you may need -lcrypto manually")
endif()

target_compile_options(scanner PRIVATE -Wall -Wextra -Wpedantic)

