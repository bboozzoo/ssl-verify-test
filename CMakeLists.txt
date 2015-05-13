cmake_minimum_required(VERSION 3.2)
project(ssltest "C")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")

add_definitions(-D_GNU_SOURCE)
add_executable(ssltest main.c)

find_package(OpenSSL 0.9.8 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(ssltest ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})


