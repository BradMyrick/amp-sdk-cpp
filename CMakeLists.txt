cmake_minimum_required(VERSION 3.16)
project(amp-sdk-cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# ── Core library ────────────────────────────────────────────

add_library(amp-sdk STATIC
    src/crypto/crypto.cpp
    src/http_client.cpp
    src/websocket.cpp
    src/client.cpp
    third_party/nayuki/Keccak256.cpp
)

target_include_directories(amp-sdk PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nayuki
)

target_link_libraries(amp-sdk
    PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads
)

# EC_KEY APIs are deprecated in OpenSSL 3.x but still fully functional
target_compile_definitions(amp-sdk PRIVATE OPENSSL_API_COMPAT=0x10100000L)

target_compile_options(amp-sdk PRIVATE -Wall -Wextra -Wpedantic)

# ── Tests ───────────────────────────────────────────────────

enable_testing()

option(AMP_LIVE_TESTS "Run live tests against the production matchmaker" OFF)

add_executable(amp-tests tests/test_main.cpp)
target_link_libraries(amp-tests PRIVATE amp-sdk)
add_test(NAME AmpTests COMMAND amp-tests)

if(AMP_LIVE_TESTS)
    target_compile_definitions(amp-tests PRIVATE AMP_LIVE_TESTS=1)
endif()

# ── Examples ────────────────────────────────────────────────

add_executable(quick_start examples/quick_start.cpp)
target_link_libraries(quick_start PRIVATE amp-sdk)

# ── Installation ────────────────────────────────────────────

include(GNUInstallDirs)

install(TARGETS amp-sdk
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

install(FILES third_party/nayuki/Keccak256.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/amp/crypto
)
