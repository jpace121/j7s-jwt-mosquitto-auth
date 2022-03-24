cmake_minimum_required(VERSION 3.16)
project(j7s-mosquitto-plugin)

include(external-deps.cmake)

find_package(OpenSSL)

set(CMAKE_CXX_STANDARD 20)

add_library(utils SHARED src/utils.cpp)
target_include_directories(utils PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(utils OpenSSL::Crypto jwt-cpp)

add_library(j7s-plugin SHARED src/j7s-plugin.cpp src/AuthList.cpp src/Authorizer.cpp)
target_include_directories(j7s-plugin PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(j7s-plugin utils)

add_executable(gen-token src/gen-token.cpp)
target_include_directories(gen-token PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(gen-token utils argparse::argparse)

if(BUILD_TESTING)
    include(GoogleTest)

    enable_testing()

    add_executable(authorizer_test test/authorizer_test.cpp)
    target_link_libraries(authorizer_test GTest::gtest_main)
    gtest_discover_tests(authorizer_test)
endif()
