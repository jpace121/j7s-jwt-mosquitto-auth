cmake_minimum_required(VERSION 3.16)
project(j7s-mosquitto-plugin)

include(external-deps.cmake)

find_package(OpenSSL)
find_package(yaml-cpp)

set(CMAKE_CXX_STANDARD 20)

add_library(utils SHARED src/utils.cpp)
target_include_directories(utils PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(utils OpenSSL::Crypto jwt-cpp)

add_library(Authorizer SHARED src/Authorizer.cpp src/AuthList.cpp)
target_include_directories(Authorizer PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(Authorizer utils yaml-cpp)

add_library(j7s-plugin SHARED src/j7s-plugin.cpp)
target_include_directories(j7s-plugin PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(j7s-plugin utils Authorizer)

add_executable(gen-token src/gen-token.cpp)
target_include_directories(gen-token PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(gen-token utils argparse::argparse)

if(BUILD_TESTING)
    include(GoogleTest)

    enable_testing()

    add_executable(token_test test/token_test.cpp)
    target_include_directories(token_test PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    target_link_libraries(token_test utils GTest::gtest_main)
    gtest_discover_tests(token_test)
endif()
