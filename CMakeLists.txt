cmake_minimum_required(VERSION 3.16)
project(j7s-mosquitto-plugin)

include(external-deps.cmake)

find_package(OpenSSL)
find_package(yaml-cpp)

set(CMAKE_CXX_STANDARD 20)

add_library(j7s-plugin-utils SHARED src/utils.cpp)
target_include_directories(j7s-plugin-utils PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(j7s-plugin-utils OpenSSL::Crypto jwt-cpp)

add_library(Authorizer SHARED src/Authorizer.cpp src/AuthList.cpp)
target_include_directories(Authorizer PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(Authorizer j7s-plugin-utils yaml-cpp)

add_library(j7s-plugin SHARED src/j7s-plugin.cpp)
target_include_directories(j7s-plugin PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(j7s-plugin j7s-plugin-utils Authorizer)

add_executable(j7s-gen-token src/gen-token.cpp)
target_include_directories(j7s-gen-token PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(j7s-gen-token j7s-plugin-utils argparse::argparse)

if(BUILD_TESTING)
    FetchContent_Declare(googletest
        GIT_REPOSITORY "https://github.com/google/googletest.git"
        GIT_TAG "release-1.11.0"
        GIT_SHALLOW "True"
    )
    FetchContent_MakeAvailable(googletest)

    include(GoogleTest)

    enable_testing()

    add_executable(token_test test/token_test.cpp)
    target_include_directories(token_test PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    target_link_libraries(token_test j7s-plugin-utils GTest::gtest_main)
    gtest_discover_tests(token_test)
endif()

install(
   TARGETS
      j7s-plugin
      Authorizer
      j7s-plugin-utils
      j7s-gen-token
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
    COMPONENT Plugin
)
