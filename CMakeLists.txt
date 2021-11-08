cmake_minimum_required(VERSION 3.5)

# https://github.com/Sarcasm/cmake-superbuild/
option (USE_SUPERBUILD "Whether or not a superbuild should be invoked" ON)

if (USE_SUPERBUILD)
  project(jwp-mosquitto-plugin-super)
  include(external-deps.cmake)
  return()
else()
  project(jwp-mosquitto-plugin)
endif()

find_package(jwt-cpp)
find_package(OpenSSL)

add_library(jwp-plugin SHARED src/jwp-plugin.cpp)

add_executable(jwt-example src/jwt-example.cpp)
target_include_directories(jwt-example PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp/include)
target_link_libraries(jwt-example OpenSSL::Crypto)
