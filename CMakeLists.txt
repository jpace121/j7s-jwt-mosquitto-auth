cmake_minimum_required(VERSION 3.16)

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

set(CMAKE_CXX_STANDARD 20)

add_library(jwp-plugin SHARED src/jwp-plugin.cpp src/AuthList.cpp src/Authorizer.cpp)
target_include_directories(jwp-plugin PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
  ${jwt-cpp_INCLUDE_DIR}
)
target_link_libraries(jwp-plugin OpenSSL::Crypto)
