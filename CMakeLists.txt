cmake_minimum_required(VERSION 3.16)

# https://github.com/Sarcasm/cmake-superbuild/
option (USE_SUPERBUILD "Whether or not a superbuild should be invoked" ON)

if (USE_SUPERBUILD)
  project(j7s-mosquitto-plugin-super)
  include(external-deps.cmake)
  return()
else()
  project(j7s-mosquitto-plugin)
endif()

find_package(jwt-cpp)
find_package(OpenSSL)

set(CMAKE_CXX_STANDARD 20)

add_library(j7s-plugin SHARED src/j7s-plugin.cpp src/AuthList.cpp src/Authorizer.cpp)
target_include_directories(j7s-plugin PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
  ${jwt-cpp_INCLUDE_DIR}
)
target_link_libraries(j7s-plugin OpenSSL::Crypto)
