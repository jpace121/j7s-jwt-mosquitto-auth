cmake_minimum_required(VERSION 3.5)

project(jwp-mosquitto-plugin)

add_subdirectory(ext/jwt-cpp)

add_library(jwp-plugin SHARED src/jwp-plugin.cpp)

add_executable(jwt-example src/jwt-example.cpp)
target_link_libraries(jwt-example PRIVATE jwt-cpp)
