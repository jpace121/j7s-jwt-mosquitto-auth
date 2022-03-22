include (ExternalProject)

set (DEPENDENCIES)
set (EXTRA_CMAKE_ARGS)

list(APPEND DEPENDENCIES ep_jwt-cpp)
ExternalProject_Add(ep_jwt-cpp
  PREFIX ep_jwt-cpp
  GIT_REPOSITORY "https://github.com/Thalhammer/jwt-cpp.git"
  GIT_TAG "v0.5.2"
  GIT_SHALLOW "True"
  CMAKE_ARGS -DJWT_CMAKE_FILES_INSTALL_DIR=${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp
  BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp
)
list (APPEND EXTRA_CMAKE_ARGS
  -Djwt-cpp_DIR=${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp -Djwt-cpp_INCLUDE_DIR=${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp/include
)

list(APPEND DEPENDENCIES ep_argparse)
ExternalProject_Add(ep_argparse
  PREFIX ep_argparse
  GIT_REPOSITORY "https://github.com/p-ranav/argparse.git"
  GIT_TAG "v2.2"
  GIT_SHALLOW "True"
  CMAKE_ARGS -DARGPARSE_CMAKE_FILES_INSTALL_DIR=${CMAKE_CURRENT_BINARY_DIR}/argparse -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/argparse
  BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/argparse
)
list (APPEND EXTRA_CMAKE_ARGS
  -Dargparse_DIR=${CMAKE_CURRENT_BINARY_DIR}/argparse
)

ExternalProject_Add (ep_j7s-mosquitto-plugin
  PREFIX ep_j7s-mosquitto-plugin
  DEPENDS ${DEPENDENCIES}
  SOURCE_DIR "${PROJECT_SOURCE_DIR}"
  CMAKE_ARGS -DUSE_SUPERBUILD=OFF ${EXTRA_CMAKE_ARGS}
  INSTALL_COMMAND ""
  BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}
)
