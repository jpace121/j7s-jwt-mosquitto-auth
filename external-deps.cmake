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
  -Djwt-cpp_DIR=${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp
)

ExternalProject_Add (ep_jwp-mosquitto-plugin
  PREFIX ep_jwp-mosquitto-plugin
  DEPENDS ${DEPENDENCIES}
  SOURCE_DIR "${PROJECT_SOURCE_DIR}"
  CMAKE_ARGS -DUSE_SUPERBUILD=OFF ${EXTRA_CMAKE_ARGS}
  INSTALL_COMMAND ""
  BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}
)
