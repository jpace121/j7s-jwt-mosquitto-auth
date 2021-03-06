include(FetchContent)

FetchContent_Declare(jwt-cpp
  GIT_REPOSITORY "https://github.com/Thalhammer/jwt-cpp.git"
  GIT_TAG "v0.5.2"
  GIT_SHALLOW "True"
)
FetchContent_MakeAvailable(jwt-cpp)

FetchContent_Declare(argparse
  GIT_REPOSITORY "https://github.com/p-ranav/argparse.git"
  GIT_TAG "v2.2"
  GIT_SHALLOW "True"
)
FetchContent_MakeAvailable(argparse)