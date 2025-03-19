cmake_minimum_required(VERSION 3.20)

# set the C standard to C++23.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(lazy_deporter)

# include the files in the source tree.
file(GLOB_RECURSE SOURCES src/*.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})
