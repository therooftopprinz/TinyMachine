cmake_minimum_required(VERSION 3.16)

project(TinyMachineTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Keep the same debug-oriented defaults as configure.py.
add_compile_options(-O0 -ggdb3 -Wall -Werror)

add_library(gtest STATIC
  gtest/gmock-gtest-all.cc
)
target_include_directories(gtest PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/gtest
)
# Newer GCC warns inside vendored gtest; keep project -Werror strictness.
target_compile_options(gtest PRIVATE -Wno-error=maybe-uninitialized)
set_target_properties(gtest PROPERTIES OUTPUT_NAME gtest)

file(GLOB TEST_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/test/*.cpp"
)

add_executable(test
  ${TEST_SOURCES}
)
target_include_directories(test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/gtest
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/test
)
target_link_libraries(test PRIVATE
  gtest
  pthread
)
