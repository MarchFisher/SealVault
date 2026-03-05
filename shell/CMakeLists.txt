cmake_minimum_required(VERSION 3.16)
project(sealvault_shell LANGUAGES CXX)

add_executable(
  svshell
  src/main.cpp
  src/windows_utils.cpp
  src/registry_menu.cpp
  src/engine_bridge.cpp
)

target_compile_features(svshell PRIVATE cxx_std_17)

if(MSVC)
  target_compile_options(svshell PRIVATE /W4 /permissive-)
else()
  target_compile_options(svshell PRIVATE -Wall -Wextra -Wpedantic)
endif()
