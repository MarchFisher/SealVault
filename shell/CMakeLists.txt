cmake_minimum_required(VERSION 3.16)
project(sealvault_shell LANGUAGES CXX)

add_executable(
  svshell
  WIN32
  src/main.cpp
  src/windows_utils.cpp
  src/registry_menu.cpp
  src/engine_bridge.cpp
)

target_compile_features(svshell PRIVATE cxx_std_17)
target_compile_definitions(svshell PRIVATE UNICODE _UNICODE)

if(MSVC)
  target_compile_options(svshell PRIVATE /W4 /permissive-)
else()
  target_compile_options(svshell PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(MINGW)
  target_link_options(svshell PRIVATE -municode)
endif()
