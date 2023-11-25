cmake_minimum_required(VERSION 3.26)
project(passwords)

set(CMAKE_CXX_STANDARD 14)

add_executable(passwords
        main.cpp
        Manager.cpp
        Hasher.h
        Hasher.cpp)
