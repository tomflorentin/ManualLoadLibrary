cmake_minimum_required(VERSION 3.15)
project(csutom_gpa)

set(CMAKE_CXX_STANDARD 14)

include_directories(csutom_gpa)

add_executable(csutom_gpa
        csutom_gpa/csutom_gpa.cpp
        csutom_gpa/pe.h)
