#CMakeLists.txt

cmake_minimum_required(VERSION 3.0)

project(client)
add_executable(client client.c)
add_compile_options(-Wall -L/usr/lib -lssl -lcrypto)
