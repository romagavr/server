#CMakeLists.txt

cmake_minimum_required(VERSION 3.0)
project(client)

set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(LIB ${CMAKE_CURRENT_SOURCE_DIR}/lib)

set(SOURCE_FILES ${SRC}/network.c ${SRC}/client.c ${LIB}/http-parser/http_parser.c)
set(HEADER_FILES ${SRC}/network.h ${SRC}/client.h ${LIB}/http-parser/http_parser.h)
set(MAIN ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

add_executable(${PROJECT_NAME} ${SOURCE_FILES} ${HEADER_FILES} ${MAIN})

find_package(OpenSSL REQUIRED)
if(NOT OpenSSL_FOUND)
    message(SEND_ERROR "Failed to find OpenSSL")
    return()
else()
    target_include_directories(${PROJECT_NAME} PUBLIC ${OPENSSL_INCLUDE_DIRS})
endif()

find_package(LibXml2 REQUIRED)
if(NOT LIBXML2_FOUND)
    message(SEND_ERROR "Failed to find LibXml2")
    return()
else()
    target_include_directories(${PROJECT_NAME} PUBLIC ${LIBXML2_INCLUDE_DIR})
endif()

target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} ${LIBXML2_LIBRARIES})
target_compile_options(${PROJECT_NAME} PUBLIC -Wall)
