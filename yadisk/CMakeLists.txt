#CMakeLists.txt

cmake_minimum_required(VERSION 3.0)
project(client)

set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/client.c ${CMAKE_CURRENT_SOURCE_DIR}/http-parser/http_parser.c)
set(HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/http-parser/http_parser.h)

add_executable(${PROJECT_NAME} ${SOURCE_FILES} ${HEADER_FILES})

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
