cmake_minimum_required(VERSION 3.10)
project(APAKE_Chen_PBC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_path(PBC_INCLUDE_DIR NAMES pbc/pbc.h
    PATHS /usr/local/include /usr/include /home/zl/opt/pbc-0.5.14/include)
find_library(PBC_LIBRARY NAMES pbc
    PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu
          /home/zl/opt/pbc-0.5.14/lib /home/zl/pbc-0.5.14/.libs)
find_path(GMP_INCLUDE_DIR NAMES gmp.h
    PATHS /usr/local/include /usr/include /usr/include/x86_64-linux-gnu
          /home/zl/miniconda3/envs/hracs/include)
find_library(GMP_LIBRARY NAMES gmp
    PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu
          /home/zl/miniconda3/envs/hracs/lib)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp
    PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu
          /home/zl/miniconda3/envs/hracs/lib)
find_library(SODIUM_LIBRARY NAMES sodium)
find_package(OpenSSL REQUIRED)

if(NOT PBC_INCLUDE_DIR OR NOT PBC_LIBRARY)
    message(FATAL_ERROR "PBC was not found")
endif()

include_directories(Header ${PBC_INCLUDE_DIR} ${GMP_INCLUDE_DIR})

add_executable(build main.cpp)
add_executable(apake_chen_client client.cpp)
add_executable(apake_chen_server server.cpp)

set(APAKE_LIBRARIES ${PBC_LIBRARY} ${GMP_LIBRARY} OpenSSL::SSL OpenSSL::Crypto)
if(CRYPTOPP_LIBRARY)
    list(APPEND APAKE_LIBRARIES ${CRYPTOPP_LIBRARY})
endif()
if(SODIUM_LIBRARY)
    list(APPEND APAKE_LIBRARIES ${SODIUM_LIBRARY})
endif()

foreach(target build apake_chen_client apake_chen_server)
    target_link_libraries(${target} ${APAKE_LIBRARIES})
    set_target_properties(${target} PROPERTIES
        BUILD_RPATH "/home/zl/opt/pbc-0.5.14/lib;/home/zl/miniconda3/envs/hracs/lib")
endforeach()

set(CMAKE_BUILD_TYPE Debug)
