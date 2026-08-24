cmake_minimum_required(VERSION 3.0)

project(HRACS)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PBC_ROOT "$ENV{PBC_ROOT}" CACHE PATH "PBC installation prefix")
set(GMP_ROOT "$ENV{GMP_ROOT}" CACHE PATH "GMP installation prefix")
set(HRACS_CONDA_ROOT "$ENV{HRACS_CONDA_ROOT}" CACHE PATH "Conda environment prefix for HRACS dependencies")

if(NOT HRACS_CONDA_ROOT)
    set(HRACS_CONDA_ROOT "$ENV{CONDA_PREFIX}")
endif()

if(PBC_ROOT)
    find_path(PBC_INCLUDE_DIR NAMES pbc/pbc.h PATHS "${PBC_ROOT}/include" NO_DEFAULT_PATH)
    find_library(PBC_LIBRARY NAMES pbc PATHS "${PBC_ROOT}/lib" NO_DEFAULT_PATH)
else()
    find_path(PBC_INCLUDE_DIR NAMES pbc/pbc.h
        PATHS
            /usr/local/include
            /usr/include
            /home/zl/opt/pbc-0.5.14/include
    )
    find_library(PBC_LIBRARY NAMES pbc
        PATHS
            /usr/local/lib
            /usr/lib
            /usr/lib/x86_64-linux-gnu
            /home/zl/opt/pbc-0.5.14/lib
    )
endif()

if(GMP_ROOT)
    find_path(GMP_INCLUDE_DIR NAMES gmp.h PATHS "${GMP_ROOT}/include" NO_DEFAULT_PATH)
    find_library(GMP_LIBRARY NAMES gmp PATHS "${GMP_ROOT}/lib" NO_DEFAULT_PATH)
else()
    find_path(GMP_INCLUDE_DIR NAMES gmp.h
        PATHS
            /usr/local/include
            /usr/include
            /usr/include/x86_64-linux-gnu
            /home/zl/miniconda3/envs/hracs/include
    )
    find_library(GMP_LIBRARY NAMES gmp
        PATHS
            /usr/local/lib
            /usr/lib
            /usr/lib/x86_64-linux-gnu
            /home/zl/miniconda3/envs/hracs/lib
    )
endif()

if(NOT PBC_INCLUDE_DIR OR NOT PBC_LIBRARY)
    message(FATAL_ERROR "PBC was not found. Set PBC_ROOT to the PBC install prefix, for example: export PBC_ROOT=/home/zl/opt/pbc-0.5.14")
endif()

if(NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARY)
    message(FATAL_ERROR "GMP was not found. Set GMP_ROOT to the GMP install prefix, for example: export GMP_ROOT=/home/zl/miniconda3/envs/hracs")
endif()

find_path(CRYPTOPP_INCLUDE_DIR NAMES cryptopp/cryptlib.h
    PATHS
        "${HRACS_CONDA_ROOT}/include"
        /usr/local/include
        /usr/include
)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp
    PATHS
        "${HRACS_CONDA_ROOT}/lib"
        /usr/local/lib
        /usr/lib
        /usr/lib/x86_64-linux-gnu
)
find_path(SODIUM_INCLUDE_DIR NAMES sodium.h
    PATHS
        "${HRACS_CONDA_ROOT}/include"
        /usr/local/include
        /usr/include
)
find_library(SODIUM_LIBRARY NAMES sodium
    PATHS
        "${HRACS_CONDA_ROOT}/lib"
        /usr/local/lib
        /usr/lib
        /usr/lib/x86_64-linux-gnu
)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Crypto++ was not found. Set HRACS_CONDA_ROOT or CONDA_PREFIX to the conda env prefix, for example: export HRACS_CONDA_ROOT=/home/zl/miniconda3/envs/hracs")
endif()

if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium was not found. Set HRACS_CONDA_ROOT or CONDA_PREFIX to the conda env prefix, for example: export HRACS_CONDA_ROOT=/home/zl/miniconda3/envs/hracs")
endif()

include_directories(Header ${PBC_INCLUDE_DIR} ${GMP_INCLUDE_DIR} ${CRYPTOPP_INCLUDE_DIR} ${SODIUM_INCLUDE_DIR})

add_executable(hracs_server server.cpp)
add_executable(hracs_client client.cpp)

foreach(target hracs_server hracs_client)
    target_link_libraries(${target} ${PBC_LIBRARY} ${GMP_LIBRARY} ${CRYPTOPP_LIBRARY} ssl crypto ${SODIUM_LIBRARY})
    set_target_properties(${target} PROPERTIES
        BUILD_RPATH "$<TARGET_FILE_DIR:${target}>;${PBC_ROOT}/lib;${GMP_ROOT}/lib;${HRACS_CONDA_ROOT}/lib;/home/zl/opt/pbc-0.5.14/lib;/home/zl/miniconda3/envs/hracs/lib"
    )
endforeach()

set(CMAKE_BUILD_TYPE Debug)
