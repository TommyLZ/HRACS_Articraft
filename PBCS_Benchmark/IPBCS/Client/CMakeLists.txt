cmake_minimum_required(VERSION 3.0)

project(IPBCS)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PBC_ROOT "$ENV{PBC_ROOT}" CACHE PATH "PBC installation prefix")
set(IPBCS_CONDA_ROOT "$ENV{IPBCS_CONDA_ROOT}" CACHE PATH "Conda environment prefix for IPBCS dependencies")

if(NOT IPBCS_CONDA_ROOT)
    set(IPBCS_CONDA_ROOT "$ENV{CONDA_PREFIX}")
endif()

if(PBC_ROOT)
    find_path(PBC_INCLUDE_DIR NAMES pbc/pbc.h pbc.h PATHS "${PBC_ROOT}/include" NO_DEFAULT_PATH)
    find_library(PBC_LIBRARY NAMES pbc PATHS "${PBC_ROOT}/lib" NO_DEFAULT_PATH)
else()
    find_path(PBC_INCLUDE_DIR NAMES pbc/pbc.h pbc.h
        PATHS
            /usr/local/include
            /usr/include
            /home/zl/opt/pbc-0.5.14/include
            /home/zl/pbc-0.5.14/include
    )
    find_library(PBC_LIBRARY NAMES pbc
        PATHS
            /usr/local/lib
            /usr/lib
            /usr/lib/x86_64-linux-gnu
            /home/zl/opt/pbc-0.5.14/lib
            /home/zl/pbc-0.5.14/.libs
    )
endif()

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
find_path(CRYPTOPP_INCLUDE_DIR NAMES cryptopp/cryptlib.h
    PATHS
        "${IPBCS_CONDA_ROOT}/include"
        /usr/local/include
        /usr/include
        /home/zl/miniconda3/envs/hracs/include
)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp
    PATHS
        "${IPBCS_CONDA_ROOT}/lib"
        /usr/local/lib
        /usr/lib
        /usr/lib/x86_64-linux-gnu
        /home/zl/miniconda3/envs/hracs/lib
)

if(NOT PBC_INCLUDE_DIR OR NOT PBC_LIBRARY)
    message(FATAL_ERROR "PBC was not found. Set PBC_ROOT to the PBC install prefix.")
endif()
if(NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARY)
    message(FATAL_ERROR "GMP was not found.")
endif()
if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Crypto++ was not found. Set IPBCS_CONDA_ROOT or CONDA_PREFIX if needed.")
endif()

include_directories(Header ${PBC_INCLUDE_DIR} ${GMP_INCLUDE_DIR} ${CRYPTOPP_INCLUDE_DIR})

set(IPBCS_SOURCES
    Source/Client.cpp
    Source/PublicParam.cpp
    Source/KeyServer.cpp
    Source/CloudServer.cpp
)

add_executable(ipbcs_server server.cpp ${IPBCS_SOURCES})
add_executable(ipbcs_client client.cpp ${IPBCS_SOURCES})

link_directories(/usr/local/lib /lib/x86_64-linux-gnu/ /usr/include)
foreach(target ipbcs_server ipbcs_client)
    target_link_libraries(${target} ${PBC_LIBRARY} ${GMP_LIBRARY} ${CRYPTOPP_LIBRARY})
    set_target_properties(${target} PROPERTIES
        BUILD_RPATH "$<TARGET_FILE_DIR:${target}>;${PBC_ROOT}/lib;${IPBCS_CONDA_ROOT}/lib;/home/zl/opt/pbc-0.5.14/lib;/home/zl/miniconda3/envs/hracs/lib"
    )
endforeach()

set(CMAKE_BUILD_TYPE Debug)
