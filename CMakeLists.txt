cmake_minimum_required(VERSION 3.0)
project(ROUTER_LAB LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

set(BACKEND Linux CACHE STRING "Router platform")
set(BACKEND_VALUES "Linux" "macOS" "stdio")
set_property(CACHE BACKEND PROPERTY STRINGS ${BACKEND_VALUES})
list(FIND BACKEND_VALUES ${BACKEND} BACKEND_INDEX)

if(${BACKEND_INDEX} EQUAL -1)
    message(WARNING "Backend ${BACKEND} not supported, valid items are: ${BACKEND_VALUES}")
    set(BACKEND "Linux")
else()
    message("Using backend ${BACKEND}")
endif()

string(TOUPPER "${BACKEND}" BACKEND)
add_definitions("-DROUTER_BACKEND_${BACKEND}")

add_subdirectory(HAL)
add_subdirectory(Example)
