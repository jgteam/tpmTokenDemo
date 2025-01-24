cmake_minimum_required(VERSION 3.10)

project(TPM_API VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(TPM2_TSS_LIB_DIR "${CMAKE_SOURCE_DIR}/compiled-libs")
set(TPM2_TSS_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/tpm2-tss-master/include")

include_directories(${TPM2_TSS_INCLUDE_DIR})
link_directories(${TPM2_TSS_LIB_DIR})

add_library(TPM_API SHARED tpmTokenDemo_NativeTPMInterface.cpp)

target_link_libraries(TPM_API
        tss2-mu
        tss2-rc
        tss2-sys
        tss2-tcti-mssim
        tss2-tcti-tbs
        tss2-tctildr
        tss2-esys
        ${JNI_LIBRARIES}
)

set_target_properties(TPM_API PROPERTIES
        OUTPUT_NAME "TPM_API"
        PREFIX ""
        SUFFIX ".dll"
)

target_compile_definitions(TPM_API PRIVATE BUILDING_TPM_API)