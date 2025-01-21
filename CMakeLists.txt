cmake_minimum_required(VERSION 3.30)
project(untitled)

set(CMAKE_CXX_STANDARD 20)

# Set the path to the TPM2-TSS library and include directory
set(TPM2_TSS_LIB_DIR "C:/Users/jagu/CLionProjects/untitled/compiled-libs")
set(TPM2_TSS_INCLUDE_DIR "C:/Users/jagu/CLionProjects/untitled/tpm2-tss-master/include")

# Include the TPM2-TSS headers
include_directories(${TPM2_TSS_INCLUDE_DIR})

# Add the executable
add_executable(untitled main.cpp)

# Link against the TPM2-TSS libraries
target_link_libraries(untitled
        ${TPM2_TSS_LIB_DIR}/tss2-mu.dll
        ${TPM2_TSS_LIB_DIR}/tss2-rc.dll
        ${TPM2_TSS_LIB_DIR}/tss2-sys.dll
        ${TPM2_TSS_LIB_DIR}/tss2-tcti-mssim.dll
        ${TPM2_TSS_LIB_DIR}/tss2-tcti-tbs.dll
        ${TPM2_TSS_LIB_DIR}/tss2-tctildr.dll
        ${TPM2_TSS_LIB_DIR}/tss2-esys.dll
)