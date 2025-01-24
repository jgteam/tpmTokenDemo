cmake_minimum_required(VERSION 3.30)
project(tpmTokenDemo)

find_package(JNI REQUIRED)
include_directories(${JNI_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 20)

# Set the path to the TPM2-TSS library and include directory
set(TPM2_TSS_LIB_DIR "${CMAKE_SOURCE_DIR}/compiled-libs")
set(TPM2_TSS_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/tpm2-tss-master/include")

# Include the TPM2-TSS headers
include_directories(${TPM2_TSS_INCLUDE_DIR})

# Add the executable
add_executable(tpmTokenDemo main.cpp)

# Link against the TPM2-TSS libraries for the executable
target_link_libraries(tpmTokenDemo
        ${TPM2_TSS_LIB_DIR}/tss2-mu.dll
        ${TPM2_TSS_LIB_DIR}/tss2-rc.dll
        ${TPM2_TSS_LIB_DIR}/tss2-sys.dll
        ${TPM2_TSS_LIB_DIR}/tss2-tcti-mssim.dll
        ${TPM2_TSS_LIB_DIR}/tss2-tcti-tbs.dll
        ${TPM2_TSS_LIB_DIR}/tss2-tctildr.dll
        ${TPM2_TSS_LIB_DIR}/tss2-esys.dll
)

# Add the shared library (DLL) for JNI
add_library(tpmTokenDemoJNI SHARED main.cpp)

# Link against the TPM2-TSS libraries for the shared library
target_link_libraries(tpmTokenDemoJNI
        ${TPM2_TSS_LIB_DIR}/tss2-mu.dll
        ${TPM2_TSS_LIB_DIR}/tss2-rc.dll
        ${TPM2_TSS_LIB_DIR}/tss2-sys.dll
        ${TPM2_TSS_LIB_DIR}/tss2-tcti-mssim.dll
        ${TPM2_TSS_LIB_DIR}/tss2-tcti-tbs.dll
        ${TPM2_TSS_LIB_DIR}/tss2-tctildr.dll
        ${TPM2_TSS_LIB_DIR}/tss2-esys.dll
        ${JNI_LIBRARIES}
)