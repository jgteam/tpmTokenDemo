//
// Created by jagu on 24/01/2025.
//

#include <tss2/tss2_sys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tcti_tbs.h>
#include <tss2/tss2_tcti_mssim.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <jni.h>

static TSS2_RC rc;

// Context and Session
static TSS2_TCTI_CONTEXT *tctiContext = nullptr;
static TSS2_SYS_CONTEXT *sysContext = nullptr;
static TSS2L_SYS_AUTH_COMMAND sessionsData = {1, {{TPM2_RS_PW, 0, 0, {0}}}};
static TPM2B_PUBLIC outPublic = {};
static TPM2B_NAME name = {};

static TPM2_HANDLE PRIMARY_HANDLE = 0x8100A00A;
static TPM2_HANDLE RSA_HANDLE = 0x8100A00B;

static TPM2B_PUBLIC rsaPublic = {};
static TPM2B_PRIVATE rsaPrivate = {};

std::string to_uppercase(const std::string &str) {
    std::string result = str;
    for (char &c : result) {
        c = std::toupper(static_cast<unsigned char>(c));
    }
    return result;
}

std::string get_error_text(const TSS2_RC rc) {
    const char *info = Tss2_RC_Decode(rc);
    return std::string(info);
}

TSS2_RC DEBUG(const TSS2_RC rc) {
    if (rc != TSS2_RC_SUCCESS) {
        std::string errorText = get_error_text(rc);
        std::cerr << "Error: " << errorText << std::endl;
    }

    return rc;
}

TSS2_RC TPM_setup_simulator() {

    size_t size = 0;
    rc = Tss2_Tcti_Mssim_Init(nullptr, &size, "host=127.0.0.1,port=2321");
    if (rc != TSS2_RC_SUCCESS) { return rc; }

    tctiContext = static_cast<TSS2_TCTI_CONTEXT*>(std::calloc(1, size));
    if (!tctiContext) { return TSS2_TCTI_RC_GENERAL_FAILURE; } // Failed to allocate TCTI context.

    rc = Tss2_Tcti_Mssim_Init(tctiContext, &size, "host=127.0.0.1,port=2321");
    if (rc != TSS2_RC_SUCCESS) { return rc; }

    size_t sysCtxSize = Tss2_Sys_GetContextSize(0);
    sysContext = static_cast<TSS2_SYS_CONTEXT*>(std::calloc(1, sysCtxSize));
    if (!sysContext) { return TSS2_SYS_RC_GENERAL_FAILURE; } // Error allocating sysContext.

    rc = Tss2_Sys_Initialize(sysContext, sysCtxSize, tctiContext, nullptr);
    if (rc != TSS2_RC_SUCCESS) { return rc; }

    rc = Tss2_Sys_Startup(sysContext, TPM2_SU_CLEAR); // Usually not needed when using a real TPM.
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) { return rc; }

    if (rc == TPM2_RC_INITIALIZE) { return TSS2_RC_SUCCESS; } // TPM already initialized.
    return rc;

}

std::string TPM_get_persistent_handles() {
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;

    rc = Tss2_Sys_GetCapability(sysContext, nullptr, TPM2_CAP_HANDLES, TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES, &moreData, &capabilityData, nullptr);
    if (rc != TSS2_RC_SUCCESS) { return get_error_text(rc); }

    std::string handles;

    for (uint32_t i = 0; i < capabilityData.data.handles.count; i++) {
        std::string naming = "";
        if (capabilityData.data.handles.handle[i] == PRIMARY_HANDLE) {
            naming = " [PRIM.]";
        } else if (capabilityData.data.handles.handle[i] == RSA_HANDLE) {
            naming = " [ RSA ]";
        }

        std::string handle;
        std::stringstream ss;
        ss << std::hex << capabilityData.data.handles.handle[i] << naming << "\n";
        handle += "0x";
        handle += to_uppercase(ss.str());
        handles += handle;
    }

    return handles;
}

TSS2_RC TPM_check_if_handle_is_free(const TPM2_HANDLE handle) {
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;

    rc = Tss2_Sys_GetCapability(sysContext, nullptr, TPM2_CAP_HANDLES, TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES, &moreData, &capabilityData, nullptr);
    if (rc != TSS2_RC_SUCCESS) { return rc; }

    for (uint32_t i = 0; i < capabilityData.data.handles.count; i++) {
        if (capabilityData.data.handles.handle[i] == handle) {
            return TSS2_SYS_RC_GENERAL_FAILURE; // Handle found.
        }
    }

    return TSS2_RC_SUCCESS; // Handle not found.
}

TSS2_RC TPM_create_primary_key(const TPM2_HANDLE persistentHandle) {
    TPM2B_SENSITIVE_CREATE inSensitive = {};
    TPM2B_PUBLIC inPublic = {};
    TPM2B_DATA outsideInfo = {};
    TPML_PCR_SELECTION creationPCR = {};
    TPM2B_CREATION_DATA creationData = {};
    TPM2B_DIGEST creationHash = {};
    TPMT_TK_CREATION creationTicket = {};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {};
    TPM2_HANDLE temporaryPrimaryHandle;

    inSensitive.size = sizeof(TPM2B_SENSITIVE_CREATE);
    inSensitive.sensitive.userAuth.size = 0;
    inSensitive.sensitive.data.size = 0;

    inPublic.size = sizeof(TPM2B_PUBLIC);
    inPublic.publicArea.type = TPM2_ALG_RSA;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH;
    inPublic.publicArea.authPolicy.size = 0;
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.publicArea.unique.rsa.size = 0;

    rc = Tss2_Sys_CreatePrimary(sysContext, TPM2_RH_OWNER, &sessionsData, &inSensitive, &inPublic, &outsideInfo, &creationPCR, &temporaryPrimaryHandle, &outPublic, &creationData, &creationHash, &creationTicket, &name, &sessionsDataOut);
    if (rc != TSS2_RC_SUCCESS) { return rc; }

    rc = Tss2_Sys_EvictControl(sysContext, TPM2_RH_OWNER, temporaryPrimaryHandle, &sessionsData, persistentHandle, nullptr);
    return rc;
}

TSS2_RC TPM_create_RSA_key(const TPM2_HANDLE parentHandle, const TPM2_HANDLE persistentHandle) {
    TPM2B_SENSITIVE_CREATE inSensitive = {};
    TPM2B_PUBLIC inPublic = {};
    TPM2B_DATA outsideInfo = {};
    TPML_PCR_SELECTION creationPCR = {};
    TPM2B_CREATION_DATA creationData = {};
    TPM2B_DIGEST creationHash = {};
    TPMT_TK_CREATION creationTicket = {};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {};
    TPM2_HANDLE temporaryRsaHandle;

    inSensitive.size = sizeof(TPM2B_SENSITIVE_CREATE);
    inSensitive.sensitive.userAuth.size = 0;
    inSensitive.sensitive.data.size = 0;

    inPublic.size = sizeof(TPM2B_PUBLIC);
    inPublic.publicArea.type = TPM2_ALG_RSA;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.objectAttributes = TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_DECRYPT |
                                            TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN;
    inPublic.publicArea.authPolicy.size = 0;
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL; // Set symmetric algorithm to NULL
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL; // No specific scheme
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.publicArea.parameters.rsaDetail.exponent = 0; // Default exponent
    inPublic.publicArea.unique.rsa.size = 0;

    rc = Tss2_Sys_Create(sysContext, parentHandle, &sessionsData, &inSensitive, &inPublic, &outsideInfo, &creationPCR, &rsaPrivate, &rsaPublic, &creationData, &creationHash, &creationTicket, &sessionsDataOut);
    if (rc != TSS2_RC_SUCCESS) { return rc; }

    rc = Tss2_Sys_Load(sysContext, parentHandle, &sessionsData, &rsaPrivate, &rsaPublic, &temporaryRsaHandle, &name, &sessionsDataOut);
    if (rc != TSS2_RC_SUCCESS) { return rc; }

    if (temporaryRsaHandle == TPM2_RH_NULL) { // Check if handle is initialized properly.
        return TSS2_BASE_RC_BAD_REFERENCE; // Handle not initialized properly.
    }

    rc = Tss2_Sys_EvictControl(sysContext, TPM2_RH_OWNER, temporaryRsaHandle, &sessionsData, persistentHandle, nullptr);
    return rc;
}

TSS2_RC TPM_encrypt(const TPM2_HANDLE rsaHandle, const std::string &plainText, std::vector<uint8_t> &cipherText) {
    TPM2B_PUBLIC_KEY_RSA message = {};
    TPM2B_PUBLIC_KEY_RSA outData = {};
    TPMT_RSA_DECRYPT scheme = {};
    TPM2B_DATA label = {};

    TSS2L_SYS_AUTH_COMMAND * nullCmdAuths = NULL;  // no auth for command
    scheme.scheme = TPM2_ALG_NULL;

    message.size = plainText.size();
    memcpy(message.buffer, plainText.c_str(), plainText.size());

    TSS2_RC rc = Tss2_Sys_RSA_Encrypt(sysContext, rsaHandle, nullCmdAuths, &message, &scheme, &label, &outData, nullptr);
    if (rc != TSS2_RC_SUCCESS) { return rc; }

    cipherText.assign(outData.buffer, outData.buffer + outData.size);
    return rc;
}

void TPM_end_session() {
    Tss2_Sys_Finalize(sysContext);
    free(tctiContext);
    free(sysContext);
}

int main() {

    rc = TPM_setup_simulator();
    if (DEBUG(rc)) { return -1; };

    std::string handles = TPM_get_persistent_handles();
    std::cout << "Handles before Prim. Key Creation: " << std::endl << handles << std::endl;

    rc = TPM_check_if_handle_is_free(PRIMARY_HANDLE);
    if (rc == TSS2_RC_SUCCESS) {
        rc = TPM_create_primary_key(PRIMARY_HANDLE);
        if (DEBUG(rc)) { return -1; };
    } else {
        rc = TSS2_RC_SUCCESS; // Handle already exists. Resetting rc.
    }

    handles = TPM_get_persistent_handles();
    std::cout << "Handles after Prim. Key Creation: " << std::endl << handles << std::endl;

    rc = TPM_check_if_handle_is_free(RSA_HANDLE);
    if (rc == TSS2_RC_SUCCESS) {
        rc = TPM_create_RSA_key(PRIMARY_HANDLE, RSA_HANDLE);
        if (DEBUG(rc)) { return -1; };
    } else {
        rc = TSS2_RC_SUCCESS; // Handle already exists. Resetting rc.
    }

    handles = TPM_get_persistent_handles();
    std::cout << "Handles after RSA Key Creation: " << std::endl << handles << std::endl;

    TPM_end_session();

    return 0;
}

extern "C" {

    JNIEXPORT jint JNICALL Java_tpmTokenDemo_tpmInterface_getRc(JNIEnv* env, jobject obj) {
        return static_cast<jint>(rc);
    }

    JNIEXPORT jstring JNICALL Java_tpmTokenDemo_tpmInterface_getLastErrorText(JNIEnv* env, jobject obj) {
        return env->NewStringUTF(get_error_text(rc).c_str());
    }

    JNIEXPORT void JNICALL Java_tpmTokenDemo_tpmInterface_setPrimaryHandle(JNIEnv* env, jobject obj, jint handle) {
        PRIMARY_HANDLE = static_cast<TPM2_HANDLE>(handle);
    }

    JNIEXPORT void JNICALL Java_tpmTokenDemo_tpmInterface_setRsaHandle(JNIEnv* env, jobject obj, jint handle) {
        RSA_HANDLE = static_cast<TPM2_HANDLE>(handle);
    }

    JNIEXPORT jint JNICALL Java_tpmTokenDemo_tpmInterface_getPrimaryHandle(JNIEnv* env, jobject obj) {
        return static_cast<jint>(PRIMARY_HANDLE);
    }

    JNIEXPORT jint JNICALL Java_tpmTokenDemo_tpmInterface_getRsaHandle(JNIEnv* env, jobject obj) {
        return static_cast<jint>(RSA_HANDLE);
    }

    JNIEXPORT jint JNICALL Java_tpmTokenDemo_tpmInterface_TPM_setupSimulator(JNIEnv* env, jobject obj) {
        return static_cast<jint>(TPM_setup_simulator());
    }

    JNIEXPORT jstring JNICALL Java_tpmTokenDemo_tpmInterface_TPM_getPersistentHandles(JNIEnv* env, jobject obj) {
        return env->NewStringUTF(TPM_get_persistent_handles().c_str());
    }

    JNIEXPORT jint JNICALL Java_tpmTokenDemo_tpmInterface_TPM_checkIfHandleIsFree(JNIEnv* env, jobject obj, jint handle) {
        return static_cast<jint>(TPM_check_if_handle_is_free(static_cast<TPM2_HANDLE>(handle)));
    }

    JNIEXPORT jint JNICALL Java_tpmTokenDemo_tpmInterface_TPM_createPrimaryKey(JNIEnv* env, jobject obj) {
        return static_cast<jint>(TPM_create_primary_key(PRIMARY_HANDLE));
    }

    JNIEXPORT jint JNICALL Java_tpmTokenDemo_tpmInterface_TPM_createRSAKey(JNIEnv* env, jobject obj) {
        return static_cast<jint>(TPM_create_RSA_key(PRIMARY_HANDLE, RSA_HANDLE));
    }

} // extern "C"