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
#include <iomanip>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <vector>

#include "tpmTokenDemo_NativeTPMInterface.h"

static TSS2_RC rc = TSS2_RC_SUCCESS;

// Context and Session
static TSS2_TCTI_CONTEXT *tctiContext = nullptr;
static TSS2_SYS_CONTEXT *sysContext = nullptr;
static TSS2L_SYS_AUTH_COMMAND sessionsData = {1, {{TPM2_RS_PW, 0, 0, {0}}}};
static TPM2B_PUBLIC outPublic = {};
static TPM2B_NAME name = {};

static TPM2B_PUBLIC rsaPublic = {};
static TPM2B_PRIVATE rsaPrivate = {};

std::string to_uppercase(const std::string &str) {
    std::string result = str;
    for (char &c: result) {
        c = std::toupper(static_cast<unsigned char>(c));
    }
    return result;
}

std::string encode_ciphertext(const std::vector<uint8_t>& bytes_to_encode) {
    std::ostringstream oss;
    for (uint8_t byte : bytes_to_encode) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return oss.str();
}
extern "C" {

    TPM_API int get_rc() {
        return rc;
    }

    TPM_API const char* get_error_text(const TSS2_RC rc) {
        return Tss2_RC_Decode(rc);
    }

    TPM_API const char* get_loaded_rsa_key_info() {
        std::stringstream ss;
        ss << "rsaPublic:\n";
        ss << "size: " << rsaPublic.size << "\n";
        ss << "type: " << rsaPublic.publicArea.type << "\n";
        ss << "nameAlg: " << rsaPublic.publicArea.nameAlg << "\n";
        ss << "objectAttributes: " << rsaPublic.publicArea.objectAttributes << "\n";
        ss << "authPolicy.size: " << rsaPublic.publicArea.authPolicy.size << "\n";
        ss << "parameters.rsaDetail.symmetric.algorithm: " << rsaPublic.publicArea.parameters.rsaDetail.symmetric.algorithm << "\n";
        ss << "parameters.rsaDetail.symmetric.keyBits.aes: " << rsaPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes << "\n";
        ss << "parameters.rsaDetail.symmetric.mode.aes: " << rsaPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes << "\n";
        ss << "parameters.rsaDetail.scheme.scheme: " << rsaPublic.publicArea.parameters.rsaDetail.scheme.scheme << "\n";
        ss << "parameters.rsaDetail.keyBits: " << rsaPublic.publicArea.parameters.rsaDetail.keyBits << "\n";
        ss << "parameters.rsaDetail.exponent: " << rsaPublic.publicArea.parameters.rsaDetail.exponent << "\n";
        ss << "unique.rsa.size: " << rsaPublic.publicArea.unique.rsa.size << "\n";

        std::string info = ss.str();
        char* result = new char[info.size() + 1];
        std::strcpy(result, info.c_str());
        return result;
    }

    TPM_API const char* TPM_get_version() {
        TPMS_CAPABILITY_DATA capabilityData;
        TPMI_YES_NO moreData;

        rc = Tss2_Sys_GetCapability(sysContext, nullptr, TPM2_CAP_TPM_PROPERTIES, TPM2_SPEC_LEVEL, 1, &moreData, &capabilityData, nullptr);
        if (rc != TSS2_RC_SUCCESS) { return get_error_text(rc); }

        std::stringstream versionStream;
        versionStream << std::hex << capabilityData.data.tpmProperties.tpmProperty[0].value;

        std::string versionStr = versionStream.str();
        char* result = new char[versionStr.size() + 1];
        std::strcpy(result, versionStr.c_str());

        return result;
    }

    TPM_API const char* TPM_get_manufacturer() {
        TPMS_CAPABILITY_DATA capabilityData;
        TPMI_YES_NO moreData;

        rc = Tss2_Sys_GetCapability(sysContext, nullptr, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER, 1, &moreData, &capabilityData, nullptr);
        if (rc != TSS2_RC_SUCCESS) { return get_error_text(rc); }

        std::string manufacturer;
        bool leadingZeros = true;
        for (size_t i = sizeof(capabilityData.data.vendor.buffer); i > 0; --i) {
            if (leadingZeros && capabilityData.data.vendor.buffer[i] == '\0') {
                continue;
            }
            if (capabilityData.data.vendor.buffer[i] == '\0') {
                break;
            }

            leadingZeros = false;
            manufacturer += capabilityData.data.vendor.buffer[i];
        }

        char* result = new char[manufacturer.size() + 1];
        std::strcpy(result, manufacturer.c_str());

        return result;
    }

    TPM_API TSS2_RC TPM_setup_simulator() {

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

    TPM_API TSS2_RC TPM_setup_real() {

        size_t size = 0;
        rc = Tss2_Tcti_Tbs_Init(NULL, &size, NULL);
        if (rc != TSS2_RC_SUCCESS) { return rc; }

        tctiContext = (TSS2_TCTI_CONTEXT*)malloc(size);
        rc = Tss2_Tcti_Tbs_Init(tctiContext, &size, NULL);
        if (rc != TSS2_RC_SUCCESS) { return rc; }

        rc = Tss2_Tcti_Tbs_Init(tctiContext, &size, nullptr);
        if (rc != TSS2_RC_SUCCESS) { return rc; }

        size_t sysCtxSize = Tss2_Sys_GetContextSize(0);
        sysContext = static_cast<TSS2_SYS_CONTEXT*>(std::calloc(1, sysCtxSize));
        if (!sysContext) { return TSS2_SYS_RC_GENERAL_FAILURE; } // Error allocating sysContext.

        rc = Tss2_Sys_Initialize(sysContext, sysCtxSize, tctiContext, nullptr);
        if (rc != TSS2_RC_SUCCESS) { return rc; }

        if (rc == TPM2_RC_INITIALIZE) { return TSS2_RC_SUCCESS; } // TPM already initialized.
        return rc;

    }

    TPM_API const char* TPM_get_persistent_handles(const TPM2_HANDLE primaryHandle, const TPM2_HANDLE rsaHandle) {
        TPMI_YES_NO moreData;
        TPMS_CAPABILITY_DATA capabilityData;

        rc = Tss2_Sys_GetCapability(sysContext, nullptr, TPM2_CAP_HANDLES, TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES, &moreData, &capabilityData, nullptr);
        if (rc != TSS2_RC_SUCCESS) { return get_error_text(rc); }

        std::string handles = "";

        for (uint32_t i = 0; i < capabilityData.data.handles.count; i++) {
            std::string naming = "";
            if (capabilityData.data.handles.handle[i] == primaryHandle) {
                naming = " [PRIM.]";
            } else if (capabilityData.data.handles.handle[i] == rsaHandle) {
                naming = " [ RSA ]";
            }

            std::string handle;
            std::stringstream ss;
            ss << std::hex << capabilityData.data.handles.handle[i] << naming << "\n";
            handle += "0x";
            handle += to_uppercase(ss.str());
            handles += handle;
        }

        if (handles.empty()) {
            handles = "< none >";
        }

        std::string handles_str = handles;

        char* result = new char[handles_str.size() + 1];
        std::strcpy(result, handles_str.c_str());

        return result;
    }

    TPM_API TSS2_RC TPM_check_if_handle_is_free(const TPM2_HANDLE handle) {
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

    TPM_API TSS2_RC TPM_create_primary_key(const TPM2_HANDLE persistentHandle) {
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

    TPM_API TSS2_RC TPM_create_RSA_key(const TPM2_HANDLE parentHandle, const TPM2_HANDLE persistentHandle) {
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

    TPM_API const char* TPM_encrypt(const TPM2_HANDLE rsaHandle, const char* plainText) {
        TPM2B_PUBLIC_KEY_RSA message = {};
        TPM2B_PUBLIC_KEY_RSA outData = {};
        TPMT_RSA_DECRYPT scheme = {};
        TPM2B_DATA label = {};

        TSS2L_SYS_AUTH_COMMAND * nullCmdAuths = NULL;  // no auth for command
        scheme.scheme = TPM2_ALG_NULL;

        message.size = std::strlen(plainText);
        memcpy(message.buffer, plainText, message.size);

        TSS2_RC rc = Tss2_Sys_RSA_Encrypt(sysContext, rsaHandle, nullCmdAuths, &message, &scheme, &label, &outData, nullptr);
        if (rc != TSS2_RC_SUCCESS) { return get_error_text(rc); }

        // Base64 encode the cipherText
        std::vector<uint8_t> cipherText(outData.buffer, outData.buffer + outData.size);
        std::string encoded_ciphertext = encode_ciphertext(cipherText);

        char* result = new char[encoded_ciphertext.size() + 1];
        std::strcpy(result, encoded_ciphertext.c_str());

        return result;
    }

    TPM_API const char* TPM_decrypt(const TPM2_HANDLE rsaHandle, const char* cipherText) {
        TPM2B_PUBLIC_KEY_RSA cipher = {};
        TPM2B_PUBLIC_KEY_RSA outData = {};
        TPMT_RSA_DECRYPT scheme = {};
        TPM2B_DATA label = {};

        scheme.scheme = TPM2_ALG_NULL;

        std::vector<uint8_t> cipherTextBytes;
        for (size_t i = 0; i < std::strlen(cipherText); i += 2) {
            std::string byteString = std::string(cipherText + i, 2);
            uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
            cipherTextBytes.push_back(byte);
        }

        cipher.size = cipherTextBytes.size();
        memcpy(cipher.buffer, cipherTextBytes.data(), cipher.size);

        TSS2_RC rc = Tss2_Sys_RSA_Decrypt(sysContext, rsaHandle, &sessionsData, &cipher, &scheme, &label, &outData, nullptr);
        if (rc != TSS2_RC_SUCCESS) { return get_error_text(rc); }

        // Find the first non-null character in the decrypted text
        size_t start = 0;
        while (start < outData.size && outData.buffer[start] == '\0') {
            ++start;
        }

        std::string decryptedText(reinterpret_cast<char*>(outData.buffer + start), outData.size - start);

        char* result = new char[decryptedText.size() + 1];
        std::strcpy(result, decryptedText.c_str());

        std::cout << "Decrypted text: " << result << std::endl;

        return result;
    }

    TPM_API void TPM_end_session() {
        Tss2_Sys_Finalize(sysContext);
        free(tctiContext);
        free(sysContext);
    }

}

// main
int main() {
    TPM_setup_simulator();
    std::cout << "TPM Version: " << TPM_get_version() << std::endl;
}