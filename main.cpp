#include <tss2/tss2_sys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tcti_tbs.h>
#include <tss2/tss2_tcti_mssim.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <vector>

void print_tpm2b_public(const TPM2B_PUBLIC &publicArea) {
    std::cout << "Public Area Type: " << publicArea.publicArea.type << std::endl;
    std::cout << "Name Algorithm: " << publicArea.publicArea.nameAlg << std::endl;
    std::cout << "Object Attributes: " << publicArea.publicArea.objectAttributes << std::endl;
    std::cout << "Auth Policy Size: " << publicArea.publicArea.authPolicy.size << std::endl;
    std::cout << "RSA Key Bits: " << publicArea.publicArea.parameters.rsaDetail.keyBits << std::endl;
    std::cout << "RSA Exponent: " << publicArea.publicArea.parameters.rsaDetail.exponent << std::endl;
    std::cout << "Unique RSA Size: " << publicArea.publicArea.unique.rsa.size << std::endl;
}

TSS2_RC read_public_info(TSS2_SYS_CONTEXT *sysContext, TPM2_HANDLE handle, TSS2L_SYS_AUTH_COMMAND &sessionsData) {
    TPM2B_PUBLIC outPublic = {};
    TPM2B_NAME name = {};
    TPM2B_NAME qualifiedName = {};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {};




    TSS2_RC rc = Tss2_Sys_ReadPublic(sysContext, handle, &sessionsData, &outPublic, &name, &qualifiedName, &sessionsDataOut);
    if (rc == TPM2_RC_HANDLE) {
        std::cerr << "Handle not found." << std::endl;
        return rc;
    }
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error reading public info: " << rc << std::endl;
        return rc;
    }

    std::cout << "Handle: " << handle << std::endl;
    std::cout << "Name: ";
    for (size_t i = 0; i < name.size; i++) {
        std::cout << std::hex << (int)name.name[i];
    }
    std::cout << std::endl;
    print_tpm2b_public(outPublic);

    return rc;
}

TSS2_RC create_primary_key(TSS2_SYS_CONTEXT *sysContext, TPM2_HANDLE &primaryHandle, TPM2B_PUBLIC &outPublic, TPM2B_NAME &name, TSS2L_SYS_AUTH_COMMAND &sessionsData) {
    TPM2B_SENSITIVE_CREATE inSensitive = {};
    TPM2B_PUBLIC inPublic = {};
    TPM2B_DATA outsideInfo = {};
    TPML_PCR_SELECTION creationPCR = {};
    TPM2B_CREATION_DATA creationData = {};
    TPM2B_DIGEST creationHash = {};
    TPMT_TK_CREATION creationTicket = {};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {};
    TPM2_HANDLE temporaryPrimaryHandle;

    // Set up sensitive data
    inSensitive.size = sizeof(TPM2B_SENSITIVE_CREATE);
    inSensitive.sensitive.userAuth.size = 0;
    inSensitive.sensitive.data.size = 0;

    // Set up public data
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

    // Create the primary key
    TSS2_RC rc = Tss2_Sys_CreatePrimary(sysContext, TPM2_RH_OWNER, &sessionsData, &inSensitive, &inPublic, &outsideInfo, &creationPCR, &temporaryPrimaryHandle, &outPublic, &creationData, &creationHash, &creationTicket, &name, &sessionsDataOut);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    /* / For EvictControl we typically need an auth session, but for Owner auth=Empty PW is often enough:
    TSS2L_SYS_AUTH_COMMAND authCmdArray = {1, {{TPM2_RS_PW, 0, 0, {0}}}};
    TSS2L_SYS_AUTH_RESPONSE authRspArray;

    rc = Tss2_Sys_EvictControl(sysContext,
                               TPM2_RH_OWNER,         // Hierarchy
                               primaryHandle, // The transient handle from step 1
                               &authCmdArray,
                               primaryHandlePersistent,// The new permanent handle in 0x81xxxxxx range
                               &authRspArray);
    return rc;*/

    TPM2_HANDLE persistentHandle = 0x81010005;
    rc = Tss2_Sys_EvictControl(sysContext,
                               TPM2_RH_OWNER,   // or correct hierarchy
                               temporaryPrimaryHandle, // ephemeral
                               &sessionsData,
                               primaryHandle,
                               nullptr);
    return rc;
}

void list_persistent_handles(TSS2_SYS_CONTEXT *sysContext) {
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;
    TSS2_RC rc;

    rc = Tss2_Sys_GetCapability(sysContext, nullptr, TPM2_CAP_HANDLES, TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES, &moreData, &capabilityData, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error getting persistent handles: " << rc << std::endl;
        return;
    }

    std::cout << "Persistent Handles:" << std::endl;
    for (uint32_t i = 0; i < capabilityData.data.handles.count; i++) {
        std::cout << "Handle: 0x" << std::hex << capabilityData.data.handles.handle[i] << std::dec << std::endl;
    }
}

void write_primary_key_info(const TPM2_HANDLE &primaryHandle, const TPM2B_PUBLIC &outPublic, const TPM2B_NAME &name) {
    std::ofstream outFile("primary_key_info.txt");
    if (!outFile) {
        std::cerr << "Error opening file for writing." << std::endl;
        return;
    }

    outFile << primaryHandle << std::endl;
    outFile << name.size << std::endl;
    for (size_t i = 0; i < name.size; i++) {
        outFile << std::hex << (int)name.name[i] << " ";
    }
    outFile << std::endl;
    outFile << outPublic.publicArea.type << std::endl;
    outFile << outPublic.publicArea.nameAlg << std::endl;
    outFile << outPublic.publicArea.objectAttributes << std::endl;
    outFile << outPublic.publicArea.authPolicy.size << std::endl;
    outFile << outPublic.publicArea.parameters.rsaDetail.keyBits << std::endl;
    outFile << outPublic.publicArea.parameters.rsaDetail.exponent << std::endl;
    outFile << outPublic.publicArea.unique.rsa.size << std::endl;

    outFile.close();
}

bool read_primary_key_info(TPM2_HANDLE &primaryHandle, TPM2B_PUBLIC &outPublic, TPM2B_NAME &name) {
    std::ifstream inFile("primary_key_info.txt");
    if (!inFile) {
        return false;
    }

    inFile >> primaryHandle;
    inFile >> name.size;
    for (size_t i = 0; i < name.size; i++) {
        int byte;
        inFile >> std::hex >> byte;
        name.name[i] = static_cast<uint8_t>(byte);
    }
    inFile >> outPublic.publicArea.type;
    inFile >> outPublic.publicArea.nameAlg;
    inFile >> outPublic.publicArea.objectAttributes;
    inFile >> outPublic.publicArea.authPolicy.size;
    inFile >> outPublic.publicArea.parameters.rsaDetail.keyBits;
    inFile >> outPublic.publicArea.parameters.rsaDetail.exponent;
    inFile >> outPublic.publicArea.unique.rsa.size;

    inFile.close();
    return true;
}

TSS2_RC read_primary_key_from_tpm(TSS2_SYS_CONTEXT *sysContext, TPM2_HANDLE primaryHandle, TPM2B_PUBLIC &outPublic, TPM2B_NAME &name, TSS2L_SYS_AUTH_COMMAND &sessionsData) {
    TPM2B_NAME qualifiedName = {};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {};
    TSS2_RC rc = Tss2_Sys_ReadPublic(sysContext, primaryHandle, &sessionsData, &outPublic, &name, &qualifiedName, &sessionsDataOut);
    return rc;
}

// Function to check if a specific encryption scheme is available
bool is_scheme_available(TSS2_SYS_CONTEXT *sysContext, TPM2_ALG_ID scheme) {
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;
    TSS2_RC rc = Tss2_Sys_GetCapability(sysContext, nullptr, TPM2_CAP_ALGS, 0, TPM2_MAX_CAP_ALGS, &moreData, &capabilityData, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error getting TPM capabilities: " << rc << std::endl;
        return false;
    }

    for (uint32_t i = 0; i < capabilityData.data.algorithms.count; i++) {
        if (capabilityData.data.algorithms.algProperties[i].alg == scheme) {
            return true;
        }
    }
    return false;
}

TSS2_RC create_rsa_key(TSS2_SYS_CONTEXT *sysContext, TPM2_HANDLE primaryHandle, TPM2_HANDLE &rsaHandle, TPM2B_PUBLIC &outPublic, TPM2B_PRIVATE &outPrivate, TSS2L_SYS_AUTH_COMMAND &sessionsData) {
    TPM2B_SENSITIVE_CREATE inSensitive = {};
    TPM2B_PUBLIC inPublic = {};
    TPM2B_DATA outsideInfo = {};
    TPML_PCR_SELECTION creationPCR = {};
    TPM2B_CREATION_DATA creationData = {};
    TPM2B_DIGEST creationHash = {};
    TPMT_TK_CREATION creationTicket = {};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {};
    TPM2B_NAME name = {};  // Declare the name variable
    TPM2_HANDLE temporaryRsaHandle;

    // Set up sensitive data
    inSensitive.size = sizeof(TPM2B_SENSITIVE_CREATE);
    inSensitive.sensitive.userAuth.size = 0;
    inSensitive.sensitive.data.size = 0;

    // Set up public data
    inPublic.size = sizeof(TPM2B_PUBLIC);
    inPublic.publicArea.type = TPM2_ALG_RSA;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH;
    inPublic.publicArea.authPolicy.size = 0;
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.publicArea.unique.rsa.size = 0;

    // Create the RSA key
    TSS2_RC rc = Tss2_Sys_Create(sysContext, primaryHandle, &sessionsData, &inSensitive, &inPublic, &outsideInfo, &creationPCR, &outPrivate, &outPublic, &creationData, &creationHash, &creationTicket, &sessionsDataOut);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    // Load the RSA key
    rc = Tss2_Sys_Load(sysContext, primaryHandle, &sessionsData, &outPrivate, &outPublic, &temporaryRsaHandle, &name, &sessionsDataOut);
    std::cout << "Loaded child key handle (hex): 0x"
              << std::hex << rsaHandle << std::dec << std::endl;

    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    rc = read_public_info(sysContext, temporaryRsaHandle, sessionsData);
    if (rc != TSS2_RC_SUCCESS) {
        std::cout << "failed readout" << std::endl;
    }

    /*rc = Tss2_Sys_EvictControl(sysContext,
                               TPM2_RH_OWNER,   // or correct hierarchy
                               temporaryRsaHandle, // ephemeral
                               &sessionsData,
                               rsaHandle,
                               nullptr);*/
    return rc;
}




// Function to encrypt a string using the created primary key
TSS2_RC encrypt_string_with_primary_key(TSS2_SYS_CONTEXT *sysContext, TPM2_HANDLE rsaHandle, const std::string &plainText, std::vector<uint8_t> &cipherText, TSS2L_SYS_AUTH_COMMAND &sessionsData) {
    TPM2B_PUBLIC_KEY_RSA message = {};
    TPM2B_PUBLIC_KEY_RSA outData = {};
    TPMT_RSA_DECRYPT scheme = {};
    TPM2B_DATA label = {};

    // Set up the message to be encrypted
    message.size = plainText.size();
    memcpy(message.buffer, plainText.c_str(), plainText.size());

    scheme.scheme = TPM2_ALG_NULL;

    // Encrypt the message
    TSS2_RC rc = Tss2_Sys_RSA_Encrypt(sysContext, rsaHandle, &sessionsData, &message, &scheme, &label, &outData, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    // Copy the encrypted data to the output vector
    cipherText.assign(outData.buffer, outData.buffer + outData.size);
    return TSS2_RC_SUCCESS;
}

void test() {
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tctiContext = nullptr;
    TSS2_SYS_CONTEXT  *sysContext  = nullptr;

    // 1) Initialize the TCTI context for Windows TBS (two-call setup)
    size_t tctiSize;
    rc = Tss2_Tcti_Tbs_Init(nullptr, &tctiSize, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error (1) getting TBS TCTI context size: 0x"
                  << std::hex << rc << std::dec << std::endl;
        return;
    }

    tctiContext = (TSS2_TCTI_CONTEXT*)malloc(tctiSize);
    if (!tctiContext) {
        std::cerr << "Error allocating TCTI context." << std::endl;
        return;
    }

    rc = Tss2_Tcti_Tbs_Init(tctiContext, &tctiSize, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error (2) initializing TBS TCTI context: 0x"
                  << std::hex << rc << std::dec << std::endl;
        free(tctiContext);
        return;
    }

    // 2) Initialize the SAPI (SYS) context
    size_t sysSize = Tss2_Sys_GetContextSize(0);
    sysContext = (TSS2_SYS_CONTEXT *)malloc(sysSize);
    if (!sysContext) {
        std::cerr << "Error allocating SYS context." << std::endl;
        free(tctiContext);
        return;
    }
    memset(sysContext, 0, sysSize);

    rc = Tss2_Sys_Initialize(sysContext, sysSize, tctiContext, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error (3) initializing SYS context: 0x"
                  << std::hex << rc << std::dec << std::endl;
        free(tctiContext);
        free(sysContext);
        return;
    }

    // NOTE: We do NOT call Tss2_Sys_Startup on Windows TBS.
    // The TPM is already in the started state thanks to the firmware.

    // 3) OPTIONAL: Attempt to read a known persistent handle (e.g. 0x81010005)
    TPM2_HANDLE handle = 0x81010005;
    TSS2L_SYS_AUTH_COMMAND sessionsData = {
        1, {{TPM2_RS_PW, 0, 0, {0}}}
    };
    TPM2B_PUBLIC outPublic    = {};
    TPM2B_NAME   name         = {};
    TPM2B_NAME   qualifiedName= {};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    rc = Tss2_Sys_ReadPublic(
            sysContext,
            handle,
            &sessionsData,
            &outPublic,
            &name,
            &qualifiedName,
            &sessionsDataOut
    );
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error reading public for handle 0x"
                  << std::hex << handle
                  << " => 0x" << rc << std::dec << std::endl;
        // If you see "tpm:handle(unk):the handle is not correct for the use",
        // that means the TPM does NOT recognize this handle in TBS environment.
    } else {
        // Succeeded. Print outPublic details...
        std::cout << "Successfully read public area of handle 0x"
                  << std::hex << handle << std::dec << std::endl;
        // e.g. show object nameAlg, keyBits, etc.
    }

    // 4) Cleanup
    Tss2_Sys_Finalize(sysContext);
    free(sysContext);
    free(tctiContext);
}


int main() {
    //test();

    // Set the logging level to maximum


    // REAL TPM
    //_putenv("TSS2_TCTI_LOG_LEVEL=TSS2_LOG_LEVEL_DEBUG");

    TSS2_TCTI_CONTEXT *tctiContext = nullptr;
    TSS2_SYS_CONTEXT  *sysContext  = nullptr;
    TSS2_RC rc;
    TPM2_HANDLE primaryHandle = 0x81010007;
    TPM2_HANDLE rsaHandle = 0x81010207;
    TPM2B_PUBLIC outPublic = {};
    TPM2B_NAME name = {};

    TSS2L_SYS_AUTH_COMMAND sessionsData = {1, {{TPM2_RS_PW, 0, 0, {0}}}};

    // Initialize TCTI context for real TPM
    size_t size;
    rc = Tss2_Tcti_Tbs_Init(NULL, &size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error initializing TCTI context: " << rc << std::endl;
        return 1;
    }
    tctiContext = (TSS2_TCTI_CONTEXT*)malloc(size);
    rc = Tss2_Tcti_Tbs_Init(tctiContext, &size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error initializing TCTI context: " << rc << std::endl;
        free(tctiContext);
        return 1;
    }

    rc = Tss2_Tcti_Tbs_Init(tctiContext, &size, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error (2) initializing TBS TCTI context: 0x"
                  << std::hex << rc << std::dec << std::endl;
        free(tctiContext);
        return 1;
    }

    // Initialize SYS context
    size = Tss2_Sys_GetContextSize(0);
    sysContext = (TSS2_SYS_CONTEXT*)malloc(size);
    rc = Tss2_Sys_Initialize(sysContext, size, tctiContext, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error initializing SYS context: " << rc << std::endl;
        free(tctiContext);
        free(sysContext);
        return 1;
    }








    /*TSS2_TCTI_CONTEXT *tctiContext = nullptr;
    TSS2_RC rc;
    TPM2_HANDLE primaryHandle = 0x81010005;
    TPM2B_PUBLIC outPublic = {};
    TPM2B_NAME name = {};

    TSS2L_SYS_AUTH_COMMAND sessionsData = {1, {{TPM2_RS_PW, 0, 0, {0}}}};

    size_t size = 0;

    // 1) Call once with tctiContext = NULL to discover how much to allocate
    rc = Tss2_Tcti_Mssim_Init(nullptr, &size, "host=127.0.0.1,port=2321,port2=2322");
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Failed to get TCTI context size: 0x"
                  << std::hex << rc << std::dec << std::endl;
        return 1;
    }

    // 2) Allocate the TCTI context
    tctiContext = static_cast<TSS2_TCTI_CONTEXT*>(std::calloc(1, size));
    if (!tctiContext) {
        std::cerr << "Error: Failed to allocate TCTI context." << std::endl;
        return 1;
    }

    // 3) Initialize the TCTI context with the same config string
    rc = Tss2_Tcti_Mssim_Init(tctiContext, &size, "host=127.0.0.1,port=2321,port2=2322");
    if (rc != TSS2_RC_SUCCESS) {
        const char *info = Tss2_RC_Decode(rc);
        std::cout << "Error: " << info << std::endl;
        std::cerr << "Tss2_Tcti_Mssim_Init failed: 0x"
                  << std::hex << rc << std::dec << std::endl;
        std::free(tctiContext);
        return 1;
    }

    // The TCTI context is now ready to be passed to Tss2_Sys_Initialize:
    size_t sysCtxSize = Tss2_Sys_GetContextSize(0);
    TSS2_SYS_CONTEXT *sysContext = static_cast<TSS2_SYS_CONTEXT*>(std::calloc(1, sysCtxSize));
    if (!sysContext) {
        std::cerr << "Error allocating sysContext." << std::endl;
        std::free(tctiContext);
        return 1;
    }

    rc = Tss2_Sys_Initialize(sysContext, sysCtxSize, tctiContext, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Tss2_Sys_Initialize failed: 0x"
                  << std::hex << rc << std::dec << std::endl;
        std::free(tctiContext);
        std::free(sysContext);
        return 1;
    }*/



































    list_persistent_handles(sysContext);

    /*rc = create_primary_key(sysContext, primaryHandle, outPublic, name, sessionsData);
    if (!(rc == TSS2_RC_SUCCESS || rc == 332)) { // 332 is the error code for persistent obj already exists
        std::cerr << "Error creating primary key: " << rc << std::endl;
        // decode rc to info text
        const char *info = Tss2_RC_Decode(rc);
        std::cout << "Error: " << info << std::endl;
        Tss2_Sys_Finalize(sysContext);
        free(tctiContext);
        free(sysContext);
        return 1;
    }*/

    // check if RSA encryption scheme is available
    if (!is_scheme_available(sysContext, TPM2_ALG_RSA)) {
        std::cerr << "RSA encryption scheme is not available." << std::endl;
        Tss2_Sys_Finalize(sysContext);
        free(tctiContext);
        free(sysContext);
        return 1;
    }

    // after creating the primary, create a RSA key
    TPM2B_PUBLIC rsaPublic = {};
    TPM2B_PRIVATE rsaPrivate = {};

    rc = create_rsa_key(sysContext, primaryHandle, rsaHandle, rsaPublic, rsaPrivate, sessionsData);
    if (!(rc == TSS2_RC_SUCCESS || rc == 332)) { // 332 is the error code for persistent obj already exists
        std::cerr << "Error creating RSA key: " << rc << std::endl;
        Tss2_Sys_Finalize(sysContext);
        free(tctiContext);
        free(sysContext);
        return 1;
    }

    std::cout << "primaryHandle = 0x"
              << std::hex << primaryHandle
              << std::dec << std::endl;
    std::cout << "rsaHandle = 0x"
              << std::hex << rsaHandle
              << std::dec << std::endl;

    // output RSA key information
    rc = read_public_info(sysContext, rsaHandle, sessionsData);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error: " << rc << std::endl;
        // decode rc to info text
        const char *info = Tss2_RC_Decode(rc);
        std::cout << "Error: " << info << std::endl;
        Tss2_Sys_Finalize(sysContext);
        free(tctiContext);
        free(sysContext);
        return 1;
    }



    // Encrypt a string using the created primary key
    std::string plainText = "Ola";
    std::vector<uint8_t> cipherText;
    rc = encrypt_string_with_primary_key(sysContext, rsaHandle, plainText, cipherText, sessionsData);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Error encrypting string: " << rc << std::endl;
        // decode rc to info text
        const char *info = Tss2_RC_Decode(rc);
        std::cout << "Error: " << info << std::endl;
        Tss2_Sys_Finalize(sysContext);
        free(tctiContext);
        free(sysContext);
        return 1;
    }

    // Output the encrypted data
    std::cout << "Encrypted Data: ";
    for (uint8_t byte : cipherText) {
        std::cout << std::hex << (int)byte << " ";
    }
    std::cout << std::endl;



    /*
    // Check if the primary key info file exists
    if (!read_primary_key_info(primaryHandle, outPublic, name)) {
        // Create the primary key
        rc = create_primary_key(sysContext, primaryHandle, outPublic, name);
        if (rc != TSS2_RC_SUCCESS) {
            std::cerr << "Error creating primary key: " << rc << std::endl;
            Tss2_Sys_Finalize(sysContext);
            free(tctiContext);
            free(sysContext);
            return 1;
        }
        // Write the primary key information to the file
        write_primary_key_info(primaryHandle, outPublic, name);
    } else {
        // Retrieve the primary key from TPM
        rc = read_primary_key_from_tpm(sysContext, primaryHandle, outPublic, name);
        if (rc != TSS2_RC_SUCCESS) {
            std::cerr << "Error reading primary key from TPM: " << rc << std::endl;
            Tss2_Sys_Finalize(sysContext);
            free(tctiContext);
            free(sysContext);
            return 1;
        }
        std::cout << "Primary key information retrieved from TPM." << std::endl;
    }
    */

    // Output primary key information
    std::cout << "Primary Handle: " << primaryHandle << std::endl;
    std::cout << "Name: ";
    for (size_t i = 0; i < name.size; i++) {
        std::cout << std::hex << (int)name.name[i];
    }
    std::cout << std::endl;
    std::cout << "Public Key Type: " << outPublic.publicArea.type << std::endl;
    std::cout << "Name Algorithm: " << outPublic.publicArea.nameAlg << std::endl;
    std::cout << "Object Attributes: " << outPublic.publicArea.objectAttributes << std::endl;
    std::cout << "Auth Policy Size: " << outPublic.publicArea.authPolicy.size << std::endl;
    std::cout << "RSA Key Bits: " << outPublic.publicArea.parameters.rsaDetail.keyBits << std::endl;
    std::cout << "RSA Exponent: " << outPublic.publicArea.parameters.rsaDetail.exponent << std::endl;
    std::cout << "Unique RSA Size: " << outPublic.publicArea.unique.rsa.size << std::endl;

    // Clean up
    Tss2_Sys_Finalize(sysContext);
    free(tctiContext);
    free(sysContext);
    return 0;
}