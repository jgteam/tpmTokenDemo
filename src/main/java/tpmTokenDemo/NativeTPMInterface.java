package tpmTokenDemo;

import com.sun.jna.Library;
import com.sun.jna.Native;

public interface NativeTPMInterface extends Library {

    NativeTPMInterface instance = (NativeTPMInterface) Native.load("TPM_API", NativeTPMInterface.class);

    int get_rc();
    String get_error_text(int rc);
    String TPM_get_version();
    String TPM_get_manufacturer();
    int TPM_setup_simulator();
    int TPM_setup_real();
    String TPM_get_persistent_handles(long primaryHandle, long rsaHandle);
    int TPM_check_if_handle_is_free(long handle);
    int TPM_create_primary_key(long persistentHandle);
    int TPM_create_RSA_key(long parentHandle, long persistentHandle);
    String TPM_encrypt(long rsaHandle, String plantext);
    String TPM_decrypt(long rsaHandle, String ciphertext);
    void TPM_end_session();

}
