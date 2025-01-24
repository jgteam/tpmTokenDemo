package tpmTokenDemo;

import com.sun.jna.Library;
import com.sun.jna.Native;

public interface NativeTPMInterface extends Library {

    NativeTPMInterface instance = (NativeTPMInterface) Native.load("TPM_API", NativeTPMInterface.class);

    int get_rc();
    String get_error_text(int rc);
    int TPM_setup_simulator();
    String TPM_get_persistent_handles(long primaryHandle, long rsaHandle);
    int TPM_check_if_handle_is_free(long handle);
    int TPM_create_primary_key(long persistentHandle);
    int TPM_create_RSA_key(long parentHandle, long persistentHandle);

}
