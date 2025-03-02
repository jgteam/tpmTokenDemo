/**
 * File: NativeTPMInterface.java
 * Author: Jannis Günsche
 * Description: This interface is for the native TPM interface.
 */
package tpmTokenDemo;

import com.sun.jna.Library;
import com.sun.jna.Native;

/**
 * The interface Native tpm.
 */
public interface NativeTPMInterface extends Library {

    /**
     * The constant instance.
     */
    NativeTPMInterface instance = (NativeTPMInterface) Native.load("TPM_API", NativeTPMInterface.class);

    /**
     * Gets rc.
     *
     * @return the rc
     */
    int get_rc();

    /**
     * Gets error text.
     *
     * @param rc the rc
     * @return the error text
     */
    String get_error_text(int rc);

    /**
     * Gets loaded rsa key info.
     *
     * @return the loaded rsa key info
     */
    String get_loaded_rsa_key_info();

    /**
     * Tpm get version string.
     *
     * @return the version string
     */
    String TPM_get_version();

    /**
     * Tpm get manufacturer string.
     *
     * @return the manufacturer string
     */
    String TPM_get_manufacturer();

    /**
     * Tpm setup simulator int.
     *
     * @return rc
     */
    int TPM_setup_simulator();

    /**
     * Tpm setup real int.
     *
     * @return rc
     */
    int TPM_setup_real();

    /**
     * Tpm get persistent handles string.
     *
     * @param primaryHandle the primary handle
     * @param rsaHandle     the rsa handle
     * @return persistent handles string
     */
    String TPM_get_persistent_handles(long primaryHandle, long rsaHandle);

    /**
     * Tpm check if handle is free int.
     *
     * @param handle the handle
     * @return rc
     */
    int TPM_check_if_handle_is_free(long handle);

    /**
     * Tpm create primary key int.
     *
     * @param persistentHandle the persistent handle
     * @return rc
     */
    int TPM_create_primary_key(long persistentHandle);

    /**
     * Tpm create rsa key int.
     *
     * @param parentHandle     the parent handle
     * @param persistentHandle the persistent handle
     * @return rc
     */
    int TPM_create_RSA_key(long parentHandle, long persistentHandle);

    /**
     * Tpm encrypt string.
     *
     * @param rsaHandle the rsa handle
     * @param plantext  the plantext
     * @return the encrypted string
     */
    String TPM_encrypt(long rsaHandle, String plantext);

    /**
     * Tpm decrypt string.
     *
     * @param rsaHandle  the rsa handle
     * @param ciphertext the ciphertext
     * @return the decrypted string
     */
    String TPM_decrypt(long rsaHandle, String ciphertext);

    /**
     * Tpm end session.
     */
    void TPM_end_session();

}
