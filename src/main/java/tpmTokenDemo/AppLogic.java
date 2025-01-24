package tpmTokenDemo;

import logger.Logger;
import org.eclipse.swt.SWT;

public class AppLogic {

    private AppLogic() {
        // Prevent instantiation
    }

    public static boolean setupTPM() {
        int rc = 0;

        rc = NativeTPMInterface.instance.TPM_setup_simulator();
        if( rc != 0 ) {
            Logger.log("AppLogic", "Error setting up TPM Simulator: " + NativeTPMInterface.instance.get_error_text(rc));
            return false;
        }

        AppShell.buttonRefreshPersistentHandles.setForeground(App.getDisplay().getSystemColor(SWT.COLOR_RED));
        return true;
    }

    public static boolean createKeys() {
        int rc = 0;

        rc = NativeTPMInterface.instance.TPM_check_if_handle_is_free(App.getPrimaryKeyHandle());
        if( rc == 0 ) {
            Logger.log("AppLogic", "Primary Key Handle is not in use. Creating new Primary Key...");

            rc = NativeTPMInterface.instance.TPM_create_primary_key(App.getPrimaryKeyHandle());
            if( rc != 0 ) {
                Logger.log("AppLogic", "Error creating Primary Key: " + NativeTPMInterface.instance.get_error_text(rc));
                return false;
            }

            AppShell.buttonRefreshPersistentHandles.setForeground(App.getDisplay().getSystemColor(SWT.COLOR_RED));

        } else {
            Logger.log("AppLogic", "Primary Key Handle is already in use. Skipping creation...");
            rc = 0; // Handle already exists. Resetting rc.
        }

        rc = NativeTPMInterface.instance.TPM_check_if_handle_is_free(App.getRsaKeyHandle());
        if( rc == 0 ) {
            Logger.log("AppLogic", "RSA Key Handle is not in use. Creating new RSA Key...");

            rc = NativeTPMInterface.instance.TPM_create_RSA_key(App.getPrimaryKeyHandle(), App.getRsaKeyHandle());
            if( rc != 0 ) {
                Logger.log("AppLogic", "Error creating RSA Key: " + NativeTPMInterface.instance.get_error_text(rc));
                return false;
            }

            AppShell.buttonRefreshPersistentHandles.setForeground(App.getDisplay().getSystemColor(SWT.COLOR_RED));

        } else {
            Logger.log("AppLogic", "RSA Key Handle is already in use. Skipping creation...");
            rc = 0; // Handle already exists. Resetting rc.
        }

        return true;
    }

}
