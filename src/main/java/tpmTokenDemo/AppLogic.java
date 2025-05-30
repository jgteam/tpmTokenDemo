/**
 * File: AppLogic.java
 * Author: Jannis Günsche
 * Description: This class contains the logic of the application.
 */


package tpmTokenDemo;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import logger.Logger;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.MessageBox;

import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;

/**
 * This class contains the logic of the application.
 */
public class AppLogic {

    private AppLogic() {
        // Prevent instantiation
    }

    /**
     * Setup of the TPM.
     *
     * @param selectedTPM the selected tpm (= 0 for simulator, = 1 for real device)
     * @return true if successful
     */
    public static boolean setupTPM(int selectedTPM) {
        boolean useSimulator = selectedTPM == 0;

        // return code
        int rc = 0;

        if(useSimulator) {
            Logger.log("AppLogic", "Using TPM Simulator...");
            rc = NativeTPMInterface.instance.TPM_setup_simulator();
        } else {
            Logger.log("AppLogic", "Using TPM Device...");
            rc = NativeTPMInterface.instance.TPM_setup_real();
        }
        if( rc != 0 ) {
            Logger.log("AppLogic", "Error setting up TPM Simulator: " + NativeTPMInterface.instance.get_error_text(rc));
            return false;
        }

        AppShell.buttonRefreshPersistentHandles.setForeground(App.getDisplay().getSystemColor(SWT.COLOR_RED));
        return true;
    }

    /**
     * Create the keys with the TPM.
     *
     * @return true if successful
     */
    public static boolean createKeys() {
        int rc = 0;

        // Create Primary Key
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

        // Create RSA Key
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

    /**
     * Clean up of the cipher text for better readability and saving to file.
     *
     * @param input cipher text
     * @return cleaned up cipher text
     */
    public static String cleanUpCipher(String input) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            if (i % 2 == 0 && i > 0) {
                stringBuilder.append(' ');
            }
            stringBuilder.append(input.charAt(i));
        }
        return stringBuilder.toString().toUpperCase();
    }

    /**
     * Put back cipher text to original format.
     *
     * @param input cleaned up cipher text
     * @return original cipher text
     */
    public static String putBackCipher(String input) {
        return input.replace(" ", "");
    }

    /**
     * Store token with TPM encryption in file.
     *
     * @param plaintext the plaintext
     * @return true if successful
     */
    public static boolean storeToken(String plaintext) {

        // Split the token into parts of better processing with TPM
        int maxLen = 256; // max length of Tss2_MU_TPM2B_PUBLIC_KEY_RSA_Marshal is 512
        int len = plaintext.length();
        int parts = len / maxLen;
        if(len % maxLen != 0) {
            parts++;
        }

        String[] tokenParts = new String[parts];
        for(int i = 0; i < parts; i++) {
            int start = i * maxLen;
            int end = Math.min((i + 1) * maxLen, len);
            tokenParts[i] = plaintext.substring(start, end);
        }

        // encrypt token parts
        String[] ciphertextParts = new String[parts];
        String[] ciphertextPartsReadable = new String[parts];
        for(int i = 0; i < parts; i++) {
            try {
                ciphertextParts[i] = NativeTPMInterface.instance.TPM_encrypt(App.getRsaKeyHandle(), tokenParts[i]);
                ciphertextPartsReadable[i] = cleanUpCipher(ciphertextParts[i]);
            } catch (Exception ex) {
                Logger.log("AppLogic", "Error encrypting token: " + ex.getMessage());
                return false;
            }
        }

        Logger.log("AppLogic", "Encrypted token: " + String.join(" ", ciphertextPartsReadable));

        // writing encrypted token to file
        try {
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode tokenJson = mapper.createObjectNode();
            tokenJson.put("schemaVersion", 1);
            tokenJson.put("rsaHandle", App.getRsaKeyHandle());
            tokenJson.put("info", "Encrypted with tpmTokenDemo-Application (github.com/jgteam/tpmTokenDemo)");
            tokenJson.putArray("encryptedTokenParts");
            for(int i = 0; i < parts; i++) {
                tokenJson.withArray("encryptedTokenParts").add(ciphertextPartsReadable[i]);
            }

            // Write JSON to file
            mapper.writeValue(new File(App.getTokenStoragePath()), tokenJson);
        } catch (Exception ex) {
            Logger.log("AppLogic", "Error writing token to file: " + ex.getMessage());
            return false;
        }

        return true;
    }

    /**
     * Overloading method for storing token with TPM encryption in file and default parameters. (No time measurement, no dialog)
     *
     * @return true if successful
     */
    public static boolean retrieveToken() {
        return retrieveToken(false, 1);
    }

    /**
     * Overloading Method for retrieving a token. Can be used to measure the time of the decryption process and to open a dialog with the token.
     *
     * @param measureTime true if the time should be measured
     * @param count       the count of retrievals
     * @return true if successful
     */
    public static boolean retrieveToken(boolean measureTime, int count) {
        if(count < 1) { // Invalid count
            Logger.log("AppLogic", "Invalid count.");
            return false;
        } else if(count == 1) { // Single retrieval
            return retrieveToken(measureTime, true);
        } else { // Multiple retrievals
            boolean lastResult = false;
            for(int i = 0; i < count; i++) {
                lastResult = retrieveToken(measureTime, false);
                Logger.log("AppLogic", "Retrieval " + (i + 1) + " of " + count + ": " + (lastResult ? "Success" : "Failed"));

                AppShell.decryptTokenMeasure.setText("Progress: " + (i + 1) + " of " + count);
                AppShell.decryptTokenMeasure.getParent().layout();
            }
            MessageBox messageBox = new MessageBox(App.getShell(), SWT.ICON_INFORMATION | SWT.OK);
            messageBox.setText("Measuring finished");
            messageBox.setMessage("The measurement is finished. Please check the log or report for details.");
            messageBox.open();
            AppShell.decryptTokenMeasure.setText("Decrypt Token (measure time)");
            return true;
        }
    }

    /**
     * Method for retrieving a token. Can be used to measure the time of the decryption process and to open a dialog with the token.
     *
     * @param measureTime true if the time should be measured
     * @param openDialog  true if the token should be displayed in a dialog after retrieval
     * @return true if successful
     */
    public static boolean retrieveToken(boolean measureTime, boolean openDialog) {
        File tokenFile = new File(App.getTokenStoragePath());
        if(!tokenFile.exists()) {
            Logger.log("AppLogic", "Token file not found.");
            return false;
        }

        ObjectNode tokenJson = null;
        try {
            ObjectMapper mapper = new ObjectMapper();
            tokenJson = (ObjectNode) mapper.readTree(tokenFile);
            if(tokenJson.get("schemaVersion").asInt() != 1) {
                Logger.log("AppLogic", "Token file has invalid schema version.");
                return false;
            }
        } catch (Exception ex) {
            Logger.log("AppLogic", "Error reading token file: " + ex.getMessage());
            return false;
        }

        if(tokenJson == null) {
            Logger.log("AppLogic", "Error reading token file: No JSON object found.");
            return false;
        }

        if(tokenJson.get("rsaHandle").asLong() != App.getRsaKeyHandle()) {
            Logger.log("AppLogic", "Token file has different RSA Handle.");
            return false;
        }

        String[] ciphertextParts = new String[tokenJson.withArray("encryptedTokenParts").size()];
        for (int i = 0; i < ciphertextParts.length; i++) {
            ciphertextParts[i] = tokenJson.withArray("encryptedTokenParts").get(i).asText();
        }

        Instant start = null;
        Instant end = null;

        // decrypt token parts
        StringBuilder plaintextBuilder = new StringBuilder();
        try {
            if(measureTime) {
                start = Instant.now();
            }
            for (String part : ciphertextParts) {
                plaintextBuilder.append(NativeTPMInterface.instance.TPM_decrypt(App.getRsaKeyHandle(), putBackCipher(part)));
            }
            if(measureTime) {
                end = Instant.now();
            }
        } catch (Exception ex) {
            Logger.log("AppLogic", "Error decrypting token: " + ex.getMessage());
            return false;
        }

        // logging the time and showing a message box if openDialog is true
        if(measureTime && start != null && end != null) {
            long timeElapsed = Duration.between(start, end).toMillis();
            Logger.log("AppLogic", "Decryption took " + timeElapsed + " ms.");
            Logger.logTime(timeElapsed);
            if(openDialog) {
                MessageBox messageBox = new MessageBox(App.getShell(), SWT.ICON_INFORMATION | SWT.OK);
                messageBox.setText("Decryption Time");
                messageBox.setMessage("Decryption took " + timeElapsed + " ms.");
                messageBox.open();
            }
        }

        String plaintext = plaintextBuilder.toString();

        Logger.log("AppLogic", "Decrypted token: " + plaintext);
        TokenViewerDialog dialog = new TokenViewerDialog("Decrypted Token", plaintext.toCharArray());
        // show dialog if openDialog is true
        if(openDialog) dialog.open();

        return true;
    }

    /**
     * Decode and prettify token string.
     *
     * @param token the token
     * @return the string
     */
    public static String decodeAndPrettifyToken(char[] token) {
        // Expecting a valid 3-Part JWT token

        try {
            // Split into 3 parts
            String tokenString = new String(token);
            String[] parts = tokenString.split("\\.");

            // decode base 64
            String[] decodedToken = new String[parts.length];
            for (int i = 0; i < 2; i++) {
                decodedToken[i] = new String(java.util.Base64.getDecoder().decode(parts[i]));
            }

            String decodedTokenPretty = "";
            // use jackson json parser to prettify
            for (int i = 0; i < 3; i++) {
                if(i == 2) {
                    // Signature-Case
                    decodedTokenPretty += "Signature: " + parts[i];
                    continue;
                }

                try {
                    ObjectMapper mapper = new ObjectMapper();
                    Object json = mapper.readValue(decodedToken[i], Object.class);
                    decodedTokenPretty += mapper.writerWithDefaultPrettyPrinter().writeValueAsString(json) + "\n\n";
                } catch (IOException e) {
                    Logger.log("AppLogic", "Error decoding token: " + e.getMessage());
                }
            }

            return decodedTokenPretty;
        } catch (Exception e) {
            Logger.log("AppLogic", "Error decoding token: " + e.getMessage());
            return "[ Error decoding token ]";
        }
    }

    /**
     * Hex string to ascii string.
     *
     * @param hexString the hex string
     * @return the  ascii string
     */
    public static String hexStringToAscii(String hexString) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hexString.length(); i += 2) {
            String str = hexString.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }
}
