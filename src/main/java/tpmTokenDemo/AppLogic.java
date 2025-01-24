package tpmTokenDemo;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import logger.Logger;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.MessageBox;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

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

    public static String binaryCipherToDecValues(String input) {
        byte[] bytes = input.getBytes();
        // Use a StringBuilder for efficient string concatenation
        StringBuilder hexString = new StringBuilder();

        for (int i = 0; i < bytes.length; i++) {
            // Convert each byte to an unsigned integer
            int unsignedByte = bytes[i] & 0xFF;

            // Convert to hex string and ensure two characters with leading zero if necessary
            String hex = Integer.toHexString(unsignedByte);
            if (hex.length() == 1) {
                hexString.append('0'); // Append leading zero
            }
            hexString.append(hex);

            // Append a space after each byte except the last one
            if (i < bytes.length - 1) {
                hexString.append(' ');
            }
        }

        return hexString.toString().toUpperCase();
    }

    public static String decValuesToBinaryCipher(String hexInput) {
        String[] hexArray = hexInput.split(" ");
        byte[] bytes = new byte[hexArray.length];

        for (int i = 0; i < hexArray.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hexArray[i], 16);
        }

        return new String(bytes);
    }


    public static boolean storeToken(String plaintext) {
        String ciphertext = "";
        try {
            ciphertext = NativeTPMInterface.instance.TPM_encrypt(App.getRsaKeyHandle(), plaintext);
        } catch (Exception ex) {
            Logger.log("AppShell", "Error encrypting token: " + ex.getMessage());
            return false;
        }

        if(ciphertext.isEmpty()) {
            Logger.log("AppShell", "Error encrypting token: Empty ciphertext returned.");
            return false;
        }

        String ciphertextUTF8 = binaryCipherToDecValues(ciphertext);
        Logger.log("AppShell", "Encrypted token: " + ciphertextUTF8);

        // make a json object with the encrypted token using com.fasterxml.jackson.core
        // and write it to the file
        try {
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode tokenJson = mapper.createObjectNode();
            tokenJson.put("schemaVersion", 1);
            tokenJson.put("rsaHandle", App.getRsaKeyHandle());
            tokenJson.put("info", "Encrypted with tpmTokenDemo-Application (github.com/jgteam/tpmTokenDemo)");
            tokenJson.put("encryptedToken", ciphertextUTF8);

            // Write JSON to file
            mapper.writeValue(new File(App.getTokenStoragePath()), tokenJson);
        } catch (Exception ex) {
            Logger.log("AppShell", "Error writing token to file: " + ex.getMessage());
            return false;
        }

        return true;
    }

    public static boolean retrieveToken() {
        File tokenFile = new File(App.getTokenStoragePath());
        if(!tokenFile.exists()) {
            Logger.log("AppShell", "Token file not found.");
            return false;
        }

        ObjectNode tokenJson = null;
        try {
            ObjectMapper mapper = new ObjectMapper();
            tokenJson = (ObjectNode) mapper.readTree(tokenFile);
            if(tokenJson.get("schemaVersion").asInt() != 1) {
                Logger.log("AppShell", "Token file has invalid schema version.");
                return false;
            }
        } catch (Exception ex) {
            Logger.log("AppShell", "Error reading token file: " + ex.getMessage());
            return false;
        }

        if(tokenJson == null) {
            Logger.log("AppShell", "Error reading token file: No JSON object found.");
            return false;
        }

        if(tokenJson.get("rsaHandle").asLong() != App.getRsaKeyHandle()) {
            Logger.log("AppShell", "Token file has different RSA Handle.");
            return false;
        }

        String ciphertext = tokenJson.get("encryptedToken").asText();
        String plaintext = "";

        try {
            plaintext = NativeTPMInterface.instance.TPM_decrypt(App.getRsaKeyHandle(), decValuesToBinaryCipher(ciphertext));
        } catch (Exception ex) {
            Logger.log("AppShell", "Error decrypting token: " + ex.getMessage());
            return false;
        }

        Logger.log("AppShell", "Decrypted token: " + plaintext);
        TokenViewerDialog dialog = new TokenViewerDialog("Decrypted Token", plaintext.toCharArray());
        dialog.open();

        return true;
    }

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
}
