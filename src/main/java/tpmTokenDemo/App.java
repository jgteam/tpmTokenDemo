package tpmTokenDemo;

import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import tpmTokenDemo.AppShell;


public class App {

    private static Display display;
    private static Shell shell;

    // Change your Key-Handles here if needed, but be careful to not use addresses
    // that are already in use by the System when using a real TPM
    private static long PRIMARY_KEY_HANDLE = 0x8100100AL;
    private static long RSA_KEY_HANDLE = 0x8100100BL;

    private static String TOKEN_STORAGE_PATH = "encryptedToken.json";

    private App() {
        // Prevent instantiation
    }

    public static void main(String[] args) {

        display = new Display();
        shell = AppShell.getShell(display);

        // CODE TO EXECUTE ON START

        shell.open();


        while (!shell.isDisposed()) {
            if (!display.readAndDispatch()) {
                display.sleep();
            }
        }

        display.dispose();
    }

    public static Display getDisplay() {
        return display;
    }

    public static Shell getShell() {
        return shell;
    }

    public static long getPrimaryKeyHandle() {
        return PRIMARY_KEY_HANDLE;
    }

    public static long getRsaKeyHandle() {
        return RSA_KEY_HANDLE;
    }

    public static String getTokenStoragePath() {
        return TOKEN_STORAGE_PATH;
    }

    public static void setPrimaryKeyHandle(long handle) {
        PRIMARY_KEY_HANDLE = handle;
    }

    public static void setRsaKeyHandle(long handle) {
        RSA_KEY_HANDLE = handle;
    }

    public static void setTokenStoragePath(String path) {
        TOKEN_STORAGE_PATH = path;
    }

}