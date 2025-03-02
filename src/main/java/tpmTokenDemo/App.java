/**
 * File: App.java
 * Author: Jannis Günsche
 * Description: This file is the starting point of a proof-of-concept demo application
 *              for tpm token storage. This application is part of
 *              a Bachelor's thesis project.
 */
package tpmTokenDemo;

import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;

public class App {

    private static Display display;
    private static Shell shell;

    private static long PRIMARY_KEY_HANDLE = 0x8100100AL;
    private static long RSA_KEY_HANDLE = 0x8100100BL;

    private static String TOKEN_STORAGE_PATH = "encryptedToken.json";

    private App() {
        // Prevent instantiation
    }

    /**
     * The entry point of application.
     *
     * @param args the input arguments
     */
    public static void main(String[] args) {

        display = new Display();
        shell = AppShell.getShell(display);

        shell.open();

        while (!shell.isDisposed()) {
            if (!display.readAndDispatch()) {
                display.sleep();
            }
        }

        display.dispose();
    }

    /**
     * Gets display.
     *
     * @return the display
     */
    public static Display getDisplay() {
        return display;
    }

    /**
     * Gets shell.
     *
     * @return the shell
     */
    public static Shell getShell() {
        return shell;
    }

    /**
     * Gets primary key handle.
     *
     * @return the primary key handle
     */
    public static long getPrimaryKeyHandle() {
        return PRIMARY_KEY_HANDLE;
    }

    /**
     * Gets rsa key handle.
     *
     * @return the rsa key handle
     */
    public static long getRsaKeyHandle() {
        return RSA_KEY_HANDLE;
    }

    /**
     * Gets token storage path.
     *
     * @return the token storage path
     */
    public static String getTokenStoragePath() {
        return TOKEN_STORAGE_PATH;
    }

    /**
     * Sets primary key handle.
     *
     * @param handle the handle
     */
    public static void setPrimaryKeyHandle(long handle) {
        PRIMARY_KEY_HANDLE = handle;
    }

    /**
     * Sets rsa key handle.
     *
     * @param handle the handle
     */
    public static void setRsaKeyHandle(long handle) {
        RSA_KEY_HANDLE = handle;
    }

    /**
     * Sets token storage path.
     *
     * @param path the path
     */
    public static void setTokenStoragePath(String path) {
        TOKEN_STORAGE_PATH = path;
    }

}