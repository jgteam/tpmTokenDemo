/**
 * File: ConfigDialog.java
 * Author: Jannis Günsche
 * Description: This class contains the configuration dialog of the application.
 */
package tpmTokenDemo;

import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.*;

/**
 * The class ConfigDialog contains the configuration dialog of the application.
 */
public class ConfigDialog {

    private ConfigDialog() {
        // Prevent instantiation
    }

    private static Button saveButton;

    /**
     * Open the dialog.
     */
    public static void open() {

        Display display = App.getDisplay();
        Shell shell = new Shell(display, SWT.DIALOG_TRIM | SWT.APPLICATION_MODAL | SWT.RESIZE);
        shell.setText("Config Dialog");
        shell.setSize(400, 400);
        shell.setLayout(new GridLayout(1, false));

        Group group = new Group(shell, SWT.NONE);
        group.setText("Config");
        group.setLayout(new GridLayout(1, false));
        group.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));

        // Primary Handle
        Label primaryHandleLabel = new Label(group, SWT.NONE);
        primaryHandleLabel.setText("Primary Handle:");
        Text primaryHandleText = new Text(group, SWT.BORDER);
        primaryHandleText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        primaryHandleText.setText(String.valueOf(App.getPrimaryKeyHandle()));
        Label primaryHandleLabelHEX = new Label(group, SWT.NONE);
        primaryHandleLabelHEX.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false, 2, 1));
        primaryHandleLabelHEX.setText("HEX Translation:  0x" + Long.toHexString(Long.parseLong(primaryHandleText.getText())).toUpperCase() + "\n");

        primaryHandleText.addListener(SWT.Modify, event -> {
            try {
                primaryHandleLabelHEX.setText("HEX Translation:  0x" + Long.toHexString(Long.parseLong(primaryHandleText.getText())).toUpperCase() + "\n");
                saveButton.setEnabled(true);
            } catch (Exception e) {
                saveButton.setEnabled(false);
            }
            });

        // RSA Handle
        Label rsaHandleLabel = new Label(group, SWT.NONE);
        rsaHandleLabel.setText("RSA Handle:");
        Text rsaHandleText = new Text(group, SWT.BORDER);
        rsaHandleText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        rsaHandleText.setText(String.valueOf(App.getRsaKeyHandle()));
        Label rsaHandleLabelHEX = new Label(group, SWT.NONE);
        rsaHandleLabelHEX.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false, 2, 1));
        rsaHandleLabelHEX.setText("HEX Translation:  0x" + Long.toHexString(Long.parseLong(rsaHandleText.getText())).toUpperCase() + "\n");

        rsaHandleText.addListener(SWT.Modify, event -> {
            try {
                rsaHandleLabelHEX.setText("HEX Translation:  0x" + Long.toHexString(Long.parseLong(rsaHandleText.getText())).toUpperCase() + "\n");
                saveButton.setEnabled(true);
            } catch (Exception e) {
                saveButton.setEnabled(false);
            }
        });

        // Token Storage Location
        Label tokenStorageLabel = new Label(group, SWT.NONE);
        tokenStorageLabel.setText("Token Storage Location:");
        Text tokenStorageText = new Text(group, SWT.BORDER);
        tokenStorageText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        tokenStorageText.setText(App.getTokenStoragePath());

        Label handleStorageInfo = new Label(group, SWT.WRAP);
        handleStorageInfo.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false, 2, 1));
        handleStorageInfo.setText("\n\nNote: The persistent storage handle range for TPM 2.0 is 0x81000000 to 0x81FFFFFF.");

        // Save Button
        saveButton = new Button(group, SWT.PUSH);
        saveButton.setText("Save");
        saveButton.setLayoutData(new GridData(SWT.END, SWT.BOTTOM, true, true, 2, 1));
        saveButton.addListener(SWT.Selection, event -> {
            App.setPrimaryKeyHandle(Long.parseLong(primaryHandleText.getText()));
            App.setRsaKeyHandle(Long.parseLong(rsaHandleText.getText()));
            App.setTokenStoragePath(tokenStorageText.getText());
            AppShell.updateConfigLabels();
            shell.close();
        });


        shell.open();
        while (!shell.isDisposed()) {
            if (!display.readAndDispatch()) {
                display.sleep();
            }

        }

    }

}
