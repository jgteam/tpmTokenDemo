/**
 * File: AppShell.java
 * Author: Jannis Günsche
 * Description: This class contains the main UI window of the application.
 */
package tpmTokenDemo;

import logger.Logger;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.*;

import java.io.IOException;

public class AppShell {

    private static Shell shell = null;

    // UI elements
    public static Button buttonRefreshPersistentHandles;
    public static Label infoTPMPersitentHandlesLabel;

    public static Label infoTPMPrimaryHandleLabel;
    public static Label infoTPMRSAHandleLabel;
    public static Label infoTokenLocationLabel;

    private AppShell() {
        // Prevent instantiation
    }

    public static Shell getShell(Display display) {

        if (shell != null) {
            return shell;
        }

        shell = new Shell(display);
        shell.setText("TPM Token Storage Proof-of-Concept App");
        shell.setSize(650, 750);

        GridLayout layout = new GridLayout(2, true);
        shell.setLayout(layout);


        // Layouts
        GridData buttonsGridData = new GridData(SWT.END, SWT.CENTER, true, true);
        buttonsGridData.widthHint = 200;
        GridData lastButtonsGridData = new GridData(SWT.END, SWT.TOP, true, false);
        lastButtonsGridData.widthHint = 200;


        // TPM SETUP GROUP
        Group groupSetup = new Group(shell, SWT.NONE);
        groupSetup.setLayout(new GridLayout(2, false));
        groupSetup.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false));
        groupSetup.setText("TPM Setup");

        Label infoTPMManuLabelHeading = new Label(groupSetup, SWT.NONE);
        infoTPMManuLabelHeading.setLayoutData(new GridData(SWT.BEGINNING, SWT.TOP, false, false));
        infoTPMManuLabelHeading.setText("TPM Manufacturer:");

        Label infoTPMManuLabel = new Label(groupSetup, SWT.WRAP);
        infoTPMManuLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        infoTPMManuLabel.setText("n/a");

        Label infoTPMVersionLabelHeading = new Label(groupSetup, SWT.NONE);
        infoTPMVersionLabelHeading.setLayoutData(new GridData(SWT.BEGINNING, SWT.TOP, false, false));
        infoTPMVersionLabelHeading.setText("TPM Version:");

        Label infoTPMVersionLabel = new Label(groupSetup, SWT.WRAP);
        infoTPMVersionLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        infoTPMVersionLabel.setText("n/a");

        Label infoTPMPersitentHandlesLabelHeading = new Label(groupSetup, SWT.NONE);
        infoTPMPersitentHandlesLabelHeading.setLayoutData(new GridData(SWT.BEGINNING, SWT.TOP, false, false));
        infoTPMPersitentHandlesLabelHeading.setText("Found Handles:");

        infoTPMPersitentHandlesLabel = new Label(groupSetup, SWT.WRAP);
        infoTPMPersitentHandlesLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        infoTPMPersitentHandlesLabel.setText("n/a");

        // TPM READOUT BUTTON
        buttonRefreshPersistentHandles = new Button(groupSetup, SWT.PUSH);
        buttonRefreshPersistentHandles.setLayoutData(new GridData(SWT.END, SWT.TOP, true, false, 2, 1));
        buttonRefreshPersistentHandles.setText("Refresh Info");
        buttonRefreshPersistentHandles.setEnabled(false);



        // APP SETUP GROUP
        Group groupAppSetup = new Group(shell, SWT.NONE);
        groupAppSetup.setLayout(new GridLayout(2, false));
        groupAppSetup.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false, 1, 1));
        groupAppSetup.setText("App Setup");

        Label infoTPMPrimaryHandleLabelHeading = new Label(groupAppSetup, SWT.NONE);
        infoTPMPrimaryHandleLabelHeading.setLayoutData(new GridData(SWT.BEGINNING, SWT.TOP, false, false));
        infoTPMPrimaryHandleLabelHeading.setText("Primary-Key Handle:");

        infoTPMPrimaryHandleLabel = new Label(groupAppSetup, SWT.WRAP);
        infoTPMPrimaryHandleLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        infoTPMPrimaryHandleLabel.setText("0x" + Long.toHexString(App.getPrimaryKeyHandle()).toUpperCase());

        Label infoTPMRSAHandleLabelHeading = new Label(groupAppSetup, SWT.NONE);
        infoTPMRSAHandleLabelHeading.setLayoutData(new GridData(SWT.BEGINNING, SWT.TOP, false, false));
        infoTPMRSAHandleLabelHeading.setText("RSA-Key Handle:");

        infoTPMRSAHandleLabel = new Label(groupAppSetup, SWT.WRAP);
        infoTPMRSAHandleLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        infoTPMRSAHandleLabel.setText("0x" + Long.toHexString(App.getRsaKeyHandle()).toUpperCase());

        Label infoTokenLocationLabelHeading = new Label(groupAppSetup, SWT.NONE);
        infoTokenLocationLabelHeading.setLayoutData(new GridData(SWT.BEGINNING, SWT.TOP, false, false, 2, 1));
        infoTokenLocationLabelHeading.setText("Token Storage Location:");

        infoTokenLocationLabel = new Label(groupAppSetup, SWT.WRAP);
        infoTokenLocationLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false, 2, 1));
        infoTokenLocationLabel.setText(App.getTokenStoragePath());

        // CONFIG BUTTON
        Button buttonOpenConfigDialog = new Button(groupAppSetup, SWT.PUSH);
        buttonOpenConfigDialog.setLayoutData(new GridData(SWT.END, SWT.TOP, true, false, 2, 1));
        buttonOpenConfigDialog.setText("Edit Config");



        // TPM ACTIONS GROUP
        Group groupTPMActions = new Group(shell, SWT.NONE);
        groupTPMActions.setLayout(new GridLayout(2, true));
        groupTPMActions.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false, 2, 1));
        groupTPMActions.setText("TPM Actions");

        Label labelTPMSelector = new Label(groupTPMActions, SWT.NONE);
        labelTPMSelector.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false, 2, 1));
        labelTPMSelector.setText("Select TPM:");

        Combo comboTPMSelector = new Combo(groupTPMActions, SWT.READ_ONLY);
        comboTPMSelector.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false, 2, 1));
        comboTPMSelector.setItems(new String[] {"Simulator TPM (host=127.0.0.1; port(tpm)=2321; port(platform)=2322)", "Device TPM (not recommended)"});
        comboTPMSelector.select(0);

        Button setupTPMUse = new Button(groupTPMActions, SWT.PUSH);
        setupTPMUse.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        setupTPMUse.setText("Setup TPM for use");

        Button setupKeys = new Button(groupTPMActions, SWT.PUSH);
        setupKeys.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        setupKeys.setText("Setup Keys");
        setupKeys.setEnabled(false);

        Button readRSAPublic = new Button(groupTPMActions, SWT.PUSH);
        readRSAPublic.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        readRSAPublic.setText("Read RSA Public Key");
        readRSAPublic.setEnabled(false);

        Button endTPMSession = new Button(groupTPMActions, SWT.PUSH);
        endTPMSession.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        endTPMSession.setText("End TPM Session");
        endTPMSession.setEnabled(false);






        // TOKEN ENCRYPT GROUP
        Group groupAddNew = new Group(shell, SWT.NONE);
        groupAddNew.setLayout(new GridLayout(2, false));
        groupAddNew.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true, 2, 1));
        groupAddNew.setText("Token Dropoff");

        Text textNewToken = new Text(groupAddNew, SWT.BORDER | SWT.MULTI | SWT.WRAP | SWT.V_SCROLL);
        GridData textNewTokenGridData = new GridData(SWT.FILL, SWT.FILL, true, true, 2, 1);
        textNewToken.setLayoutData(textNewTokenGridData);
        textNewToken.setText("<Enter new token>");

        Button encryptToken = new Button(groupAddNew, SWT.PUSH);
        encryptToken.setLayoutData(new GridData(SWT.END, SWT.TOP, true, false));
        encryptToken.setText("Encrypt Token");
        encryptToken.setEnabled(false);



        // TOKEN DECRYPT GROUP
        Group groupReadStored = new Group(shell, SWT.NONE);
        groupReadStored.setLayout(new GridLayout(1, false));
        groupReadStored.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false, 2, 1));
        groupReadStored.setText("Token Retrieval");

        Button decryptToken = new Button(groupReadStored, SWT.PUSH);
        decryptToken.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        decryptToken.setText("Decrypt Token");
        decryptToken.setEnabled(false);



        // LOG BUTTON
        Button buttonOpenLog = new Button(shell, SWT.PUSH);
        buttonOpenLog.setLayoutData(new GridData(SWT.END, SWT.TOP, true, false, 2, 1));
        buttonOpenLog.setText("Open Log Viewer");


        // INFO LABEL
        Label infoLabel = new Label(shell, SWT.WRAP);
        infoLabel.setLayoutData(new GridData(SWT.FILL, SWT.BOTTOM, true, false, 2, 1));
        infoLabel.setText("\n\nTPM Demo Application - This application is part of a Bachelor's thesis project by Jannis Günsche. \n\nDisclaimer: This application demonstrates the use of the TPM. Only use this application for demonstration purposes.");


        // LISTENERS

        buttonRefreshPersistentHandles.addSelectionListener(new SelectionListener() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                infoTPMManuLabel.setText(NativeTPMInterface.instance.TPM_get_manufacturer());
                infoTPMVersionLabel.setText(AppLogic.hexStringToAscii(NativeTPMInterface.instance.TPM_get_version()));
                infoTPMPersitentHandlesLabel.setText(NativeTPMInterface.instance.TPM_get_persistent_handles(App.getPrimaryKeyHandle(), App.getRsaKeyHandle()));
                infoTPMPersitentHandlesLabel.getParent().layout();
                groupAppSetup.getParent().layout();
                AppShell.buttonRefreshPersistentHandles.setForeground(App.getDisplay().getSystemColor(SWT.COLOR_BLACK));
            }

            @Override
            public void widgetDefaultSelected(SelectionEvent e) {
                // Do nothing
            }
        });

        buttonOpenConfigDialog.addSelectionListener(new SelectionListener() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                ConfigDialog.open();
            }

            @Override
            public void widgetDefaultSelected(SelectionEvent e) {
                // Do nothing
            }
        });

        setupTPMUse.addSelectionListener(new SelectionListener() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                boolean success = AppLogic.setupTPM(comboTPMSelector.getSelectionIndex());
                if(!success) {
                    MessageBox messageBox = new MessageBox(shell, SWT.ICON_ERROR | SWT.OK);
                    messageBox.setMessage("Error setting up TPM. Check log for details.");
                    messageBox.setText("Error");
                    messageBox.open();
                } else {
                    comboTPMSelector.setEnabled(false);
                    setupTPMUse.setEnabled(false);
                    setupKeys.setEnabled(true);
                    readRSAPublic.setEnabled(true);
                    encryptToken.setEnabled(true);
                    decryptToken.setEnabled(true);
                    endTPMSession.setEnabled(true);
                    buttonRefreshPersistentHandles.setEnabled(true);
                }
            }

            @Override
            public void widgetDefaultSelected(SelectionEvent e) {
                // Do nothing
            }
        });

        setupKeys.addSelectionListener(new SelectionListener() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                boolean success = AppLogic.createKeys();
                if(!success) {
                    MessageBox messageBox = new MessageBox(shell, SWT.ICON_ERROR | SWT.OK);
                    messageBox.setMessage("Error setting up Keys. Check log for details.");
                    messageBox.setText("Error");
                    messageBox.open();
                }
            }

            @Override
            public void widgetDefaultSelected(SelectionEvent e) {
                // Do nothing
            }
        });

        endTPMSession.addSelectionListener(new SelectionListener() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                NativeTPMInterface.instance.TPM_end_session();
                setupTPMUse.setEnabled(false);
                setupKeys.setEnabled(false);
                readRSAPublic.setEnabled(false);
                encryptToken.setEnabled(false);
                decryptToken.setEnabled(false);
                endTPMSession.setEnabled(false);
                buttonRefreshPersistentHandles.setEnabled(false);
            }

            @Override
            public void widgetDefaultSelected(SelectionEvent e) {
                // Do nothing
            }
        });

        encryptToken.addSelectionListener(new SelectionListener() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                boolean success = AppLogic.storeToken(textNewToken.getText());
                if(!success) {
                    MessageBox messageBox = new MessageBox(shell, SWT.ICON_ERROR | SWT.OK);
                    messageBox.setMessage("Error storing token. Check log for details.");
                    messageBox.setText("Error");
                    messageBox.open();
                } else {
                    textNewToken.setText("");
                    MessageBox messageBox = new MessageBox(shell, SWT.ICON_INFORMATION | SWT.OK);
                    messageBox.setMessage("Token stored successfully.");
                    messageBox.setText("Success");
                    messageBox.open();
                }
            }

            @Override
            public void widgetDefaultSelected(SelectionEvent e) {
                // Do nothing
            }
        });

        decryptToken.addSelectionListener(new SelectionListener() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                boolean success = AppLogic.retrieveToken();
                if(!success) {
                    MessageBox messageBox = new MessageBox(shell, SWT.ICON_ERROR | SWT.OK);
                    messageBox.setMessage("Error retrieving token. Check log for details.");
                    messageBox.setText("Error");
                    messageBox.open();
                }
            }

            @Override
            public void widgetDefaultSelected(SelectionEvent e) {
                // Do nothing
            }
        });

        buttonOpenLog.addSelectionListener(new SelectionListener() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                LogDialog.open();
            }

            @Override
            public void widgetDefaultSelected(SelectionEvent e) {
                // Do nothing
            }
        });

        return shell;
    }

    public static void updateConfigLabels() {
        infoTPMPrimaryHandleLabel.setText("0x" + Long.toHexString(App.getPrimaryKeyHandle()).toUpperCase());
        infoTPMRSAHandleLabel.setText("0x" + Long.toHexString(App.getRsaKeyHandle()).toUpperCase());
        infoTokenLocationLabel.setText(App.getTokenStoragePath());
    }

}
