/**
 * File: AppShell.java
 * Author: Jannis Günsche
 * Description: This class contains the main UI window of the application.
 */
package tpmTokenDemo;

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
    public static Combo combo;

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
        infoTPMManuLabel.setText("XXXX");

        Label infoTPMManuVersionLabelHeading = new Label(groupSetup, SWT.NONE);
        infoTPMManuVersionLabelHeading.setLayoutData(new GridData(SWT.BEGINNING, SWT.TOP, false, false));
        infoTPMManuVersionLabelHeading.setText("TPM Manu. Version:");

        Label infoTPMManuVersionLabel = new Label(groupSetup, SWT.WRAP);
        infoTPMManuVersionLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        infoTPMManuVersionLabel.setText("XXXX");

        Label infoTPMVersionLabelHeading = new Label(groupSetup, SWT.NONE);
        infoTPMVersionLabelHeading.setLayoutData(new GridData(SWT.BEGINNING, SWT.TOP, false, false));
        infoTPMVersionLabelHeading.setText("TPM Version:");

        Label infoTPMVersionLabel = new Label(groupSetup, SWT.WRAP);
        infoTPMVersionLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        infoTPMVersionLabel.setText("XXXX");

        Label infoTPMPersitentHandlesLabelHeading = new Label(groupSetup, SWT.NONE);
        infoTPMPersitentHandlesLabelHeading.setLayoutData(new GridData(SWT.BEGINNING, SWT.TOP, false, false));
        infoTPMPersitentHandlesLabelHeading.setText("Found Handles:");

        Label infoTPMPersitentHandlesLabel = new Label(groupSetup, SWT.WRAP);
        infoTPMPersitentHandlesLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        infoTPMPersitentHandlesLabel.setText("0x00000000\n0x00000000\n0x00000000\n0x00000000");

        // TPM READOUT BUTTON
        Button buttonRefreshPersistentHandles = new Button(groupSetup, SWT.PUSH);
        buttonRefreshPersistentHandles.setLayoutData(new GridData(SWT.END, SWT.TOP, true, false, 2, 1));
        buttonRefreshPersistentHandles.setText("Refresh List of Handles");

        buttonRefreshPersistentHandles.addSelectionListener(new SelectionListener() {
            @Override
            public void widgetSelected(SelectionEvent e) {

            }

            @Override
            public void widgetDefaultSelected(SelectionEvent e) {
                // Do nothing
            }
        });


        // APP SETUP GROUP
        Group groupAppSetup = new Group(shell, SWT.NONE);
        groupAppSetup.setLayout(new GridLayout(2, false));
        groupAppSetup.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false, 1, 1));
        groupAppSetup.setText("App Setup");

        Label infoTPMPrimaryHandleLabelHeading = new Label(groupAppSetup, SWT.NONE);
        infoTPMPrimaryHandleLabelHeading.setLayoutData(new GridData(SWT.BEGINNING, SWT.TOP, false, false));
        infoTPMPrimaryHandleLabelHeading.setText("Primary-Key Handle:");

        Label infoTPMPrimaryHandleLabel = new Label(groupAppSetup, SWT.WRAP);
        infoTPMPrimaryHandleLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        infoTPMPrimaryHandleLabel.setText("0x" + Long.toHexString(App.getPrimaryKeyHandle()).toUpperCase());

        Label infoTPMRSAHandleLabelHeading = new Label(groupAppSetup, SWT.NONE);
        infoTPMRSAHandleLabelHeading.setLayoutData(new GridData(SWT.BEGINNING, SWT.TOP, false, false));
        infoTPMRSAHandleLabelHeading.setText("RSA-Key Handle:");

        Label infoTPMRSAHandleLabel = new Label(groupAppSetup, SWT.WRAP);
        infoTPMRSAHandleLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        infoTPMRSAHandleLabel.setText("0x" + Long.toHexString(App.getRsaKeyHandle()).toUpperCase());

        Label infoTPMHandlesInfoLabel = new Label(groupAppSetup, SWT.WRAP);
        infoTPMHandlesInfoLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false, 2, 1));
        infoTPMHandlesInfoLabel.setText("Note: The handles can be changed in the source code of this app.\n");

        Label infoTokenLocationLabelHeading = new Label(groupAppSetup, SWT.NONE);
        infoTokenLocationLabelHeading.setLayoutData(new GridData(SWT.BEGINNING, SWT.TOP, false, false, 2, 1));
        infoTokenLocationLabelHeading.setText("Token Storage Location:");

        Label infoTokenLocationLabel = new Label(groupAppSetup, SWT.WRAP);
        infoTokenLocationLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false, 2, 1));
        infoTokenLocationLabel.setText(App.getTokenStoragePath());

        Label infoTokenLocationInfoLabel = new Label(groupAppSetup, SWT.WRAP);
        infoTokenLocationInfoLabel.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false, 2, 1));
        infoTokenLocationInfoLabel.setText("Note: The token storage location can be changed with the 1st argument of the app.");




        // TPM ACTIONS GROUP
        Group groupTPMActions = new Group(shell, SWT.NONE);
        groupTPMActions.setLayout(new GridLayout(2, true));
        groupTPMActions.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false, 2, 1));
        groupTPMActions.setText("TPM Actions");

        Button setupTPMUse = new Button(groupTPMActions, SWT.PUSH);
        setupTPMUse.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        setupTPMUse.setText("Setup TPM for use");

        Button readRSAPublic = new Button(groupTPMActions, SWT.PUSH);
        readRSAPublic.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        readRSAPublic.setText("Read RSA Public Key");
        readRSAPublic.setEnabled(false);






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





        return shell;
    }

}
