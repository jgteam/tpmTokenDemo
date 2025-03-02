/**
 * File: LogDialog.java
 * Author: Jannis Günsche
 * Description: This class contains the dialog for viewing the log.
 */
package tpmTokenDemo;

import logger.Logger;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.List;
import org.eclipse.swt.widgets.Shell;

/**
 * The class LogDialog contains the dialog for viewing the log.
 */
public class LogDialog {

    private LogDialog() {
        // Prevent instantiation
    }

    public static void open() {

        Display display = App.getDisplay();
        Shell shell = new Shell(display, SWT.DIALOG_TRIM | SWT.APPLICATION_MODAL | SWT.RESIZE);
        shell.setText("Log Viewer");
        shell.setSize(400, 500);
        shell.setLayout(new GridLayout(1, false));

        Group group = new Group(shell, SWT.NONE);
        group.setText("Log Information");
        group.setLayout(new GridLayout(1, false));
        group.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));

        List logList = new List(group, SWT.BORDER | SWT.V_SCROLL | SWT.H_SCROLL);
        logList.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));

        java.util.List<String> loggedMessages = Logger.getLoggedMessages();
        for (String message : loggedMessages) {
            logList.add(message);
        }

        shell.open();
        while (!shell.isDisposed()) {
            if (!display.readAndDispatch()) {
                display.sleep();
            }

        }

    }

}
