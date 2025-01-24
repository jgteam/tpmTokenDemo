package logger;

import java.util.ArrayList;
import java.util.List;

public class Logger {

        private static Logger instance = null;

        private static List<String> loggedMessages = new ArrayList<>();

        private Logger() {
            // Prevent instantiation
        }

        public static void log(String className, String message) {
            System.out.println("[" + className + "] " + message);
            loggedMessages.add("[" + className + "] " + message);
        }

        public static List<String> getLoggedMessages() {
            return loggedMessages;
        }
}
