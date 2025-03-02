/**
 * File: Logger.java
 * Author: Jannis Günsche
 * Description: This file is for the logging functionality of the application.
 */

package logger;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * The Logger class is for the logging functionality of the application.
 */
public class Logger {

    private static Logger instance = null;

    // List of logged messages
    private static List<String> loggedMessages = new ArrayList<>();

    private Logger() {
        // Prevent instantiation
    }

    /**
     * Method for logging messages.
     *
     * @param className the class name of the calling class
     * @param message   the message
     */
    public static void log(String className, String message) {
        System.out.println("[" + className + "] " + message);
        loggedMessages.add("[" + className + "] " + message);
    }

    /**
     * Gets logged messages.
     *
     * @return the logged messages
     */
    public static List<String> getLoggedMessages() {
        return loggedMessages;
    }

    // Logic for Time Measurement below

    // List of measured times
    private static List<Long> times = new ArrayList<>();

    /**
     * Logs time.
     *
     * @param time the time
     */
    public static void logTime(long time) {
        System.out.println("Added Time: " + time + "ms");
        times.add(time);
    }

    /**
     * Gets time report.
     *
     * @return the time report
     */
    public static String getTimeReport() {
        int n = times.size();
        if (n == 0) {
            return "No times measured";
        }

        long min = Long.MAX_VALUE;
        long max = Long.MIN_VALUE;
        long sum = 0;

        for (long time : times) {
            if (time < min) {
                min = time;
            }
            if (time > max) {
                max = time;
            }
            sum += time;
        }

        long median;
        if (n % 2 == 0) {
            median = (times.get(n / 2 - 1) + times.get(n / 2)) / 2;
        } else {
            median = times.get(n / 2);
        }

        writeTimesToLog();

        return "[Decryption Times]\n   Number of times measured: " + n + "\n\n" +
                "   Biggest time: " + max + "ms\n" +
                "   Smallest time: " + min + "ms\n" +
                "   Median time: " + median + "ms\n" +
                "   Average time: " + sum / n + "ms\n\n\n" +
                "Full list of times written to latestTimes.log";
    }

    private static void writeTimesToLog() {
        try {
            FileWriter writer = new FileWriter("latestTimes.log");
            for (long time : times) {
                writer.write(time + "\n");
            }
            writer.close();
        } catch (IOException e) {
            Logger.log("Logger", "Error writing times to log: " + e.getMessage());
        }
    }
}
