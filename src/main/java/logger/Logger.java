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

    // Time Measurements

    private static List<Long> times = new ArrayList<>();

    public static void logTime(long time) {
        System.out.println("Added Time: " + time + "ms");
        times.add(time);
    }

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

        return "[Decryption Times]\n   Number of times measured: " + n + "\n\n" +
                "   Biggest time: " + max + "ms\n" +
                "   Smallest time: " + min + "ms\n" +
                "   Median time: " + median + "ms\n" +
                "   Average time: " + sum / n + "ms";
    }
}
