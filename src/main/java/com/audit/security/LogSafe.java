package com.audit.security;

/** Neutralises caller-controlled text before it is logged (blocks log injection via CR/LF). */
public final class LogSafe {

    private LogSafe() {
    }

    public static String clean(String value) {
        if (value == null) {
            return "null";
        }
        String flat = value.replaceAll("[\\r\\n\\t]", "_");
        return flat.length() > 128 ? flat.substring(0, 128) + "..." : flat;
    }
}
