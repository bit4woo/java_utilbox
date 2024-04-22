package com.bit4woo.utilbox.utils;

import java.util.List;

public class EmailUtils {
    public static final String GREP_REGEX_EMAIL = "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+";

    public static final String VALID_REGEX_EMAIL = "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$";//TODO Check

    public static List<String> grepEmail(String text) {
        return TextUtils.grepWithRegex(text, GREP_REGEX_EMAIL);
    }


    public static boolean isValidEmail(String text) {
        return TextUtils.isRegexMatch(text, VALID_REGEX_EMAIL);
    }
}
