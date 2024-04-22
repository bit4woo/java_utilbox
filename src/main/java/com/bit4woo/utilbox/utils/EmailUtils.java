package com.bit4woo.utilbox.utils;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EmailUtils {

    @Deprecated //从burp的Email addresses disclosed这个issue中提取，废弃这个
    public static Set<String> grepEmail(String httpResponse) {
        Set<String> Emails = new HashSet<>();
        final String REGEX_EMAIL = "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+";

        Pattern pDomainNameOnly = Pattern.compile(REGEX_EMAIL);
        Matcher matcher = pDomainNameOnly.matcher(httpResponse);
        while (matcher.find()) {//多次查找
            Emails.add(matcher.group());
            System.out.println(matcher.group());
        }

        return Emails;
    }


    //public static final String REGEX_EMAIL = "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z]{2,6}";
    public static final String REGEX_EMAIL = "[a-zA-Z0-9_.+-]+@[[a-zA-Z0-9-]+\\.]+[a-zA-Z]{2,6}";

    /**
     * 从burp的Email addresses disclosed这个issue中提取，废弃这个
     * DomainPanel.collectEmails()，可以从issue中提取Email，但是不是实时的，只有search或者fresh的时候才会触发。
     */
    public static Set<String> grepEmail(String httpResponse) {
        Set<String> Emails = new HashSet<>();

        Pattern pDomainNameOnly = Pattern.compile(REGEX_EMAIL);
        Matcher matcher = pDomainNameOnly.matcher(httpResponse);
        while (matcher.find()) {//多次查找
            String item = matcher.group();
            if (DomainUtils.isValidDomain(item.split("@")[1])) {
                Emails.add(item);
                System.out.println(item);
            }
        }
        return Emails;
    }

}
