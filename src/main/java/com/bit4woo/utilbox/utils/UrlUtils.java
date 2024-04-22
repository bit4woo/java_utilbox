package com.bit4woo.utilbox.utils;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UrlUtils {
    private final URL url;

    public static final String URL_Regex = "(?:\"|')"
            + "("
            + "((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})"
            + "|"
            + "((?:/|\\.\\./|\\./)[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})"
            + "|"
            + "([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/][^\"|']{0,}|))"
            + "|"
            + "([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|))"
            + ")"
            + "(?:\"|')";

    public static void main(String[] args) throws MalformedURLException {
        String aaa = "https://api.example.vn:443/Execute#1653013013763";
        String bbb = "https://api.example.vn/Execute#1653013013763";

        String url1 = "http://www.example.com";
        String url2 = "https://www.example.com:8080";
        String url3 = "ftp://www.example.com:21/files#1111";

        System.out.println(new UrlUtils(url1).getFullURLWithDefaultPort());

        try {
            System.out.println(new URL(bbb).toString());
        } catch (MalformedURLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    UrlUtils(String urlStr) throws MalformedURLException {
        this.url = new URL(urlStr);
    }

    UrlUtils(URL url) {
        this.url = url;
    }

    public String getHost() {
        return url.getHost();
    }

    public int getPort() {
        int port = url.getPort();
        if (port == -1) {
            port = url.getDefaultPort();
        }
        return port;
    }

    public static boolean isVaildUrl(String urlString) {
        try {
            new URL(urlString);
            return true;
        } catch (Exception e) {
            return false;
        }
    }


    /**
     * return Type is URL,not String.
     * use equal() function to compare URL object.
     * the string contains default port or not both OK, but the path(/) is sensitive
     * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
     * <p>
     * result example:
     * http://bit4woo.com/ 不包含默认端口；包含默认path(/)
     * 是符合通常浏览器中使用格式的
     *
     * @return http://www.baidu.com/  不包含默认端口；包含默认path(/)
     */
    public String getBaseURL() {
        String baseUrl = url.getProtocol() + "://" + url.getHost() + ":" + getPort() + "/";
        baseUrl = removeUrlDefaultPort(baseUrl);
        return baseUrl;
    }

    /**
     * return Type is URL,not String.
     * use equal() function to compare URL object.
     * the string contains default port or not both OK, but the path(/) is sensitive
     * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
     * <p>
     * result example:
     * <p>
     * eg. http://bit4woo.com:80/ 包含默认端口和默认path(/)
     *
     * @return
     */
    public String getBaseURLWithDefaultPort() {
        return url.getProtocol() + "://" + url.getHost() + ":" + getPort() + "/";
    }


    /**
     * return Type is URL,not String.
     * use equal() function to compare URL object. the string contains default port or not both OK, but the path(/) is sensitive
     * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
     * <p>
     * 不包含默认端口的URL格式，符合通常浏览器中的格式
     * http://bit4woo.com/test.html#123
     */
    public String getFullURL() {
        return url.toString();
    }

    /**
     * return Type is URL,not String.
     * use equal() function to compare URL object. the string contains default port or not both OK, but the path(/) is sensitive
     * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
     * <p>
     * 这个函数的返回结果转换成字符串是包含了默认端口的。
     * http://bit4woo.com:80/test.html#123
     */
    public String getFullURLWithDefaultPort() {
        return addUrlDefaultPort(url.toString());
    }

    /**
     * 1、这个函数的目的是：在【浏览器URL】的基础上，加上默认端口。
     * <p>
     * https://www.baidu.com/ ---> https://www.baidu.com:443/
     * http://www.baidu.com ---> http://www.baidu.com:80/
     * <p>
     * 在浏览器中，我们看到的是 baidu.com, 复制粘贴得到的是 https://www.baidu.com/
     * let url String contains default port(80\443) and default path(/)
     * <p>
     * burp中获取到的URL是包含默认端口的，但是平常浏览器中的URL格式都是不包含默认端口的。
     * 应该尽量和平常使用习惯保存一致！所以尽量避免使用该函数。
     *
     * @param urlStr
     * @return
     */
    public static String addUrlDefaultPort(String urlStr) {
        try {
            URL url = new URL(urlStr);
            String host = url.getHost();
            int port = url.getPort();
            String path = url.getPath();

            if (port == -1) {
                String newHost = url.getHost() + ":" + url.getDefaultPort();
                urlStr = urlStr.replaceFirst(host, newHost);
            }

            if (path.equals("")) {
                urlStr = urlStr + "/";
            }
            return new URL(urlStr).toString();
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return urlStr;
        }
    }

    /**
     * 1.remove default port(80\443) from the url
     * 2.add default path(/) to the url,if it's empty
     * 这个函数的目的是让URL的格式和通常从浏览器中复制的格式一致：
     * 在浏览器中，我们看到的是 baidu.com, 复制粘贴得到的是 https://www.baidu.com/
     * <p>
     * 比如
     * http://bit4woo.com:80/ ---> http://bit4woo.com/
     * https://bit4woo.com:443 ---> https://bit4woo.com/
     */
    public static String removeUrlDefaultPort(String urlString) {
        try {
            URL url = new URL(urlString);
            String protocol = url.getProtocol();
            String host = url.getHost();
            int port = url.getPort();//不包含端口时返回-1
            String path = url.getPath();

            if ((port == 80 && protocol.equalsIgnoreCase("http"))
                    || (port == 443 && protocol.equalsIgnoreCase("https"))) {
                String oldHost = url.getHost() + ":" + url.getPort();
                urlString = urlString.replaceFirst(oldHost, host);
            }

            if (path.equals("")) {
                urlString = urlString + "/";
            }
            return new URL(urlString).toString();
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return urlString;
        }
    }

    public static List<String> grepUrls(String text) {
        List<String> result = new ArrayList<>();
        //TODO

        return result;
    }


    //https://stackoverflow.com/questions/163360/regular-expression-to-match-urls-in-java
    //https://github.com/aosp-mirror/platform_frameworks_base/blob/master/core/java/android/util/Patterns.java
    public static List<String> grepURL(String httpResponse) {
        httpResponse = httpResponse.toLowerCase();
        Set<String> URLs = new HashSet<>();

        String[] lines = httpResponse.split("\r\n");

        Pattern pt = Pattern.compile(URL_Regex);
        for (String line:lines) {//分行进行提取，似乎可以提高成功率？PATH_AND_QUERY
            Matcher matcher = pt.matcher(line);
            while (matcher.find()) {//多次查找
                String url = matcher.group();
                URLs.add(url);
            }
        }

        List<String> tmplist= new ArrayList<>(URLs);
        return tmplist;
    }


    //https://stackoverflow.com/questions/163360/regular-expression-to-match-urls-in-java
    //https://github.com/aosp-mirror/platform_frameworks_base/blob/master/core/java/android/util/Patterns.java
    /**
     *
     * @param httpResponse
     * @return
     */
    public static List<String> grepURL(String httpResponse) {
        //httpResponse = httpResponse.toLowerCase();URL是大小写敏感的。这会对URL有影响，造成服务端不识别
        Set<String> URLs = new HashSet<>();

        String[] lines = httpResponse.split("\r\n");

        //https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py
        String regex_str = "(?:\"|')"
                + "("
                + "((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})"
                + "|"
                + "((?:/|\\.\\./|\\./)[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})"
                + "|"
                + "([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/][^\"|']{0,}|))"
                + "|"
                + "([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|))"
                + ")"
                + "(?:\"|')";

        String regex_str1= "[a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-.]{1,}";//处理不是/开头的urlpath
        //regex_str = Pattern.quote(regex_str);
        Pattern pt = Pattern.compile(regex_str);
        Pattern pt1 = Pattern.compile(regex_str1);

        for (String line:lines) {//分行进行提取，似乎可以提高成功率？PATH_AND_QUERY
            line = decodeAll(line);

            Matcher matcher = pt.matcher(line);
            while (matcher.find()) {//多次查找
                String url = matcher.group();
                URLs.add(url);
            }

            //这部分提取的是含有协议头的完整URL地址
            matcher = PatternsFromAndroid.WEB_URL.matcher(line);
            while (matcher.find()) {//多次查找
                String url = matcher.group();
                //即使是www.www也会被认为是URL（应该是被认作了主机名或文件名），所以必须过滤
                if (url.toLowerCase().startsWith("http://")
                        ||url.toLowerCase().startsWith("https://")
                        ||url.toLowerCase().startsWith("rtsp://")
                        ||url.toLowerCase().startsWith("ftp://")){
                    URLs.add(url);
                }
            }
        }

        List<String> tmplist= new ArrayList<>(URLs);
        //Collections.sort(tmplist);
        tmplist = Commons.removePrefixAndSuffix(tmplist,"\"","\"");
        tmplist = Commons.removePrefixAndSuffix(tmplist,"\'","\'");
        return tmplist;
    }


    /**
     * 误报较多，却有时候有用
     * @param httpResponse
     * @return
     */
    public static List<String> grepURL1(String httpResponse) {
        //httpResponse = httpResponse.toLowerCase();//URL是大小写敏感的。这会对URL有影响，造成服务端不识别
        Set<String> URLs = new HashSet<>();

        String[] lines = httpResponse.split("\r\n");

        String regex_str1= "[a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-.]{1,}";//处理不是/开头的urlpath
        Pattern pt1 = Pattern.compile(regex_str1);

        for (String line:lines) {//分行进行提取，似乎可以提高成功率？PATH_AND_QUERY
            line = decodeAll(line);

            Matcher matcher = pt1.matcher(line);
            while (matcher.find()) {//多次查找
                String url = matcher.group();
                if (url.length()>=5) {//简单过滤，减少误报
                    URLs.add(url);
                }
            }
        }

        List<String> tmplist= new ArrayList<>(URLs);
        //Collections.sort(tmplist);
        tmplist = Commons.removePrefixAndSuffix(tmplist,"\"","\"");
        tmplist = Commons.removePrefixAndSuffix(tmplist,"\'","\'");
        return tmplist;
    }




    /**
     * 对于信息收集来说，没有用的文件
     * js是有用的
     * pdf\doc\excel等也是有用的，可以收集到其中的域名
     * rar\zip文件即使其中包含了有用信息，是无法直接读取的
     * @param urlpath
     * @return
     */
    public static boolean uselessExtension(String urlpath) {
        String extensions = "css|jpeg|gif|jpg|png|rar|zip|svg|jpeg|ico|woff|woff2|ttf|otf|vue";
        String[] extList = extensions.split("\\|");
        for ( String item:extList) {
            if(urlpath.endsWith("."+item)) {
                return true;
            }
        }
        return false;
    }


}
