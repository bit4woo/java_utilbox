package com.bit4woo.utilbox.utils;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.text.StringEscapeUtils;

import Tools.PatternsFromAndroid;
import base.Commons;

public class GrepUtils {

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
			if (DomainNameUtils.isValidDomain(item.split("@")[1])) {
				Emails.add(item);
				System.out.println(item);
			}
		}
		return Emails;
	}

	/**
	 * 先解Unicode，再解url，应该才是正确操作吧
	 * @param line
	 * @return
	 */
	public static String decodeAll(String line) {
		line = line.trim();

		/*
		if (false) {// &#x URF-8编码的特征，对于域名的提取不需要对它进行处理
			while (true) {
				try {
					int oldlen = line.length();
					line = StringEscapeUtils.unescapeHtml4(line);
					int currentlen = line.length();
					if (oldlen > currentlen) {
						continue;
					}else {
						break;
					}
				}catch(Exception e) {
					//e.printStackTrace(BurpExtender.getStderr());
					break;//即使出错，也要进行后续的查找
				}
			}
		}
		 */

		if (needUnicodeConvert(line)) {
			while (true) {//unicode解码
				try {
					int oldlen = line.length();
					line = StringEscapeUtils.unescapeJava(line);
					int currentlen = line.length();
					if (oldlen > currentlen) {
						continue;
					}else {
						break;
					}
				}catch(Exception e) {
					//e.printStackTrace(BurpExtender.getStderr());
					break;//即使出错，也要进行后续的查找
				}
			}
		}

		if (needURLConvert(line)) {
			while (true) {
				try {
					int oldlen = line.length();
					line = URLDecoder.decode(line);
					int currentlen = line.length();
					if (oldlen > currentlen) {
						continue;
					}else {
						break;
					}
				}catch(Exception e) {
					//e.printStackTrace(BurpExtender.getStderr());
					break;//即使出错，也要进行后续的查找
				}
			}
		}

		return line;
	}

	public static Set<String> grepDomain(String httpResponse) {
		httpResponse = httpResponse.toLowerCase();
		//httpResponse = cleanResponse(httpResponse);
		Set<String> domains = new HashSet<>();

		List<String> lines = Commons.textToLines(httpResponse);

		for (String line:lines) {//分行进行提取，似乎可以提高成功率？
			line = decodeAll(line);
			Pattern pDomainNameOnly = Pattern.compile(DomainNameUtils.GREP_DOMAIN_NAME_AND_PORT_PATTERN);
			Matcher matcher = pDomainNameOnly.matcher(line);
			while (matcher.find()) {//多次查找
				String tmpDomain = matcher.group();
				if (tmpDomain.startsWith("*.")) {
					tmpDomain = tmpDomain.replaceFirst("\\*\\.","");//第一个参数是正则
				}
				if (tmpDomain.toLowerCase().startsWith("252f")) {//url中的//的URL编码，上面的解码逻辑可能出错
					tmpDomain = tmpDomain.replaceFirst("252f","");
				}
				if (tmpDomain.toLowerCase().startsWith("2f")) {
					tmpDomain = tmpDomain.replaceFirst("2f","");
				}
				domains.add(tmpDomain);
			}
		}
		return domains;
	}

	/**
	 * 不带端口
	 * @param httpResponse
	 * @return
	 */
	public static Set<String> grepDomainNoPort(String httpResponse) {
		httpResponse = httpResponse.toLowerCase();
		//httpResponse = cleanResponse(httpResponse);
		Set<String> domains = new HashSet<>();

		List<String> lines = Commons.textToLines(httpResponse);

		for (String line:lines) {//分行进行提取，似乎可以提高成功率？
			line = decodeAll(line);
			Pattern pDomainNameOnly = Pattern.compile(DomainNameUtils.GREP_DOMAIN_NAME_PATTERN);
			Matcher matcher = pDomainNameOnly.matcher(line);
			while (matcher.find()) {//多次查找
				String tmpDomain = matcher.group();
				if (tmpDomain.startsWith("*.")) {
					tmpDomain = tmpDomain.replaceFirst("\\*\\.","");//第一个参数是正则
				}
				if (tmpDomain.toLowerCase().startsWith("252f")) {//url中的//的URL编码，上面的解码逻辑可能出错
					tmpDomain = tmpDomain.replaceFirst("252f","");
				}
				if (tmpDomain.toLowerCase().startsWith("2f")) {
					tmpDomain = tmpDomain.replaceFirst("2f","");
				}
				domains.add(tmpDomain);
			}
		}
		return domains;
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
	 * 会发现如下类型的IP，是有效的IP地址，但是实际情况却不会有人这么写。
	 * 应当从我们的正则中剔除
	 * PING 181.002.245.007 (181.2.245.7): 56 data bytes
	 * @param httpResponse
	 * @return
	 */
	public static List<String> grepIP(String httpResponse) {
		Set<String> IPSet = new HashSet<>();
		List<String> lines = Commons.textToLines(httpResponse);

		for (String line:lines) {
			Matcher matcher = PatternsFromAndroid.IP_ADDRESS.matcher(line);
			while (matcher.find()) {//多次查找
				String tmpIP = matcher.group();
				if (IPAddressUtils.isValidIP(tmpIP)) {
					IPSet.add(tmpIP);
				}
			}
		}

		List<String> tmplist= new ArrayList<>(IPSet);
		//Collections.sort(tmplist);
		return tmplist;
	}

	public static List<String> grepPrivateIP(String httpResponse) {
		Set<String> IPSet = new HashSet<>();
		List<String> lines = Commons.textToLines(httpResponse);

		for (String line:lines) {
			Matcher matcher = PatternsFromAndroid.IP_ADDRESS.matcher(line);
			while (matcher.find()) {//多次查找
				String tmpIP = matcher.group();
				if (IPAddressUtils.isValidIP(tmpIP) && IPAddressUtils.isPrivateIPv4(tmpIP)) {
					IPSet.add(tmpIP);
				}
			}
		}

		List<String> tmplist= new ArrayList<>(IPSet);
		//Collections.sort(tmplist);
		return tmplist;
	}


	public static List<String> grepPublicIP(String httpResponse) {
		Set<String> IPSet = new HashSet<>();
		List<String> lines = Commons.textToLines(httpResponse);

		for (String line:lines) {
			Matcher matcher = PatternsFromAndroid.IP_ADDRESS.matcher(line);
			while (matcher.find()) {//多次查找
				String tmpIP = matcher.group();
				if (IPAddressUtils.isValidIP(tmpIP) && !IPAddressUtils.isPrivateIPv4(tmpIP)) {
					IPSet.add(tmpIP);
				}
			}
		}

		List<String> tmplist= new ArrayList<>(IPSet);
		//Collections.sort(tmplist);
		return tmplist;
	}

	/**
	 *  误报太高，不划算。不再使用
	 * @param httpResponse
	 * @return
	 */
	@Deprecated
	public static List<String> grepIPAndPort(String httpResponse) {
		Set<String> IPSet = new HashSet<>();
		String[] lines = httpResponse.split("(\r\n|\r|\n)");

		for (String line:lines) {
			String pattern = "\\d{1,3}(?:\\.\\d{1,3}){3}(?::\\d{1,5})?";
			Pattern pt = Pattern.compile(pattern);
			Matcher matcher = pt.matcher(line);
			while (matcher.find()) {//多次查找
				String tmpIP = matcher.group();
				if (IPAddressUtils.isValidIP(tmpIP)) {
					IPSet.add(tmpIP);
				}
			}
		}

		List<String> tmplist= new ArrayList<>(IPSet);
		//Collections.sort(tmplist);
		return tmplist;
	}


	/**
	 *  查找masscan结果中的port
	 * @param httpResponse
	 * @return
	 */
	public static List<String> grepPort(String httpResponse) {
		Set<String> resultSet = new HashSet<>();
		List<String> lines = Commons.textToLines(httpResponse);
		String REGEX_masscan_port = "(\\d{1,6})";
		Pattern pattern = Pattern.compile(REGEX_masscan_port);

		Matcher matcher = pattern.matcher(httpResponse);
		while (matcher.find()) {//多次查找
			String item = matcher.group(1);
			try {
				int port = Integer.parseInt(item);
				if (port >=0 && port <=65535) {
					resultSet.add(item);
				}
			}catch(Exception e) {

			}
		}

		List<String> tmplist= new ArrayList<>(resultSet);
		//Collections.sort(tmplist);
		return tmplist;
	}

	/**
	 * 提取网段信息 比如143.11.99.0/24
	 * @param httpResponse
	 * @return
	 */
	public static List<String> grepSubnet(String httpResponse) {
		Set<String> IPSet = new HashSet<>();
		String[] lines = httpResponse.split("(\r\n|\r|\n)");

		for (String line:lines) {
			String pattern = "\\d{1,3}(?:\\.\\d{1,3}){3}(?:/\\d{1,2})?";
			Pattern pt = Pattern.compile(pattern);
			Matcher matcher = pt.matcher(line);
			while (matcher.find()) {//多次查找
				String tmpIP = matcher.group();
				IPSet.add(tmpIP);
			}
		}

		List<String> tmplist= new ArrayList<>(IPSet);
		//Collections.sort(tmplist);
		return tmplist;
	}

	public static boolean needUnicodeConvert(String str) {
		Pattern pattern = Pattern.compile("(\\\\u(\\p{XDigit}{4}))");
		//Pattern pattern = Pattern.compile("(\\\\u([A-Fa-f0-9]{4}))");//和上面的效果一样
		Matcher matcher = pattern.matcher(str.toLowerCase());
		if (matcher.find() ){
			return true;
		}else {
			return false;
		}
	}

	public static boolean needURLConvert(String str) {
		Pattern pattern = Pattern.compile("(%(\\p{XDigit}{2}))");

		Matcher matcher = pattern.matcher(str.toLowerCase());
		if (matcher.find() ){
			return true;
		}else {
			return false;
		}
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

	public static List<String> grepChinese(String inputText) {
		// 使用正则表达式匹配中文字符
		Pattern pattern = Pattern.compile("[\\u4e00-\\u9fa5]+");
		Matcher matcher = pattern.matcher(inputText);

		// 提取匹配到的中文字符
		List<String> chineseCharacters = new ArrayList<String>();
		while (matcher.find()) {
			chineseCharacters.add(matcher.group());
		}
		return chineseCharacters;
	}


	/**
	 * 提取两个字符串之间的内容
	 *
	 * @param input   输入字符串
	 * @param start   开始标记
	 * @param end     结束标记
	 * @return 提取的字符串内容
	 */
	public static List<String> grepBetween(String start,String end,String inputText) {
		// 使用正则表达式匹配中文字符
		String regex = Pattern.quote(start) + "(.*?)" + Pattern.quote(end);
		Pattern pattern = Pattern.compile(regex, Pattern.DOTALL);
		// Pattern.DOTALL 支持在多行中匹配内容
		Matcher matcher = pattern.matcher(inputText);

		// 提取匹配到的中文字符
		List<String> result = new ArrayList<String>();
		while (matcher.find()) {
			result.add(matcher.group(0));
		}
		return result;
	}


	public static void main(String[] args) {
		test3();
	}


	public static void test5(){
		System.out.println(grepEmail("111 cs@ph.aaa.com"));
		
	}

	public static void test4(){
		System.out.println(grepSubnet("202.181.90.0/24\tSHOPEE SINGAPORE PRIVATE LIMITEDSingapore\n" +
				"202.181.91.0/24\tSHOPEE SINGAPORE PRIVATE LIMITEDSingapore"));
	}

	public static void test3(){
		System.out.println(grepDomain("baidu.com."));
		System.out.println(grepDomain("http://baidu.com."));
		System.out.println(grepDomain("http://baidu.com:200."));
		System.out.println(grepDomainNoPort("testopenapi.xxx.com:22"));
	}

	public static void test2() {
		String tmpDomain = "aaa *.baidu.com  bbb";
		if (tmpDomain.startsWith("*.")) {
			tmpDomain = tmpDomain.replaceFirst("\\*\\.","");//第一个参数是正则
		}
		System.out.println(tmpDomain);
	}

	public static void test1() {
		//		String line = "\"%.@.\\\"xsrf\\\",";
		String line = "%2f%2fbaidu.com";
		System.out.println(needURLConvert(line));
		if (needURLConvert(line)) {
			while (true) {
				try {
					int oldlen = line.length();
					line = URLDecoder.decode(line);
					int currentlen = line.length();
					if (oldlen > currentlen) {
						continue;
					}else {
						break;
					}
				}catch(Exception e) {
					e.printStackTrace();
					break;//即使出错，也要进行后续的查找
				}
			}
		}
		System.out.println(line);
	}

	public static void test(){
		String aaa="  <div class=\"mod_confirm brandad_authority_failapply\">\n" +
				"    <a href=\"javascript:;\" class=\"mod_confirm_close\"><i></i></a>\n" +
				"    <div class=\"mod_confirm_hd\">申请开通账户权限</div>\n" +
				"    <div class=\"mod_confirm_bd\">\n" +
				"      <p class=\"mod_confirm_txt fapplyReason\"></p>\n" +
				"      <p class=\"mod_confirm_txt\">如有疑问请咨询：<em>bdm@jd.com</em></p>\n" +
				"    </div>\n" +
				"    <div class=\"mod_confirm_ft\">\n" +
				"      <a href=\"#\" class=\"mod_btn mod_btn_default reapply\">重新申请</a>\n" +
				"      <a href=\"#\" class=\"mod_btn mod_btn_white mod_close_btn\">关闭</a>\n" +
				"    </div>\n" +
				"  </div>"+"            <div class=\"footer-menu-left\">\r\n" +
				"                <dl>\r\n" +
				"                    <dt>京东众创</dt>\r\n" +
				"                    <dd>客服电话 400-088-8816</dd>\r\n" +
				"                    <dd>客服邮箱 zcfw@jd.com</dd>\r\n" +
				"                </dl>\r\n" +
				"            </div>"+"                        if (result.Code == 8)\r\n" +
				"                        {\r\n" +
				"                            $(\"#divInfo\").show();\r\n" +
				"                            $(\"#divInfo\").html(\"<b></b><span class=\\\"warntip_text\\\">ERP系统中信息不完整，请将邮箱地址、erp账户、手机号发送至itmail@jd.com邮箱中</span>\");//ERP系统中信息不完整，请联系邮件管理员!\r\n" +
				"                        }"+"/* 2019-03-12 11:16:22 joya.js @issue to lijiwen@jd.com Thanks */\r\n" +
				"try{window.fingerprint={},function t(){fingerprint.config={fpb_send_data:'body={\"appname\": \"jdwebm_hf\",\"jdkey\": \"\",\"whwswswws\": \"\",\"businness\": \"\",\"body\":";
		//System.out.println(grepEmail(aaa));

		//		String bbb="https%3A%2F%2F3pl.jd.com%2F";
		//		System.out.println(needURLConvert(bbb));
		//
		//		String ccc = "5E44a6a6a1f3731fbaa00ca03e68a8d20c%5E%5E%E5%9C%A8%E7%BA%BF%E6%94%AF%E4%BB%98%5E%5Ehttps%3A%2F%2Fpay.bilibili.com%2Fpayplatform-h5%2Fcashierdesk.html";
		//		System.out.println(URLDecoder.decode(ccc));
		//		System.out.println(ccc.length());
		//		System.out.println(URLDecoder.decode(ccc).length());
		//		System.out.println("在线支付".length());
		System.out.println(grepBetween("brandad_authority_failapply","warntip_text",aaa));

	}

}
