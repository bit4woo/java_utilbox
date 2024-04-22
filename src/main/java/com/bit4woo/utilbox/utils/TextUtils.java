package com.bit4woo.utilbox.utils;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TextUtils {

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


    /**
     * 换行符的可能性有三种，都必须考虑到
     * @param input
     * @return
     */
    public static List<String> textToLines(String input){
        String[] lines = input.split("(\r\n|\r|\n)", -1);
        List<String> result = new ArrayList<String>();
        for(String line: lines) {
            line = line.trim();
            if (!line.equalsIgnoreCase("")) {
                result.add(line.trim());
            }
        }
        return result;
    }

}
