package com.bit4woo.utilbox.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Map;

import org.apache.commons.io.input.BOMInputStream;

public class CharsetUtils {

	public CharsetUtils() {
		// TODO Auto-generated constructor stub
	}

	public static String getSystemCharSet() {
		return Charset.defaultCharset().toString();
	}
	
	public static boolean isValidCharset(String charsetName) {
        Map<String, Charset> charsets = Charset.availableCharsets();
        return charsets.keySet().contains(charsetName);
    }

	/**
	 * 进行响应包的编码转换。
	 * @param response
	 * @return 转换后的格式的byte[]
	 */
	public static byte[] covertCharSet(byte[] content,String originalCharset,String newCharset){
		if (originalCharset == null) {
			originalCharset = detectCharset(content);
		}
		try {
			return new String(content,originalCharset).getBytes(newCharset);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return content;
		}
	}
	
	
	public static byte[] covertCharSet(byte[] content,String newCharset) throws UnsupportedEncodingException {
		return covertCharSet(content,null,newCharset);
	}
	
	
	public static String detectCharset(byte[] bytes){
        try {
			ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
			BOMInputStream bomInputStream = new BOMInputStream(bis);
			String encoding = bomInputStream.getBOMCharsetName();
			bomInputStream.close();
			return encoding;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
    }
	
    public static void main(String[] args) {
        Map<String, Charset> charsets = Charset.availableCharsets();
        
        // 打印所有字符编码集的规范名称
        System.out.println("Available Charsets:");
        for (String name : charsets.keySet()) {
            System.out.println(name);
        }
    }
}
