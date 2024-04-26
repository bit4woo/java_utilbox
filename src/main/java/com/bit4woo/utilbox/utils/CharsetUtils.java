package com.bit4woo.utilbox.utils;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

import com.bit4woo.utilbox.burp.HelperPlus;

import burp.IExtensionHelpers;
import org.apache.commons.io.input.BOMInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public class CharsetUtils {

	public CharsetUtils() {
		// TODO Auto-generated constructor stub
	}

	public static String getSystemCharSet() {
		return Charset.defaultCharset().toString();
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
}
