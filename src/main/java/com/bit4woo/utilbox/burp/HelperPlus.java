package com.bit4woo.utilbox.burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import com.bit4woo.utilbox.utils.ByteArrayUtils;
import com.bit4woo.utilbox.utils.CharsetUtils;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;

/**
 * author: bit4woo
 * github: https://github.com/bit4woo
 * <p>
 * String getHeadersAsStr(boolean isRequest,byte[] requestOrResponse)
 * String getHeadersAsStr(boolean messageIsRequest,IHttpRequestResponse messageInfo)
 * getHeaderList
 * getHeaderLine
 * getHeaderValueOf
 * <p>
 * addOrUpdateHeader
 * removeHeaderList
 * <p>
 * getBody
 * updateBoby #将body看做一个整体进行替换
 * <p>
 * shorturl
 * url
 * protocol
 * host
 * port
 * <p>
 * getParameters
 * addParameter --Helper中已经存在
 * byte[] addParameter(byte[] request, IParameter parameter);
 * byte[] removeParameter(byte[] request, IParameter parameter);
 * byte[] updateParameter(byte[] request, IParameter parameter);
 * Paras
 * <p>
 * method
 * statusCode
 */

public class HelperPlus {

	/**
	 * 历史设计: 本类工具方法全是 static, 而 Burp 的 IExtensionHelpers 只能通过构造函数注入到静态字段。
	 * 副作用是"必须先 new 过一次 HelperPlus(callbacks.getHelpers())", 静态方法才能用,
	 * 否则 helpers.analyzeRequest(...) 直接 NPE, 而且堆栈指不到根因(排查成本很高)。
	 *
	 * 为了不破坏已有调用方, 这里保留静态注入, 但补齐:
	 *   1. volatile: 多线程下可见;
	 *   2. setHelpers()/getHelpers(): 显式初始化入口(不方便 new 实例时用);
	 *   3. requireHelpers(): 未初始化时抛出带修复建议的 IllegalStateException;
	 *   4. 取 header/body 分界位置的方法在没有 helpers 时退化为按字节查找。
	 */
	private static volatile IExtensionHelpers helpers;

	private final static String Header_Spliter = ":";
	private final static String Header_Connector = ": ";//contains space

	/** header 与 body 的分界标记: CR LF CR LF (13,10,13,10) */
	private final static byte[] HEADER_END = new byte[]{13, 10, 13, 10};

	/** CRLF 字面量; 拿它当 split 的分隔符时不含正则元字符, 可直接使用 */
	private final static String CRLF = String.valueOf(new char[]{13, 10});

	public HelperPlus(IExtensionHelpers helpers) {
		if (helpers != null) {
			HelperPlus.helpers = helpers;
		}
	}

	/** 显式初始化入口, 给不方便 new 实例的场景用 */
	public static void setHelpers(IExtensionHelpers extensionHelpers) {
		if (extensionHelpers != null) {
			HelperPlus.helpers = extensionHelpers;
		}
	}

	public static IExtensionHelpers getHelpers() {
		return helpers;
	}

	/** 需要 helpers 的方法统一走这里: 未初始化时给出可操作的错误信息, 而不是裸 NPE */
	private static IExtensionHelpers requireHelpers() {
		IExtensionHelpers current = helpers;
		if (current == null) {
			throw new IllegalStateException(
					"HelperPlus is not initialized: call 'new HelperPlus(callbacks.getHelpers())' "
							+ "or 'HelperPlus.setHelpers(callbacks.getHelpers())' once at extension startup");
		}
		return current;
	}

	/**
	 * 取 "Name: value" 行里的 Name; 不是 header 行(没有冒号)返回 null。
	 * 用 indexOf 而不是 String.split, 避免每次调用都编译一次正则(扫描器里调用量很大)。
	 */
	private static String headerNameOf(String headerLine) {
		if (headerLine == null) {
			return null;
		}
		int idx = headerLine.indexOf(Header_Spliter);
		if (idx <= 0) {
			return null;
		}
		return headerLine.substring(0, idx).trim();
	}

	/** 空安全的 containsIgnoreCase */
	private static boolean containsIgnoreCase(String content, String keyword) {
		return content != null && keyword != null && content.toLowerCase(Locale.ROOT).contains(keyword);
	}

	/**
	 * 返回HTTP请求或响应的整个header头部分，与body相对应
	 */
	public static String getHeadersAsStr(boolean isRequest, byte[] requestOrResponse) {
	    if (requestOrResponse == null) {
	        return "";
	    }
	    int headerEnd = bodyOffset(isRequest, requestOrResponse);
	    // 去掉分界标记本身: 原实现把结尾的 CRLF CRLF 一起返回, 调用方按 CRLF 切分后会多出空行
	    while (headerEnd > 0) {
	        byte last = requestOrResponse[headerEnd - 1];
	        if (last == 13 || last == 10) {          // CR / LF
	            headerEnd--;
	        } else {
	            break;
	        }
	    }
	    // header 是字节流, 固定按 ISO-8859-1 解码(1 字节对应 1 字符, 可无损往返);
	    // 用默认字符集(中文 Windows 上是 GBK)会把非 ASCII 的 header 值解错
	    return new String(requestOrResponse, 0, headerEnd, StandardCharsets.ISO_8859_1);
	}

	/**
	 * 取 header 与 body 的分界位置, 也就是 body 的起始下标。
	 *
	 * 有 helpers 时用 Burp 的 analyzeRequest/analyzeResponse, 没有时按字节找 CRLF CRLF。
	 * 结果统一夹紧到 [0, length]: 空包/畸形包时 getBodyOffset() 可能返回 -1 或大于长度的值,
	 * 直接拿去 Arrays.copyOfRange 会抛 ArrayIndexOutOfBoundsException / IllegalArgumentException。
	 */
	static int bodyOffset(boolean isRequest, byte[] message) {
	    if (message == null) {
	        return 0;
	    }
	    int offset;
	    IExtensionHelpers current = helpers;
	    if (current != null) {
	        offset = isRequest
	                ? current.analyzeRequest(message).getBodyOffset()
	                : current.analyzeResponse(message).getBodyOffset();
	    } else {
	        int idx = ByteArrayUtils.BytesIndexOf(HEADER_END, message);
	        offset = idx < 0 ? message.length : idx + HEADER_END.length;
	    }
	    if (offset < 0) {
	        offset = 0;
	    }
	    if (offset > message.length) {
	        offset = message.length;
	    }
	    return offset;
	}


	/**
	 * 返回HTTP请求或响应的整个header头部分，与body相对应
	 */
	public static String getHeadersAsStr(boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (messageInfo == null) {
			return "";
		}
		byte[] requestOrResponse = null;
		if (messageIsRequest) {
			requestOrResponse = messageInfo.getRequest();
		} else {
			requestOrResponse = messageInfo.getResponse();
		}
		return getHeadersAsStr(messageIsRequest, requestOrResponse);
	}

	/**
	 * 获取header的字符串数组，是构造burp中请求需要的格式。
	 * return headers list
	 */
	public static List<String> getHeaderList(boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (null == messageInfo) {
			return new ArrayList<>();
		}
		byte[] requestOrResponse;
		if (messageIsRequest) {
			requestOrResponse = messageInfo.getRequest();
		} else {
			requestOrResponse = messageInfo.getResponse();
		}
		return getHeaderList(messageIsRequest, requestOrResponse);
	}

	/**
	 * 获取请求包或者响应包中的header List
	 */
	public static List<String> getHeaderList(boolean IsRequest, byte[] requestOrResponse) {
	    if (null == requestOrResponse) {
	        return new ArrayList<>();
	    }

	    IExtensionHelpers current = helpers;
	    if (current != null) {
	        List<String> headers = IsRequest
	                ? current.analyzeRequest(requestOrResponse).getHeaders()
	                : current.analyzeResponse(requestOrResponse).getHeaders();
	        // 本类的 addOrUpdate/remove 都是原地修改传入的 List,
	        // 统一复制一份, 避免 Burp 返回不可变 List 时抛 UnsupportedOperationException
	        return new ArrayList<>(headers);
	    }
	    String headerStr = getHeadersAsStr(IsRequest, requestOrResponse);
	    if (headerStr.isEmpty()) {
	        return new ArrayList<>();
	    }
	    return new ArrayList<>(Arrays.asList(headerStr.split(CRLF)));
	}


	/**
	 * 新增或更新header
	 *
	 * @param headerLine header的一整行
	 */
	public static List<String> addOrUpdateHeader(List<String> headers, String headerLine) {
	    if (headers == null || headerLine == null) {
	        return headers;
	    }
	    int idx = headerLine.indexOf(Header_Spliter);
	    if (idx > 0) {
	        return addOrUpdateHeader(headers, headerLine.substring(0, idx).trim(),
	                headerLine.substring(idx + 1).trim());
	    }
	    return headers;
	}

	/**
	 * 新增或更新header
	 */
	public static List<String> addOrUpdateHeader(List<String> headers, String headerName, String headerValue) {
	    if (headers == null || headerName == null) {
	        return headers;
	    }
	    String name = headerName.trim();
	    String newLine = name + Header_Connector + (headerValue == null ? "" : headerValue.trim());
	    // 从下标 1 开始: 第 0 行是请求行/状态行, 不是 header。
	    // 原来的 remove + add 会把被更新的 header 挪到列表末尾, 这里原地替换, 保持原有顺序。
	    for (int i = 1; i < headers.size(); i++) {
	        String nameOrigin = headerNameOf(headers.get(i));
	        if (nameOrigin != null && nameOrigin.equalsIgnoreCase(name)) {
	            headers.set(i, newLine);
	            return headers;
	        }
	    }
	    headers.add(newLine);
	    return headers;
	}


	/**
	 * 新增或更新header
	 *
	 * @param headerLine header的一整行
	 */
	public IHttpRequestResponse addOrUpdateHeader(boolean messageIsRequest, IHttpRequestResponse messageInfo, String headerLine) {
		List<String> headers = getHeaderList(messageIsRequest, messageInfo);
		byte[] body = getBody(messageIsRequest, messageInfo);
		headers = addOrUpdateHeader(headers, headerLine);
		byte[] RequestOrResponse = helpers.buildHttpMessage(headers, body);
		if (messageIsRequest) {
			messageInfo.setRequest(RequestOrResponse);
		} else {
			messageInfo.setResponse(RequestOrResponse);
		}
		return messageInfo;
	}
	
	/**
	 * 更改header第一行的请求方式/PATH等
	 * GET /api/search?q=aaa HTTP/1.1
	 */
	public static List<String> updateFirstLineOfHeaders(List<String> headers, String method, String path, String httpVersion) {
	    if (headers == null || headers.isEmpty()) {
	        return headers;
	    }
	    // 原实现 split(" ") 后直接取下标的 [0][1][2]:
	    //   - 请求行只有两段(如 "GET /")时抛 ArrayIndexOutOfBoundsException;
	    //   - 中间有连续空格时会多出空段, String.join 拼回去把请求行搞坏。
	    // 这里先把空格/TAB 折叠成单个空格, 再切分; 缺段用默认值补齐。
	    String firstLine = headers.get(0) == null ? "" : headers.get(0).trim();
	    StringBuilder normalized = new StringBuilder();
	    boolean lastWasSpace = false;
	    for (int i = 0; i < firstLine.length(); i++) {
	        char c = firstLine.charAt(i);
	        if (c == ' ' || c == 9) {                 // 9 == TAB
	            if (!lastWasSpace) {
	                normalized.append(' ');
	            }
	            lastWasSpace = true;
	        } else {
	            normalized.append(c);
	            lastWasSpace = false;
	        }
	    }
	    String[] parts = normalized.toString().split(" ");

	    String newMethod = method != null ? method
	            : (parts.length > 0 && !parts[0].isEmpty() ? parts[0] : "GET");
	    String newPath = path != null ? path : (parts.length > 1 ? parts[1] : "/");
	    String newVersion = httpVersion != null ? httpVersion : (parts.length > 2 ? parts[2] : "HTTP/1.1");

	    headers.set(0, newMethod + " " + newPath + " " + newVersion);
	    return headers;
	}


	/**
	 * 新增或更新header
	 */
	public IHttpRequestResponse addOrUpdateHeader(boolean messageIsRequest, IHttpRequestResponse messageInfo, String headerName, String headerValue) {
		List<String> headers = getHeaderList(messageIsRequest, messageInfo);
		byte[] body = getBody(messageIsRequest, messageInfo);
		headers = addOrUpdateHeader(headers, headerName, headerValue);
		byte[] RequestOrResponse = helpers.buildHttpMessage(headers, body);
		if (messageIsRequest) {
			messageInfo.setRequest(RequestOrResponse);
		} else {
			messageInfo.setResponse(RequestOrResponse);
		}
		return messageInfo;
	}


	/**
	 * 新增或更新header
	 */
	public byte[] addOrUpdateHeader(boolean isRequest, byte[] requestOrResponse, String headerLine) {
		List<String> headers = getHeaderList(isRequest, requestOrResponse);
		byte[] body = getBody(isRequest, requestOrResponse);
		headers = addOrUpdateHeader(headers, headerLine);
		return helpers.buildHttpMessage(headers, body);
	}


	/**
	 * 新增或更新header
	 */
	public byte[] addOrUpdateHeader(boolean isRequest, byte[] requestOrResponse, String headerName, String headerValue) {
		List<String> headers = getHeaderList(isRequest, requestOrResponse);
		byte[] body = getBody(isRequest, requestOrResponse);
		headers = addOrUpdateHeader(headers, headerName, headerValue);
		return helpers.buildHttpMessage(headers, body);
	}


	public static List<String> addOrUpdateHeaders(List<String> headers,List<String> headersToAdd) {
		for (String newHeader:headersToAdd) {
			headers = addOrUpdateHeader(headers,newHeader);
		}
		return headers;
	}


	public static List<String> addOrUpdateHeaders(List<String> headers,Map<String,String> headersToAdd) {
		for (String newHeaderKey:headersToAdd.keySet()) {
			headers = addOrUpdateHeader(headers,newHeaderKey,headersToAdd.get(newHeaderKey));
		}
		return headers;
	}

	public byte[] addOrUpdateHeader(boolean isRequest, byte[] requestOrResponse, List<String> headersToAdd) {
		List<String> headers = getHeaderList(isRequest, requestOrResponse);
		byte[] body = getBody(isRequest, requestOrResponse);
		headers = addOrUpdateHeaders(headers, headersToAdd);
		return helpers.buildHttpMessage(headers, body);
	}

	public byte[] addOrUpdateHeader(boolean isRequest, byte[] requestOrResponse, Map<String,String> headersToAdd) {
		List<String> headers = getHeaderList(isRequest, requestOrResponse);
		byte[] body = getBody(isRequest, requestOrResponse);
		headers = addOrUpdateHeaders(headers, headersToAdd);
		return helpers.buildHttpMessage(headers, body);
	}

	/**
	 * 新增或更新header
	 */
	public IHttpRequestResponse addOrUpdateHeader(boolean messageIsRequest, IHttpRequestResponse messageInfo, List<String> headersToAdd) {
		List<String> headers = getHeaderList(messageIsRequest, messageInfo);
		byte[] body = getBody(messageIsRequest, messageInfo);
		headers = addOrUpdateHeaders(headers, headersToAdd);
		byte[] RequestOrResponse = helpers.buildHttpMessage(headers, body);
		if (messageIsRequest) {
			messageInfo.setRequest(RequestOrResponse);
		} else {
			messageInfo.setResponse(RequestOrResponse);
		}
		return messageInfo;
	}

	/**
	 * 新增或更新header
	 */
	public IHttpRequestResponse addOrUpdateHeader(boolean messageIsRequest, IHttpRequestResponse messageInfo, Map<String,String> headersToAdd) {
		List<String> headers = getHeaderList(messageIsRequest, messageInfo);
		byte[] body = getBody(messageIsRequest, messageInfo);
		headers = addOrUpdateHeaders(headers, headersToAdd);
		byte[] RequestOrResponse = helpers.buildHttpMessage(headers, body);
		if (messageIsRequest) {
			messageInfo.setRequest(RequestOrResponse);
		} else {
			messageInfo.setResponse(RequestOrResponse);
		}
		return messageInfo;
	}

	/**
	 * 删除header
	 */
	public static List<String> removeHeader(List<String> headers, String headerNameOrHeaderLine) {
	    if (headers == null || headerNameOrHeaderLine == null) {
	        return headers;
	    }
	    String target = headerNameOrHeaderLine.trim();
	    // 传整行("Cookie: a=b")就按整行精确删除; 只传名字("Cookie")就按名字删除。
	    // 原实现是对整行做 startsWith 前缀匹配: removeHeader(headers, "X-Forwarded") 会把
	    // X-Forwarded-For / X-Forwarded-Host 一起删掉, 语义太宽, 容易误删鉴权相关头。
	    boolean fullLine = target.indexOf(Header_Spliter) > 0;
	    String targetName = fullLine ? headerNameOf(target) : target;
	    if (targetName == null || targetName.isEmpty()) {
	        return headers;
	    }
	    Iterator<String> it = headers.iterator();
	    boolean first = true;
	    while (it.hasNext()) {
	        String header = it.next();
	        if (first) {
	            first = false;                       // 第 0 行是请求行/状态行, 永不删
	            continue;
	        }
	        String headerName = headerNameOf(header);
	        if (headerName == null) {
	            continue;                            // 续行/畸形行
	        }
	        boolean hit = fullLine ? header.trim().equalsIgnoreCase(target)
	                : headerName.equalsIgnoreCase(targetName);
	        if (hit) {
	            it.remove();
	        }
	    }
	    return headers;
	}


	/**
	 * 删除header
	 */
	public IHttpRequestResponse removeHeader(boolean messageIsRequest, IHttpRequestResponse messageInfo, String headerNameOrHeaderLine) {
		List<String> headers = getHeaderList(messageIsRequest, messageInfo);
		byte[] body = getBody(messageIsRequest, messageInfo);
		headers = removeHeader(headers, headerNameOrHeaderLine);
		byte[] RequestOrResponse = helpers.buildHttpMessage(headers, body);
		if (messageIsRequest) {
			messageInfo.setRequest(RequestOrResponse);
		} else {
			messageInfo.setResponse(RequestOrResponse);
		}
		return messageInfo;
	}

	/**
	 * 删除特定的header。
	 */
	public byte[] removeHeader(boolean isRequest, byte[] requestOrResponse, String headerNameOrHeaderLine) {
		List<String> headers = getHeaderList(isRequest, requestOrResponse);
		byte[] body = getBody(isRequest, requestOrResponse);
		headers = removeHeader(headers, headerNameOrHeaderLine);
		return helpers.buildHttpMessage(headers, body);
	}


	/**
	 * 获取某个header的整行，如果没有此header，返回null，以header的名称作为查找依据。
	 */
	public static String getHeaderLine(List<String> headers, String headerName) {
		if (null == headers || headerName == null) return null;
		for (String header : headers) {
			if (header.contains(":")) {
				String[] parts = header.split(Header_Spliter, 2);
				if (parts.length == 2) {
					String headerNameOrigin = parts[0].trim();
					if (headerNameOrigin.equalsIgnoreCase(headerName)) {
						return header;
					}
				}
			}
		}
		return null;
	}


	/**
	 * 获取某个header的整行，如果没有此header，返回null，以header的名称作为查找依据。
	 */
	public static String getHeaderLine(boolean messageIsRequest, IHttpRequestResponse messageInfo, String headerName) {
		List<String> headers = getHeaderList(messageIsRequest, messageInfo);
		return getHeaderLine(headers, headerName);
	}

	/**
	 * 获取某个header的整行，如果没有此header，返回null，以header的名称作为查找依据。
	 */
	public static String getHeaderLine(boolean messageIsRequest, byte[] requestOrResponse, String headerName) {
		List<String> headers = getHeaderList(messageIsRequest, requestOrResponse);
		return getHeaderLine(headers, headerName);
	}

	/**
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public static String getHeaderValueOf(List<String> headers, String headerName) {
		if (null == headers || headerName == null) return null;
		for (String header : headers) {
			if (header.contains(":")) {
				String[] parts = header.split(Header_Spliter, 2);
				if (parts.length == 2) {
					String headerNameOrigin = parts[0].trim();
					String headerValue = parts[1].trim();
					if (headerNameOrigin.equalsIgnoreCase(headerName)) {
						return headerValue;
					}
				}
			}
		}
		return null;
	}

	/**
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public static String getHeaderValueOf(boolean messageIsRequest, IHttpRequestResponse messageInfo, String headerName) {
		List<String> headers = getHeaderList(messageIsRequest, messageInfo);
		return getHeaderValueOf(headers, headerName);
	}

	/**
	 * 获取某个header的值，如果没有此header，返回null。
	 */
	public static String getHeaderValueOf(boolean messageIsRequest, byte[] requestOrResponse, String headerName) {
		List<String> headers = getHeaderList(messageIsRequest, requestOrResponse);
		return getHeaderValueOf(headers, headerName);
	}

	/**
	 * 获取数据包的body
	 */
	public static byte[] getBody(boolean isRequest, byte[] requestOrResponse) {
	    // 返回空数组而不是 null: 调用方常用的 new String(getBody(...)) 就不会 NPE;
	    // 传给 buildHttpMessage(headers, body) 时空数组等价于"没有 body"。
	    if (requestOrResponse == null) {
	        return new byte[0];
	    }
	    // 原实现的两个坑:
	    //   1. 包里没有 CRLF CRLF 时 BytesIndexOf 返回 -1, +4 得到 3, 会把 header 当成 body 返回;
	    //   2. 分界位置超过包长度时 Arrays.copyOfRange 直接抛异常。
	    // bodyOffset() 内部已把结果夹紧到 [0, length]。
	    int offset = bodyOffset(isRequest, requestOrResponse);
	    return Arrays.copyOfRange(requestOrResponse, offset, requestOrResponse.length);
	}


	/**
	 * 获取数据包的body
	 */
	public static byte[] getBody(boolean messageIsRequest, IHttpRequestResponse messageInfo) {
	    if (messageInfo == null) {
	        return new byte[0];
	    }
		byte[] requestOrResponse = null;
		if (messageIsRequest) {
			requestOrResponse = messageInfo.getRequest();
		} else {
			requestOrResponse = messageInfo.getResponse();
		}
		return getBody(messageIsRequest, requestOrResponse);
	}

	/**
	 * 更新数据包的body
	 */
	public IHttpRequestResponse UpdateBody(boolean messageIsRequest, IHttpRequestResponse messageInfo, byte[] body) {
		List<String> headers = getHeaderList(messageIsRequest, messageInfo);
		byte[] RequestOrResponse = helpers.buildHttpMessage(headers, body);
		if (messageIsRequest) {
			messageInfo.setRequest(RequestOrResponse);
		} else {
			messageInfo.setResponse(RequestOrResponse);
		}
		return messageInfo;
	}

	/**
	 * 更新数据包的body
	 */
	public byte[] UpdateBody(boolean isRequest, byte[] requestOrResponse, byte[] body) {
		List<String> headers = getHeaderList(isRequest, requestOrResponse);
		return helpers.buildHttpMessage(headers, body);
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
	public static URL getBaseURL(IHttpRequestResponse messageInfo) {
		if (null == messageInfo) return null;
		IHttpService service = messageInfo.getHttpService();
		String shortUrlString = getBaseURL(service);
		try {
			return new URL(shortUrlString);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * @param service
	 * @return http://www.baidu.com/  不包含默认端口；包含默认path(/)
	 */
	public static String getBaseURL(IHttpService service) {
	    // 不要用 service.toString(): 新版 Burp 返回的是 Object 默认实现(burp.Ze6r@7f06cf44/)
	    if (service == null) {
	        return null;
	    }
	    // IPv6 字面量必须加方括号, 否则 http://::1:8080/ 不是合法 URL
	    String shortUrlString = service.getProtocol() + "://" + hostForUrl(service.getHost())
	            + ":" + service.getPort() + "/";
	    return removeUrlDefaultPort(shortUrlString);
	}

	/** IPv6 字面量需要加方括号才能拼进 URL */
	private static String hostForUrl(String host) {
	    if (host == null) {
	        return "";
	    }
	    if (host.indexOf(':') >= 0 && !host.startsWith("[")) {
	        return "[" + host + "]";
	    }
	    return host;
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
	 * @param messageInfo
	 * @return
	 */
	public static URL getBaseURLWithDefaultPort(IHttpRequestResponse messageInfo) {
		if (null == messageInfo) return null;
		IHttpService service = messageInfo.getHttpService();
		String shortUrlString = getBaseURL(service);
		shortUrlString = addUrlDefaultPort(shortUrlString);
		try {
			return new URL(shortUrlString);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
	}


	/**
	 * return Type is URL,not String.
	 * use equal() function to compare URL object. the string contains default port or not both OK, but the path(/) is sensitive
	 * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
	 * <p>
	 * 不包含默认端口的URL格式，符合通常浏览器中的格式
	 * http://bit4woo.com/test.html#123
	 */
	public final URL getFullURL(IHttpRequestResponse messageInfo) {
		if (null == messageInfo) return null;
		IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
		String tmpurl = analyzeRequest.getUrl().toString();
		tmpurl = removeUrlDefaultPort(tmpurl);
		try {
			return new URL(tmpurl);
		} catch (MalformedURLException e) {
			// 某些请求(如Burp Collaborator回调)analyzeRequest.getUrl()会返回无scheme的"host:port"，
			// 导致new URL抛MalformedURLException。退化为用IHttpService(明确含protocol/host/port)重建base URL。
			URL base = getBaseURL(messageInfo);
			if (base != null) {
				return base;
			}
			e.printStackTrace();
			return null;
		}
	}


	public final URL getFullURL(IHttpService httpService, byte[] request) {
		if (null == request) return null;
		IRequestInfo analyzeRequest = helpers.analyzeRequest(httpService,request);
		String tmpurl = analyzeRequest.getUrl().toString();
		tmpurl = removeUrlDefaultPort(tmpurl);
		try {
			return new URL(tmpurl);
		} catch (MalformedURLException e) {
			// 同上：无scheme时退化为用IHttpService重建base URL。
			String baseStr = getBaseURL(httpService);
			if (baseStr != null) {
				try {
					return new URL(baseStr);
				} catch (MalformedURLException e2) {
					e2.printStackTrace();
				}
			}
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * return Type is URL,not String.
	 * use equal() function to compare URL object. the string contains default port or not both OK, but the path(/) is sensitive
	 * URL对象可以用它自己提供的equal()函数进行对比，是否包含默认端口都是没有关系的。但最后的斜杠path却是有关系的。
	 * <p>
	 * 这个函数的返回结果转换成字符串是包含了默认端口的。
	 * http://bit4woo.com:80/test.html#123
	 */
	public final URL getFullURLWithDefaultPort(IHttpRequestResponse messageInfo) {
		if (null == messageInfo) return null;
		IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
		return analyzeRequest.getUrl();
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
	    return rewriteUrl(urlStr, false);
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
	    return rewriteUrl(urlString, true);
	}

	/**
	 * 统一重写 URL 的端口与 path, 替代原来"正则替换字符串再 new URL 解析回来"的写法。
	 *
	 * 原写法的问题:
	 *   1. replaceFirst + Pattern.quote 只是补丁式规避 host 里的正则元字符;
	 *   2. path 为空时直接在原串尾部拼 "/", URL 带 query 时会拼错: http://h?x=1 会变成 http://h?x=1/;
	 *   3. 末尾 new URL(...).toString() 会重新规范化, 调用方拿回的不再是自己传进去的那份串。
	 * 这里改成按 URL 各部件拼回去, 顺序、转义、query/fragment 都确定。
	 *
	 * @param dropDefaultPort true: 去掉默认端口(http:80 / https:443); false: 补上默认端口
	 */
	private static String rewriteUrl(String urlStr, boolean dropDefaultPort) {
	    if (urlStr == null || urlStr.isEmpty()) {
	        return urlStr;
	    }
	    URL url;
	    try {
	        url = new URL(urlStr);
	    } catch (MalformedURLException e) {
	        // 无 scheme 的 "host:port" 之类无法解析, 原样返回, 由调用方决定怎么处理
	        return urlStr;
	    }

	    int port = url.getPort();               // 未显式指定端口时为 -1
	    int defaultPort = url.getDefaultPort(); // 未知协议时为 -1
	    if (port == -1 && !dropDefaultPort) {
	        port = defaultPort;
	    } else if (port != -1 && dropDefaultPort && port == defaultPort) {
	        port = -1;
	    }

	    StringBuilder sb = new StringBuilder();
	    sb.append(url.getProtocol()).append("://").append(hostForUrl(url.getHost()));
	    if (port != -1) {
	        sb.append(':').append(port);
	    }
	    String path = url.getPath();
	    sb.append(path == null || path.isEmpty() ? "/" : path);
	    if (url.getQuery() != null) {
	        sb.append('?').append(url.getQuery());
	    }
	    if (url.getRef() != null) {
	        sb.append('#').append(url.getRef());
	    }
	    return sb.toString();
	}


	public static String getHost(IHttpRequestResponse messageInfo) {
		return messageInfo.getHttpService().getHost();
	}

	public static String getProtocol(IHttpRequestResponse messageInfo) {
		return messageInfo.getHttpService().getProtocol();
	}

	public static int getPort(IHttpRequestResponse messageInfo) {
		return messageInfo.getHttpService().getPort();
	}

	public short getStatusCode(IHttpRequestResponse messageInfo) {
	    if (messageInfo == null || messageInfo.getResponse() == null) {
	        return -1;
	    }
	    return getStatusCode(messageInfo.getResponse());     // 复用下面带 try/catch 的实现
	}

	/** 解析失败(空响应/畸形响应)统一返回 -1, 不向上抛异常 */
	public short getStatusCode(byte[] response) {
	    if (response == null || response.length == 0) {
	        return -1;
	    }
	    try {
	        return requireHelpers().analyzeResponse(response).getStatusCode();
	    } catch (Exception e) {
	        return -1;
	    }
	}

	public List<IParameter> getParameters(IHttpRequestResponse messageInfo) {
		IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
		return analyzeRequest.getParameters();
	}

	public List<IParameter> getParameters(byte[] request) {
		IRequestInfo analyzeRequest = helpers.analyzeRequest(request);
		return analyzeRequest.getParameters();
	}


	/**
	 * 使用burp.IExtensionHelpers.getRequestParameter(byte[], String),未考虑同名参数的情况！
	 */
	public IParameter getParameterByKey(IHttpRequestResponse messageInfo, String key) {
		return helpers.getRequestParameter(messageInfo.getRequest(), key);
	}

	public IParameter getParameterByKey(byte[] request, String key) {
		return helpers.getRequestParameter(request, key);
	}


	/**
	 * 根据参数的key查找IParameter对象，考虑了同名函数的情况，但这种情况很少，几乎用不上。
	 * 尽量不要使用这个函数
	 */
	@Deprecated
	public static List<IParameter> findParametersByKey(List<IParameter> parameters, String key) {
		List<IParameter> result = new ArrayList<IParameter>();
		for (IParameter para : parameters) {
			if (para.getName().equalsIgnoreCase(key)) {
				result.add(para);
			}
		}
		return result;
	}

	/**
	 * 根据参数的key和type查找IParameter对象
	 * 考虑了同名函数的情况，但这种情况很少，几乎用不上
	 * 尽量不要使用这个函数
	 */
	@Deprecated
	public static List<IParameter> findParametersByKeyAndType(List<IParameter> parameters, String key, byte type) {
		List<IParameter> result = new ArrayList<IParameter>();
		for (IParameter para : parameters) {
			if (para.getName().equalsIgnoreCase(key) && para.getType() == type) {
				result.add(para);
			}
		}
		return result;
	}

	/**
	 * 考虑了同名函数的情况，但这种情况很少，几乎用不上
	 * 尽量不要使用这个函数
	 */
	@Deprecated
	public List<IParameter> getParametersByKeyAndType(IHttpRequestResponse messageInfo, String key, byte type) {
		IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
		List<IParameter> paras = analyzeRequest.getParameters();
		return findParametersByKeyAndType(paras, key, type);
	}

	/**
	 * 考虑了同名函数的情况，但这种情况很少，几乎用不上
	 * 尽量不要使用这个函数
	 */
	@Deprecated
	public List<IParameter> getParametersByKeyAndType(byte[] request, String key, byte type) {
		IRequestInfo analyzeRequest = helpers.analyzeRequest(request);
		return findParametersByKeyAndType(analyzeRequest.getParameters(), key, type);
	}


	public IHttpRequestResponse addOrUpdateParameter(IHttpRequestResponse messageInfo, IParameter para) {
		byte[] request = messageInfo.getRequest();
		request = addOrUpdateParameter(request, para);
		messageInfo.setRequest(request);
		return messageInfo;
	}

	public byte[] addOrUpdateParameter(byte[] request, IParameter para) {
		IParameter existPara = helpers.getRequestParameter(request, para.getName());
		if (null != existPara) {
			request = helpers.removeParameter(request, existPara);
		}
		request = helpers.addParameter(request, para);
		return request;
	}

	public IHttpRequestResponse removeParameter(IHttpRequestResponse messageInfo, IParameter parameter) {
		byte[] request = messageInfo.getRequest();
		request = helpers.removeParameter(request, parameter);
		messageInfo.setRequest(request);
		return messageInfo;
	}


	public String getMethod(IHttpRequestResponse messageInfo) {
		if (messageInfo == null || messageInfo.getRequest() == null) {
			return null;
		}
		IRequestInfo analyzedRequest = helpers.analyzeRequest(messageInfo.getRequest());
		return analyzedRequest.getMethod();
	}

	public String getMethod(byte[] request) {
		if (request == null) {
			return null;
		}
		try {
			IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
			return analyzedRequest.getMethod();
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * 仅仅修改数据包的请求方法
	 */
	public IHttpRequestResponse changeMethod(IHttpRequestResponse messageInfo,String method) {
		byte[] newReq = changeMethod(messageInfo.getRequest(),method);
		messageInfo.setRequest(newReq);
		return messageInfo;
	}

	/**
	 * 仅仅修改数据包的请求方法
	 */
	public byte[] changeMethod(byte[] request,String method) {
		IRequestInfo analyzeRequest = helpers.analyzeRequest(request);
		List<String> headers = analyzeRequest.getHeaders();
		byte[] body = getBody(true, request);
		String firstLine = headers.get(0);
		String line = firstLine.substring(firstLine.indexOf(" "));
		firstLine = method + line;
		headers.remove(0);
		headers.add(0, firstLine);

		byte[] newReq = helpers.buildHttpMessage(headers, body);
		return newReq;
	}

	public String detectCharset(boolean isRequest, byte[] requestOrResponse) {

		String contentType = getHeaderValueOf(isRequest, requestOrResponse, "Content-Type");

		//1、尝试从 content-type 中获取
		//   原实现用 split("charset=")[1]: Content-Type 里只有 charset= 而没有值时会抛
		//   ArrayIndexOutOfBoundsException; 值后面常跟 "; xxx" 或引号, 一并处理掉。
		//   另外原来直接 return getCharsetName(...), 遇到不认识的编码名会返回 null,
		//   而不是继续用 body/meta 兜底判断, 这里改成"取到才返回"。
		if (contentType != null) {
		    int charsetIdx = contentType.toLowerCase(Locale.ROOT).indexOf("charset=");
		    if (charsetIdx >= 0) {
		        String tmpcharSet = contentType.substring(charsetIdx + "charset=".length());
		        int end = tmpcharSet.indexOf(';');
		        if (end >= 0) {
		            tmpcharSet = tmpcharSet.substring(0, end);
		        }
		        tmpcharSet = tmpcharSet.trim();
		        if (tmpcharSet.length() >= 2
		                && tmpcharSet.charAt(0) == '"'
		                && tmpcharSet.charAt(tmpcharSet.length() - 1) == '"') {
		            tmpcharSet = tmpcharSet.substring(1, tmpcharSet.length() - 1);
		        }
		        if (StringUtils.isNotEmpty(tmpcharSet)) {
		            String charsetName = CharsetUtils.getCharsetName(tmpcharSet);
		            if (charsetName != null) {
		                return charsetName;
		            }
		        }
		    }
		}

		String charset = detectCharsetInBody(isRequest, requestOrResponse);
		if (StringUtils.isNotEmpty(charset)) {
			return CharsetUtils.getCharsetName(charset);
		}

		return CharsetUtils.detectCharset(requestOrResponse);
	}

	/**
	 * 尝试在响应包中寻找meta charset的标签，来判别响应包的编码
	 * <p>
	 * 一些常见格式：
	 * <meta HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
	 * <meta charset="UTF-8">
	 * <meta charset="utf-8">
	 * <meta charset=utf-8>
	 * <meta http-equiv="Content-Language" content="zh-CN">
	 * <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	 * <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
	 * <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	 */
	public static String detectCharsetInBody(boolean isRequest, byte[] requestOrResponse) {
		String body = new String(getBody(isRequest, requestOrResponse));
		String pattern = "charset=(.*?)[\"/\\s>]+";//加? 非贪婪模式

		Pattern metaCharset = Pattern.compile(pattern);
		Matcher matcher = metaCharset.matcher(body);
		if (matcher.find()) {//多次查找
			String charset = matcher.group(1);
			return charset;
		}
		return null;
	}


	public boolean isJSON(byte[] content, boolean isRequest) {
	    if (content == null) {
	        return false;
	    }
	    if (isRequest) {
	        return requireHelpers().analyzeRequest(content).getContentType() == IRequestInfo.CONTENT_TYPE_JSON;
	    }
	    // getStatedMimeType()/getInferredMimeType() 在识别不出时可能返回 null,
	    // 原实现直接 .toLowerCase() 会 NPE
	    IResponseInfo responseInfo = requireHelpers().analyzeResponse(content);
	    return containsIgnoreCase(responseInfo.getStatedMimeType(), "json")
	            || containsIgnoreCase(responseInfo.getInferredMimeType(), "json");
	}

	/**
	 * 判断数据包的内容，是否是HTML（主要用于判断响应包）
	 *
	 * @param content
	 * @param isRequest
	 * @return
	 */
	public boolean isHtml(byte[] content, boolean isRequest) {
	    if (isRequest || content == null) {
	        return false;
	    }
	    IResponseInfo responseInfo = requireHelpers().analyzeResponse(content);
	    return containsIgnoreCase(responseInfo.getStatedMimeType(), "html")
	            || containsIgnoreCase(responseInfo.getInferredMimeType(), "html");
	}


	/**
	 * 判断数据包的内容，是否是JavaScript（主要用于判断响应包）
	 *
	 * @param content
	 * @param isRequest
	 * @return
	 */
	public boolean isJavaScript(byte[] content, boolean isRequest) {
	    if (isRequest || content == null) {
	        return false;
	    }
	    IResponseInfo responseInfo = requireHelpers().analyzeResponse(content);
	    return containsIgnoreCase(responseInfo.getStatedMimeType(), "script")
	            || containsIgnoreCase(responseInfo.getInferredMimeType(), "script");
	}

	public String getHTTPBasicCredentials(IHttpRequestResponse messageInfo) throws Exception {
	    String authHeader = getHeaderValueOf(true, messageInfo, "Authorization");
	    if (authHeader == null) {
	        // 原实现直接 .trim() 会抛 NPE, 调用方拿到的异常语义还不清楚
	        throw new Exception("No Authorization header in request");
	    }
	    authHeader = authHeader.trim();
	    String[] parts = authHeader.split("\\s");

		if (parts.length != 2)
			throw new Exception("Wrong number of HTTP Authorization header parts");

		if (!parts[0].equalsIgnoreCase("Basic"))
			throw new Exception("HTTP authentication must be Basic");

		return parts[1];
	}

	private static void test1() {
		List<String> headerList = new ArrayList<String>();
		headerList.add("User-Agent: sssss");
		headerList.add("Use: sssss");
		headerList.add("User: sssss");
		headerList.add("Agent: sssss");
		List<String> newHeader = removeHeader(headerList, "Use");
		System.out.println(newHeader.toString());
		newHeader = addOrUpdateHeader(headerList, "Use1", "xxxx");
		System.out.println(newHeader.toString());
	}

	private static void test2() {
		String url = "http://www.baidu.com";
		String url2 = "https://www.baidu.com:443";
		System.out.println(addUrlDefaultPort(url));
		System.out.println(removeUrlDefaultPort(url2));
		System.out.println(removeUrlDefaultPort(url));
		System.out.println(addUrlDefaultPort(url));
	}

	public static void main(String args[]) {
		test2();
	}
}
