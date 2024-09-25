package com.bit4woo.utilbox.utils.test;

import com.bit4woo.utilbox.utils.UrlUtils;

public class Test {

	public static void main(String[] args) throws Exception {
        String aaa = "https://api.example.vn:443/Execute?a=b&c=d#1653013013763 /*";
        String bbb = "https://api.example.vn/Execute#1653013013763";
        
        System.out.println(UrlUtils.getFile(aaa));
        System.out.println(UrlUtils.getPath(bbb));
    }
}
