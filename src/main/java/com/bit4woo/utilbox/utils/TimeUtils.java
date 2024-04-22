package com.bit4woo.utilbox.utils;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class TimeUtils {

    public static Long getTimestamp(Date date){
        if (null == date) {
            return (long) 0;
        }
        return date.getTime();
    }

    /*
     * 	标准的时间格式要求 2020-12-11 12:00:00
     * 	效果如同 https://tool.lu/timestamp/
     */
    public static Long getTimestamp(String date) throws Exception{
        if (null == date) {
            return (long) 0;
        }
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return dateFormat.parse(date).getTime();
    }

    public static String timeStr() {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");//设置日期格式
        String time = df.format(new Date());// new Date()为获取当前系统时间
        return time;
    }

    public static String timePlusOrSub(long sec) {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");//设置日期格式
        String time = df.format(new Date(new Date().getTime() + sec * 1000));// new Date()为获取当前系统时间
        return time;
    }
}
