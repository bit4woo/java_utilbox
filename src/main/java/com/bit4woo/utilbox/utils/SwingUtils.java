package com.bit4woo.utilbox.utils;

import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public class SwingUtils {

	public SwingUtils() {
		// TODO Auto-generated constructor stub
	}
	
	public static void main(String[] args) {
		System.out.print(showTextAreaDialog("aaaa"));
	}
	
	
	/**
	 * 显示Text，让用户修改确认
	 * @param text
	 * @return
	 */
	public static String showTextAreaDialog(String text) {
		// 创建一个 JTextArea
		JTextArea textArea = new JTextArea(10, 20); // 设置行数和列数
		// 将 JTextArea 放入 JScrollPane 中，以便可以滚动查看
		textArea.setText(text);
		JScrollPane scrollPane = new JScrollPane(textArea);
		// 显示包含 JTextArea 的对话框
		int result = JOptionPane.showOptionDialog(
				null, // parentComponent
				scrollPane, // message
				"Edit or Comfirm Text", // title
				JOptionPane.OK_CANCEL_OPTION, // optionType
				JOptionPane.PLAIN_MESSAGE, // messageType
				null, // icon
				null, // options
				null // initialValue
				);

		// 处理用户输入
		if (result == JOptionPane.OK_OPTION) {
			return textArea.getText();
		}
		return null;
	}

}
