/**
 * 
 */
package com.soffid.iam.agent.sqlserver;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * @author (C) Soffid 2014
 *
 */
public class Messages {
	private static final String BUNDLE_NAME = "com.soffid.iam.agent.oracle.messages"; //$NON-NLS-1$

	private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle
			.getBundle(BUNDLE_NAME);

	private Messages() {
	}

	public static String getString(String key) {
		try {
			return RESOURCE_BUNDLE.getString(key);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}
}
