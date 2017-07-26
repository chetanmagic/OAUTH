/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.http;

import java.io.IOException;
import java.net.URL;
import java.util.Map;

public abstract class HttpResponseMessage extends HttpMessage {
	public static final String LOCATION = "Location";
	public static final String STATUS_CODE = "HTTP status";
	public static final int STATUS_OK = 200;
	public static final String EOL = "\r\n";

	protected HttpResponseMessage(String method, URL url) {
		super(method, url);
	}

	public void dump(Map<String, Object> into) throws IOException {
		super.dump(into);
		into.put("HTTP status", Integer.valueOf(getStatusCode()));
		String location = getHeader("Location");
		if (location != null)
			into.put("Location", location);
	}

	public abstract int getStatusCode() throws IOException;
}