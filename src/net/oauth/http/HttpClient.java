/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.http;

import java.io.IOException;

public abstract interface HttpClient {
	public static final String GET = "GET";
	public static final String POST = "POST";
	public static final String PUT = "PUT";
	public static final String DELETE = "DELETE";

	public abstract HttpResponseMessage execute(HttpMessage paramHttpMessage) throws IOException;
}