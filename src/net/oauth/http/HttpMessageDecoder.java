/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.http;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

public class HttpMessageDecoder extends HttpResponseMessage {
	public static final String GZIP = "gzip";
	public static final String DEFLATE = "deflate";
	public static final String ACCEPTED = "gzip,deflate";
	private final HttpResponseMessage in;

	public static HttpResponseMessage decode(HttpResponseMessage message) throws IOException {
		if (message != null) {
			String encoding = getEncoding(message);
			if (encoding != null) {
				return new HttpMessageDecoder(message, encoding);
			}
		}
		return message;
	}

	private static String getEncoding(HttpMessage message) {
		String encoding = message.getHeader("Content-Encoding");
		if (encoding != null) {
			if (("gzip".equalsIgnoreCase(encoding)) || ("x-gzip".equalsIgnoreCase(encoding)))
				return "gzip";
			if ("deflate".equalsIgnoreCase(encoding))
				return "deflate";
		}
		return null;
	}

	private HttpMessageDecoder(HttpResponseMessage in, String encoding)
            throws IOException {
        super(in.method, in.url);
        this.headers.addAll(in.headers);
        removeHeaders(CONTENT_ENCODING); // handled here
        removeHeaders(CONTENT_LENGTH); // unpredictable
        InputStream body = in.getBody();
        if (body != null) {
            if (encoding == GZIP) {
                body = new GZIPInputStream(body);
            } else if (encoding == DEFLATE) {
                body = new InflaterInputStream(body);
            } else {
                assert false;
            }
        }
        this.body = body;
        this.in = in;
    }


	public void dump(Map<String, Object> into) throws IOException {
		this.in.dump(into);
	}

	public int getStatusCode() throws IOException {
		return this.in.getStatusCode();
	}
}