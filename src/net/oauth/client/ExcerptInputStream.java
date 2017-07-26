/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.client;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ExcerptInputStream extends BufferedInputStream {
	public static final byte[] ELLIPSIS = " ...".getBytes();
	private static final int LIMIT = 1024;
	private byte[] excerpt = new byte[1024 + ELLIPSIS.length];

	public ExcerptInputStream(InputStream in) throws IOException {
		super(in);
		mark(1024);
		int total = 0;
		int read;
		while ((read = read(excerpt, total, LIMIT - total)) != -1 && ((total += read) < LIMIT));
		if (total == 1024) {
			System.arraycopy(ELLIPSIS, 0, this.excerpt, total, ELLIPSIS.length);
		} else {
			byte[] tmp = new byte[total];
			System.arraycopy(this.excerpt, 0, tmp, 0, total);
			this.excerpt = tmp;
		}
		reset();
	}

	public byte[] getExcerpt() {
		return this.excerpt;
	}
}