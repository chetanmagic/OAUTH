/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class ConsumerProperties {
	private final Properties consumerProperties;
	private final Map<String, OAuthConsumer> pool;

	public static URL getResource(String name, ClassLoader loader) throws IOException {
		URL resource = loader.getResource(name);
		if (resource == null) {
			throw new IOException("resource not found: " + name);
		}
		return resource;
	}

	public static Properties getProperties(URL source) throws IOException {
		InputStream input = source.openStream();
		try {
			Properties p = new Properties();
			p.load(input);
			return p;
		} finally {
			input.close();
		}
	}

	public ConsumerProperties(String resourceName, ClassLoader loader) throws IOException {
		this(getProperties(getResource(resourceName, loader)));
	}

	public ConsumerProperties(Properties consumerProperties) {
		this.pool = new HashMap();

		this.consumerProperties = consumerProperties;
	}

	public OAuthConsumer getConsumer(String name) throws MalformedURLException {
		OAuthConsumer consumer;
		synchronized (this.pool) {
			consumer = (OAuthConsumer) this.pool.get(name);
		}
		if (consumer == null) {
			consumer = newConsumer(name);
		}
		synchronized (this.pool) {
			OAuthConsumer first = (OAuthConsumer) this.pool.get(name);
			if (first == null) {
				this.pool.put(name, consumer);
			} else {
				consumer = first;
			}
		}
		return consumer;
	}

	protected OAuthConsumer newConsumer(String name) throws MalformedURLException {
		String base = this.consumerProperties.getProperty(name + ".serviceProvider.baseURL");
		URL baseURL = new URL(base);
		OAuthServiceProvider serviceProvider = new OAuthServiceProvider(
				getURL(baseURL, name + ".serviceProvider.requestTokenURL"),
				getURL(baseURL, name + ".serviceProvider.userAuthorizationURL"),
				getURL(baseURL, name + ".serviceProvider.accessTokenURL"));
		OAuthConsumer consumer = new OAuthConsumer(this.consumerProperties.getProperty(name + ".callbackURL"),
				this.consumerProperties.getProperty(name + ".consumerKey"),
				this.consumerProperties.getProperty(name + ".consumerSecret"), serviceProvider);
		consumer.setProperty("name", name);
		if (baseURL != null) {
			consumer.setProperty("serviceProvider.baseURL", baseURL);
		}
		for (Map.Entry prop : this.consumerProperties.entrySet()) {
			String propName = (String) prop.getKey();
			if (propName.startsWith(name + ".consumer.")) {
				String c = propName.substring(name.length() + 10);
				consumer.setProperty(c, prop.getValue());
			}
		}
		return consumer;
	}

	private String getURL(URL base, String name) throws MalformedURLException {
		String url = this.consumerProperties.getProperty(name);
		if (base != null) {
			url = new URL(base, url).toExternalForm();
		}
		return url;
	}
}