/** <a href="http://www.cpupk.com/decompiler">Eclipse Class Decompiler</a> plugin, Copyright (c) 2017 Chen Chao. **/
package net.oauth.nonce;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class InMemoryNonce extends TimestampExpiringNonce {
	protected static final ConcurrentMap<String, LinkedList<TimestampEntry>> TIMESTAMP_ENTRIES = new ConcurrentHashMap();

	public boolean validateNonce(String consumerKey, long timestamp, String nonce) {
		long cutoff = System.currentTimeMillis() / 1000L - getValidityWindowSeconds();
		if (!(super.validateNonce(consumerKey, timestamp, nonce))) {
			return false;
		}

		LinkedList entries = (LinkedList) TIMESTAMP_ENTRIES.get(consumerKey);
		if (entries == null) {
			entries = new LinkedList();
			TIMESTAMP_ENTRIES.put(consumerKey, entries);
		}

		synchronized (entries) {
			if (entries.isEmpty()) {
				entries.add(new TimestampEntry(timestamp, nonce));
			} else {
				boolean isNew = ((TimestampEntry) entries.getLast()).getTimestamp().longValue() < timestamp;
				ListIterator listIterator = entries.listIterator();
				while (listIterator.hasNext()) {
					TimestampEntry entry = (TimestampEntry) listIterator.next();
					if (entry.getTimestamp().longValue() < cutoff) {
						listIterator.remove();
						isNew = !(listIterator.hasNext());
					} else {
						if (isNew) {
							entries.addLast(new TimestampEntry(timestamp, nonce));
							return true;
						}
						if (entry.getTimestamp().longValue() == timestamp) {
							return (entry.addNonce(nonce));
						}

						if (entry.getTimestamp().longValue() <= timestamp)
							continue;
						entries.add(listIterator.previousIndex(), new TimestampEntry(timestamp, nonce));
						return true;
					}

				}

				entries.addLast(new TimestampEntry(timestamp, nonce));
			}
		}

		return true;
	}

	protected static class TimestampEntry {
		private final Long timestamp;
		private final Set<String> nonces = new HashSet();

		public TimestampEntry(long timestamp, String firstNonce) {
			this.timestamp = Long.valueOf(timestamp);
			this.nonces.add(firstNonce);
		}

		public boolean addNonce(String nonce) {
			synchronized (this.nonces) {
				return this.nonces.add(nonce);
			}
		}

		public Long getTimestamp() {
			return this.timestamp;
		}

		public int hashCode() {
			return this.timestamp.hashCode();
		}

		public boolean equals(Object obj) {
			return ((obj instanceof TimestampEntry) && (this.timestamp.equals(((TimestampEntry) obj).timestamp)));
		}
	}
}