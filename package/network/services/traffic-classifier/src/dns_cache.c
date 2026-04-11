#include "dns_cache.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <stdio.h>

static uint32_t dns_ip_hash(const struct in6_addr *ip)
{
	const uint32_t *w = (const uint32_t *)ip;
	uint32_t h = w[0] ^ w[1] ^ w[2] ^ w[3];
	return h % DNS_CACHE_BUCKETS;
}

struct dns_cache *dns_cache_create(int max_entries)
{
	struct dns_cache *dc = calloc(1, sizeof(*dc));
	if (!dc)
		return NULL;
	dc->max_entries = max_entries > 0 ? max_entries : DNS_MAX_ENTRIES;
	return dc;
}

void dns_cache_destroy(struct dns_cache *dc)
{
	if (!dc)
		return;

	for (int i = 0; i < DNS_CACHE_BUCKETS; i++) {
		struct dns_entry *e = dc->buckets[i];
		while (e) {
			struct dns_entry *next = e->hash_next;
			free(e);
			e = next;
		}
	}
	free(dc);
}

void dns_cache_insert(struct dns_cache *dc, const struct in6_addr *ip,
		      const char *domain, uint32_t ttl)
{
	uint32_t idx = dns_ip_hash(ip);
	time_t expiry = time(NULL) + (ttl > 0 ? ttl : DNS_TTL_DEFAULT);

	struct dns_entry *e = dc->buckets[idx];
	while (e) {
		if (memcmp(&e->ip, ip, sizeof(*ip)) == 0) {
			snprintf(e->domain, DNS_MAX_DOMAIN, "%s", domain);
			e->expires = expiry;
			return;
		}
		e = e->hash_next;
	}

	if (dc->count >= dc->max_entries)
		return;

	e = calloc(1, sizeof(*e));
	if (!e)
		return;

	memcpy(&e->ip, ip, sizeof(*ip));
	snprintf(e->domain, DNS_MAX_DOMAIN, "%s", domain);
	e->expires = expiry;

	e->hash_next = dc->buckets[idx];
	dc->buckets[idx] = e;
	dc->count++;
}

const char *dns_cache_lookup(const struct dns_cache *dc,
			     const struct in6_addr *ip)
{
	uint32_t idx = dns_ip_hash(ip);
	time_t now = time(NULL);

	struct dns_entry *e = dc->buckets[idx];
	while (e) {
		if (memcmp(&e->ip, ip, sizeof(*ip)) == 0)
			return (e->expires > now) ? e->domain : NULL;
		e = e->hash_next;
	}
	return NULL;
}

void dns_cache_expire(struct dns_cache *dc, time_t now)
{
	for (int i = 0; i < DNS_CACHE_BUCKETS; i++) {
		struct dns_entry **pp = &dc->buckets[i];
		while (*pp) {
			struct dns_entry *e = *pp;
			if (e->expires <= now) {
				*pp = e->hash_next;
				dc->count--;
				free(e);
			} else {
				pp = &e->hash_next;
			}
		}
	}
}

/* ---- Minimal DNS response parser ---- */

struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed));

static int dns_skip_name(const uint8_t *buf, uint16_t buf_len,
			 uint16_t *offset)
{
	int jumps = 0;
	while (*offset < buf_len && jumps < 16) {
		uint8_t len = buf[*offset];
		if (len == 0) {
			(*offset)++;
			return 0;
		}
		if ((len & 0xC0) == 0xC0) {
			*offset += 2;
			return 0;
		}
		*offset += 1 + len;
		jumps++;
	}
	return -1;
}

static int dns_read_name(const uint8_t *buf, uint16_t buf_len,
			 uint16_t offset, char *name, int name_size)
{
	int pos = 0;
	int jumps = 0;
	uint16_t off = offset;

	while (off < buf_len && jumps < 16) {
		uint8_t len = buf[off];
		if (len == 0) {
			if (pos > 0)
				pos--;
			name[pos] = '\0';
			return 0;
		}
		if ((len & 0xC0) == 0xC0) {
			if (off + 1 >= buf_len)
				return -1;
			off = ((len & 0x3F) << 8) | buf[off + 1];
			jumps++;
			continue;
		}
		off++;
		for (int i = 0; i < len && off < buf_len; i++, off++) {
			if (pos < name_size - 2)
				name[pos++] = buf[off];
		}
		name[pos++] = '.';
	}
	return -1;
}

void dns_cache_parse_response(struct dns_cache *dc,
			      const uint8_t *data, uint16_t len)
{
	if (len < sizeof(struct dns_header))
		return;

	const struct dns_header *hdr = (const struct dns_header *)data;
	uint16_t flags = ntohs(hdr->flags);

	/* QR=1 (response) and RCODE=0 (no error) */
	if (!(flags & 0x8000) || (flags & 0x000F))
		return;

	uint16_t qdcount = ntohs(hdr->qdcount);
	uint16_t ancount = ntohs(hdr->ancount);
	if (ancount == 0)
		return;

	uint16_t offset = sizeof(struct dns_header);

	char qname[DNS_MAX_DOMAIN] = {};
	if (qdcount > 0)
		dns_read_name(data, len, offset, qname, sizeof(qname));

	for (uint16_t i = 0; i < qdcount; i++) {
		if (dns_skip_name(data, len, &offset) < 0)
			return;
		offset += 4;
		if (offset > len)
			return;
	}

	for (uint16_t i = 0; i < ancount && offset < len; i++) {
		if (dns_skip_name(data, len, &offset) < 0)
			return;

		if (offset + 10 > len)
			return;

		uint16_t rtype = (data[offset] << 8) | data[offset + 1];
		uint32_t ttl   = (data[offset + 4] << 24) | (data[offset + 5] << 16) |
				 (data[offset + 6] << 8)  | data[offset + 7];
		uint16_t rdlen = (data[offset + 8] << 8) | data[offset + 9];
		offset += 10;

		if (offset + rdlen > len)
			return;

		const char *domain = qname[0] ? qname : "unknown";

		if (rtype == 1 && rdlen == 4) {
			struct in6_addr ip = {};
			ip.s6_addr[10] = 0xff;
			ip.s6_addr[11] = 0xff;
			memcpy(&ip.s6_addr[12], data + offset, 4);
			dns_cache_insert(dc, &ip, domain, ttl);
		} else if (rtype == 28 && rdlen == 16) {
			struct in6_addr ip;
			memcpy(&ip, data + offset, 16);
			dns_cache_insert(dc, &ip, domain, ttl);
		}

		offset += rdlen;
	}
}
