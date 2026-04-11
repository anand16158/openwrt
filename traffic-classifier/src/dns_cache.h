#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <stdint.h>
#include <netinet/in.h>
#include <time.h>

#define DNS_CACHE_BUCKETS 512
#define DNS_MAX_DOMAIN    128
#define DNS_TTL_DEFAULT   300
#define DNS_MAX_ENTRIES   4096

struct dns_entry {
	struct in6_addr ip;
	char domain[DNS_MAX_DOMAIN];
	time_t expires;
	struct dns_entry *hash_next;
};

struct dns_cache {
	struct dns_entry *buckets[DNS_CACHE_BUCKETS];
	int count;
	int max_entries;
};

struct dns_cache *dns_cache_create(int max_entries);
void dns_cache_destroy(struct dns_cache *dc);

void dns_cache_insert(struct dns_cache *dc, const struct in6_addr *ip,
		      const char *domain, uint32_t ttl);
const char *dns_cache_lookup(const struct dns_cache *dc,
			     const struct in6_addr *ip);
void dns_cache_expire(struct dns_cache *dc, time_t now);

/*
 * Parse a DNS response packet (starting at the DNS header, not UDP)
 * and insert A/AAAA answer records into the cache.
 */
void dns_cache_parse_response(struct dns_cache *dc,
			      const uint8_t *dns_payload, uint16_t dns_len);

#endif
