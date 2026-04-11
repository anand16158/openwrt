#include "device_fingerprint.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>

#define FP_MAX_DEVICES  128

static const char *device_type_names[] = {
	[DEV_UNKNOWN]        = "unknown",
	[DEV_ANDROID]        = "Android",
	[DEV_IPHONE]         = "iPhone/iPad",
	[DEV_WINDOWS]        = "Windows",
	[DEV_MACOS]          = "macOS",
	[DEV_LINUX]          = "Linux",
	[DEV_SMART_TV]       = "Smart TV",
	[DEV_IOT]            = "IoT",
	[DEV_GAMING_CONSOLE] = "Game Console",
	[DEV_OTHER]          = "other",
};

struct device_fp_ctx {
	struct device_evidence devices[FP_MAX_DEVICES];
	bool oui_applied[FP_MAX_DEVICES];
	int count;
	struct dns_cache *dc;
};

struct dns_fp_rule {
	const char *domain;
	enum device_type type;
	int weight;
};

/*
 * DNS-based fingerprinting rules.
 * Devices make characteristic DNS queries that reveal their OS.
 */
static const struct dns_fp_rule dns_rules[] = {
	/* Android */
	{ "connectivitycheck.gstatic.com",   DEV_ANDROID, 5 },
	{ "connectivitycheck.android.com",   DEV_ANDROID, 5 },
	{ "clients3.google.com",             DEV_ANDROID, 3 },
	{ "play.googleapis.com",             DEV_ANDROID, 3 },
	{ "mtalk.google.com",                DEV_ANDROID, 4 },
	{ "android.googleapis.com",          DEV_ANDROID, 4 },
	{ "android.clients.google.com",      DEV_ANDROID, 4 },
	{ "play.google.com",                 DEV_ANDROID, 2 },
	{ "firebaseinstallations.googleapis.com", DEV_ANDROID, 2 },

	/* Apple iOS / iPadOS */
	{ "captive.apple.com",               DEV_IPHONE,  5 },
	{ "gsp-ssl.ls.apple.com",            DEV_IPHONE,  4 },
	{ "gs-loc.apple.com",                DEV_IPHONE,  4 },
	{ "push.apple.com",                  DEV_IPHONE,  4 },
	{ "init.ess.apple.com",              DEV_IPHONE,  3 },
	{ "mesu.apple.com",                  DEV_IPHONE,  3 },
	{ "xp.apple.com",                    DEV_IPHONE,  3 },
	{ "identity.apple.com",              DEV_IPHONE,  3 },
	{ "icloud-content.com",              DEV_IPHONE,  2 },
	{ "icloud.com",                      DEV_IPHONE,  2 },

	/* macOS (shares some with iOS; these are macOS-specific) */
	{ "swscan.apple.com",                DEV_MACOS,   4 },
	{ "osrecovery.apple.com",            DEV_MACOS,   5 },
	{ "configuration.apple.com",         DEV_MACOS,   3 },
	{ "gdmf.apple.com",                  DEV_MACOS,   3 },

	/* Windows */
	{ "www.msftconnecttest.com",         DEV_WINDOWS, 5 },
	{ "msftconnecttest.com",             DEV_WINDOWS, 5 },
	{ "dns.msftncsi.com",                DEV_WINDOWS, 5 },
	{ "windowsupdate.com",               DEV_WINDOWS, 4 },
	{ "update.microsoft.com",            DEV_WINDOWS, 4 },
	{ "settings-win.data.microsoft.com", DEV_WINDOWS, 4 },
	{ "login.live.com",                  DEV_WINDOWS, 3 },
	{ "wns.windows.com",                 DEV_WINDOWS, 3 },
	{ "v10.events.data.microsoft.com",   DEV_WINDOWS, 3 },
	{ "telemetry.microsoft.com",         DEV_WINDOWS, 2 },

	/* Linux */
	{ "connectivity-check.ubuntu.com",   DEV_LINUX,   5 },
	{ "nmcheck.gnome.org",               DEV_LINUX,   5 },
	{ "network-test.debian.org",         DEV_LINUX,   5 },
	{ "fedoraproject.org",               DEV_LINUX,   4 },
	{ "archlinux.org",                   DEV_LINUX,   4 },
	{ "ntp.ubuntu.com",                  DEV_LINUX,   3 },

	/* Smart TVs */
	{ "samsungcloudsolution.net",        DEV_SMART_TV, 5 },
	{ "samsungcloudsolution.com",        DEV_SMART_TV, 5 },
	{ "samsungosp.com",                  DEV_SMART_TV, 4 },
	{ "lgtvsdp.com",                     DEV_SMART_TV, 5 },
	{ "lgappstv.com",                    DEV_SMART_TV, 5 },
	{ "lgsmartad.com",                   DEV_SMART_TV, 4 },
	{ "roku.com",                        DEV_SMART_TV, 5 },
	{ "rokutime.com",                    DEV_SMART_TV, 4 },
	{ "fire-tv-settings.amazon.com",     DEV_SMART_TV, 5 },
	{ "device-metrics-us.amazon.com",    DEV_SMART_TV, 3 },
	{ "tplinkcloud.com",                 DEV_SMART_TV, 3 },

	/* IoT devices */
	{ "mqtt.googleapis.com",             DEV_IOT,     3 },
	{ "pool.ntp.org",                    DEV_IOT,     1 },
	{ "time.google.com",                 DEV_IOT,     1 },
	{ "time.windows.com",               DEV_IOT,     1 },
	{ "smartthings.com",                 DEV_IOT,     5 },
	{ "tuya.com",                        DEV_IOT,     5 },
	{ "tuyaus.com",                      DEV_IOT,     5 },
	{ "alexa.amazon.com",                DEV_IOT,     4 },
	{ "device-advice-bootstrap.amazon.com", DEV_IOT,  5 },
	{ "nest.com",                        DEV_IOT,     5 },
	{ "home.nest.com",                   DEV_IOT,     5 },
	{ "ring.com",                        DEV_IOT,     5 },
	{ "philips-hue.com",                 DEV_IOT,     5 },
	{ "ewelink.cc",                      DEV_IOT,     5 },
	{ "shelly.cloud",                    DEV_IOT,     5 },

	/* Gaming consoles */
	{ "playstation.net",                 DEV_GAMING_CONSOLE, 5 },
	{ "playstation.com",                 DEV_GAMING_CONSOLE, 4 },
	{ "xboxlive.com",                    DEV_GAMING_CONSOLE, 5 },
	{ "xbox.com",                        DEV_GAMING_CONSOLE, 4 },
	{ "xsts.auth.xboxlive.com",         DEV_GAMING_CONSOLE, 5 },
	{ "nintendo.net",                    DEV_GAMING_CONSOLE, 5 },
	{ "nintendo.com",                    DEV_GAMING_CONSOLE, 4 },
	{ "nintendowifi.net",                DEV_GAMING_CONSOLE, 5 },

	{ NULL, 0, 0 }
};

/* OUI (first 3 bytes of MAC) hints for device type */
struct oui_rule {
	uint8_t oui[3];
	enum device_type type;
	int weight;
};

static const struct oui_rule oui_rules[] = {
	/* Samsung (common for phones + TVs, low weight) */
	{{ 0x00, 0x1A, 0x8A }, DEV_ANDROID,        1 },
	/* Apple */
	{{ 0x00, 0x03, 0x93 }, DEV_IPHONE,          2 },
	{{ 0x3C, 0x22, 0xFB }, DEV_IPHONE,          2 },
	{{ 0xF0, 0x18, 0x98 }, DEV_IPHONE,          2 },
	{{ 0xA4, 0x83, 0xE7 }, DEV_IPHONE,          2 },
	/* Raspberry Pi → Linux/IoT */
	{{ 0xB8, 0x27, 0xEB }, DEV_LINUX,            2 },
	{{ 0xDC, 0xA6, 0x32 }, DEV_LINUX,            2 },
	/* Amazon (Echo, Fire) */
	{{ 0x74, 0xC2, 0x46 }, DEV_IOT,              2 },
	{{ 0xFC, 0x65, 0xDE }, DEV_IOT,              2 },
	/* Roku */
	{{ 0xDC, 0x3A, 0x5E }, DEV_SMART_TV,         3 },
	{{ 0xB0, 0xA7, 0x37 }, DEV_SMART_TV,         3 },
	/* Sony (PlayStation) */
	{{ 0x00, 0x04, 0x1F }, DEV_GAMING_CONSOLE,   2 },
	{{ 0x28, 0x3F, 0x69 }, DEV_GAMING_CONSOLE,   2 },
	/* Nintendo */
	{{ 0x00, 0x1F, 0x32 }, DEV_GAMING_CONSOLE,   2 },
	{{ 0x00, 0x17, 0xAB }, DEV_GAMING_CONSOLE,   2 },
	/* Microsoft (Xbox) */
	{{ 0x7C, 0xED, 0x8D }, DEV_GAMING_CONSOLE,   2 },

	{{ 0, 0, 0 }, 0, 0 }
};

struct device_fp_ctx *device_fp_init(struct dns_cache *dc)
{
	struct device_fp_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;
	ctx->dc = dc;
	syslog(LOG_INFO, "device_fp: initialized (%d DNS rules, %d OUI rules)",
	       (int)(sizeof(dns_rules) / sizeof(dns_rules[0]) - 1),
	       (int)(sizeof(oui_rules) / sizeof(oui_rules[0]) - 1));
	return ctx;
}

void device_fp_destroy(struct device_fp_ctx *ctx)
{
	free(ctx);
}

static struct device_evidence *find_or_create(struct device_fp_ctx *ctx,
					      const uint8_t *mac)
{
	for (int i = 0; i < ctx->count; i++) {
		if (memcmp(ctx->devices[i].mac, mac, 6) == 0)
			return &ctx->devices[i];
	}

	if (ctx->count >= FP_MAX_DEVICES)
		return NULL;

	struct device_evidence *ev = &ctx->devices[ctx->count++];
	memset(ev, 0, sizeof(*ev));
	memcpy(ev->mac, mac, 6);
	return ev;
}

static bool domain_suffix_match(const char *domain, const char *pattern)
{
	size_t dlen = strlen(domain);
	size_t plen = strlen(pattern);
	if (dlen < plen)
		return false;
	if (strcasecmp(domain + dlen - plen, pattern) != 0)
		return false;
	if (dlen > plen && domain[dlen - plen - 1] != '.')
		return false;
	return true;
}

static void apply_dns_rules(struct device_evidence *ev,
			    const char *domain)
{
	if (!domain || !domain[0])
		return;

	for (const struct dns_fp_rule *r = dns_rules; r->domain; r++) {
		if (domain_suffix_match(domain, r->domain)) {
			ev->votes[r->type] += r->weight;
			return;
		}
	}
}

static void apply_oui_rules(struct device_evidence *ev,
			    const uint8_t *mac)
{
	for (const struct oui_rule *r = oui_rules; r->weight > 0; r++) {
		if (mac[0] == r->oui[0] && mac[1] == r->oui[1] &&
		    mac[2] == r->oui[2]) {
			ev->votes[r->type] += r->weight;
			return;
		}
	}
}

static void resolve_device(struct device_evidence *ev)
{
	int max_votes = 0;
	int total_votes = 0;
	enum device_type best = DEV_UNKNOWN;

	for (int i = 0; i < MAX_DEVICE_TYPES; i++) {
		total_votes += ev->votes[i];
		if (ev->votes[i] > max_votes) {
			max_votes = ev->votes[i];
			best = (enum device_type)i;
		}
	}

	ev->best_guess = best;
	ev->confidence = (total_votes > 0) ?
		(float)max_votes / (float)total_votes : 0.0f;
	ev->resolved = (max_votes >= 3);
}

void device_fp_analyze_flow(struct device_fp_ctx *ctx,
			    const struct flow_entry *entry)
{
	if (!ctx)
		return;

	struct device_evidence *ev = find_or_create(ctx, entry->src_mac);
	if (!ev)
		return;

	/* DNS-based: check domain of destination */
	if (entry->dns_hint[0])
		apply_dns_rules(ev, entry->dns_hint);

	if (ctx->dc) {
		const char *dst_domain = dns_cache_lookup(ctx->dc,
							  &entry->key.dst_ip);
		if (dst_domain)
			apply_dns_rules(ev, dst_domain);
	}

	/* OUI-based: only apply once (first time we see this MAC) */
	int idx = ev - ctx->devices;
	if (idx >= 0 && idx < FP_MAX_DEVICES && !ctx->oui_applied[idx]) {
		apply_oui_rules(ev, entry->src_mac);
		ctx->oui_applied[idx] = true;
	}

	/*
	 * IoT behavioral hint: devices with very few unique destinations
	 * and small packets are likely IoT. We don't have full counters
	 * here but can check individual flow characteristics.
	 */
	uint32_t total_pkts = entry->stats.total_pkts_fwd +
			      entry->stats.total_pkts_bwd;
	uint64_t total_bytes = entry->stats.total_bytes_fwd +
			       entry->stats.total_bytes_bwd;

	if (total_pkts > 10 && total_bytes > 0) {
		float avg_pkt = (float)total_bytes / (float)total_pkts;

		/* Very small periodic traffic: IoT pattern */
		if (avg_pkt < 150 && total_pkts < 50 &&
		    entry->key.proto == 17 /* UDP */) {
			ev->votes[DEV_IOT] += 1;
		}
	}

	resolve_device(ev);
}

static const struct device_evidence *find_evidence(
	const struct device_fp_ctx *ctx, const uint8_t *mac)
{
	for (int i = 0; i < ctx->count; i++) {
		if (memcmp(ctx->devices[i].mac, mac, 6) == 0)
			return &ctx->devices[i];
	}
	return NULL;
}

enum device_type device_fp_get_type(const struct device_fp_ctx *ctx,
				    const uint8_t *mac)
{
	if (!ctx)
		return DEV_UNKNOWN;
	const struct device_evidence *ev = find_evidence(ctx, mac);
	return ev ? ev->best_guess : DEV_UNKNOWN;
}

const char *device_fp_get_name(const struct device_fp_ctx *ctx,
			       const uint8_t *mac)
{
	return device_type_to_name(device_fp_get_type(ctx, mac));
}

float device_fp_get_confidence(const struct device_fp_ctx *ctx,
			       const uint8_t *mac)
{
	if (!ctx)
		return 0.0f;
	const struct device_evidence *ev = find_evidence(ctx, mac);
	return ev ? ev->confidence : 0.0f;
}

const char *device_type_to_name(enum device_type dt)
{
	if (dt < MAX_DEVICE_TYPES)
		return device_type_names[dt];
	return "unknown";
}
