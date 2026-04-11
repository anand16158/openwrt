#include "classifier.h"
#include "tc_model.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>

struct classifier_ctx {
	char *model_path;
	bool model_loaded;
	struct dns_cache *dc;
};

struct classifier_ctx *classifier_init(const char *model_path,
				       struct dns_cache *dc)
{
	struct classifier_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	if (model_path)
		ctx->model_path = strdup(model_path);

	ctx->dc = dc;
	ctx->model_loaded = tc_model_available() ? true : false;

	if (ctx->model_loaded)
		syslog(LOG_INFO, "classifier: ML model loaded (treelite)");
	else
		syslog(LOG_INFO, "classifier: domain-aware heuristic engine"
		       " (no ML model compiled in)");
	return ctx;
}

void classifier_destroy(struct classifier_ctx *ctx)
{
	if (!ctx)
		return;
	free(ctx->model_path);
	free(ctx);
}

/* ---- Domain-based classification ---- */

struct domain_rule {
	const char *suffix;
	enum traffic_class cls;
	float confidence;
};

static const struct domain_rule domain_rules[] = {
	/* Video streaming */
	{ "youtube.com",        CLASS_VIDEO,    0.95f },
	{ "ytimg.com",          CLASS_VIDEO,    0.90f },
	{ "googlevideo.com",    CLASS_VIDEO,    0.95f },
	{ "netflix.com",        CLASS_VIDEO,    0.95f },
	{ "nflxvideo.net",      CLASS_VIDEO,    0.95f },
	{ "hotstar.com",        CLASS_VIDEO,    0.90f },
	{ "hotstar.in",         CLASS_VIDEO,    0.90f },
	{ "jiocinema.com",      CLASS_VIDEO,    0.90f },
	{ "primevideo.com",     CLASS_VIDEO,    0.90f },
	{ "amazonvideo.com",    CLASS_VIDEO,    0.90f },
	{ "twitch.tv",          CLASS_VIDEO,    0.90f },
	{ "ttvnw.net",          CLASS_VIDEO,    0.90f },
	{ "vimeo.com",          CLASS_VIDEO,    0.85f },
	{ "dailymotion.com",    CLASS_VIDEO,    0.85f },
	{ "disneyplus.com",     CLASS_VIDEO,    0.90f },
	{ "sonyliv.com",        CLASS_VIDEO,    0.85f },
	{ "zee5.com",           CLASS_VIDEO,    0.85f },
	{ "mxplayer.in",        CLASS_VIDEO,    0.85f },

	/* Social media */
	{ "whatsapp.net",       CLASS_SOCIAL,   0.90f },
	{ "whatsapp.com",       CLASS_SOCIAL,   0.90f },
	{ "facebook.com",       CLASS_SOCIAL,   0.85f },
	{ "fbcdn.net",          CLASS_SOCIAL,   0.85f },
	{ "instagram.com",      CLASS_SOCIAL,   0.85f },
	{ "cdninstagram.com",   CLASS_SOCIAL,   0.85f },
	{ "twitter.com",        CLASS_SOCIAL,   0.80f },
	{ "x.com",              CLASS_SOCIAL,   0.80f },
	{ "twimg.com",          CLASS_SOCIAL,   0.80f },
	{ "tiktok.com",         CLASS_SOCIAL,   0.85f },
	{ "tiktokcdn.com",      CLASS_SOCIAL,   0.85f },
	{ "snapchat.com",       CLASS_SOCIAL,   0.85f },
	{ "snap.com",           CLASS_SOCIAL,   0.80f },
	{ "telegram.org",       CLASS_SOCIAL,   0.85f },
	{ "t.me",               CLASS_SOCIAL,   0.85f },
	{ "reddit.com",         CLASS_SOCIAL,   0.75f },
	{ "redd.it",            CLASS_SOCIAL,   0.75f },
	{ "linkedin.com",       CLASS_SOCIAL,   0.75f },
	{ "threads.net",        CLASS_SOCIAL,   0.80f },

	/* VoIP / Video calling */
	{ "zoom.us",            CLASS_VOIP,     0.95f },
	{ "zoom.com",           CLASS_VOIP,     0.90f },
	{ "zoomgov.com",        CLASS_VOIP,     0.90f },
	{ "jiomeet.com",        CLASS_VOIP,     0.90f },
	{ "webex.com",          CLASS_VOIP,     0.90f },
	{ "gotomeeting.com",    CLASS_VOIP,     0.85f },

	/* Gaming */
	{ "steampowered.com",   CLASS_GAMING,   0.85f },
	{ "steamcontent.com",   CLASS_GAMING,   0.80f },
	{ "epicgames.com",      CLASS_GAMING,   0.85f },
	{ "unrealengine.com",   CLASS_GAMING,   0.80f },
	{ "riotgames.com",      CLASS_GAMING,   0.85f },
	{ "garena.com",         CLASS_GAMING,   0.85f },
	{ "supercell.com",      CLASS_GAMING,   0.80f },
	{ "mihoyo.com",         CLASS_GAMING,   0.80f },
	{ "hoyoverse.com",      CLASS_GAMING,   0.80f },
	{ "pubg.com",           CLASS_GAMING,   0.85f },
	{ "playbattlegrounds.com", CLASS_GAMING, 0.85f },
	{ "ea.com",             CLASS_GAMING,   0.75f },
	{ "activision.com",     CLASS_GAMING,   0.80f },

	/* Download / Updates */
	{ "dl.google.com",      CLASS_DOWNLOAD, 0.85f },
	{ "play.google.com",    CLASS_DOWNLOAD, 0.80f },
	{ "gvt1.com",           CLASS_DOWNLOAD, 0.80f },
	{ "apple.com",          CLASS_DOWNLOAD, 0.60f },
	{ "mzstatic.com",       CLASS_DOWNLOAD, 0.75f },
	{ "windowsupdate.com",  CLASS_DOWNLOAD, 0.90f },
	{ "download.microsoft.com", CLASS_DOWNLOAD, 0.90f },

	{ NULL, 0, 0 }
};

static bool domain_matches(const char *domain, const char *pattern)
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

static bool classify_by_domain(struct flow_entry *entry,
			       struct dns_cache *dc)
{
	const char *domain = entry->dns_hint;

	if (!domain[0] && dc) {
		const char *name = dns_cache_lookup(dc, &entry->key.dst_ip);
		if (!name)
			name = dns_cache_lookup(dc, &entry->key.src_ip);
		if (name)
			snprintf(entry->dns_hint, sizeof(entry->dns_hint),
				 "%s", name);
		domain = entry->dns_hint;
	}

	if (!domain[0])
		return false;

	/*
	 * Google Meet / Teams / FaceTime use domains that overlap with
	 * their parent companies; check specific subdomains first.
	 */
	if (domain_matches(domain, "meet.google.com") ||
	    domain_matches(domain, "teams.microsoft.com") ||
	    domain_matches(domain, "facetime.apple.com") ||
	    domain_matches(domain, "stun.l.google.com")) {
		entry->classification = CLASS_VOIP;
		entry->confidence = 0.92f;
		return true;
	}

	for (const struct domain_rule *r = domain_rules; r->suffix; r++) {
		if (domain_matches(domain, r->suffix)) {
			entry->classification = r->cls;
			entry->confidence = r->confidence;
			return true;
		}
	}

	return false;
}

/* ---- Statistical heuristic classification ---- */

static void classify_heuristic(struct flow_entry *entry,
			       float features[NUM_FEATURES])
{
	uint16_t dst_port = entry->key.dst_port;
	uint16_t src_port = entry->key.src_port;
	uint8_t proto = entry->key.proto;

	float avg_pkt_size = features[6];
	float std_pkt_size = features[7];
	float pkt_per_sec  = features[12];
	float bytes_per_sec = features[13];
	float fwd_ratio    = features[14];

	(void)std_pkt_size;

	if (dst_port == 53 || src_port == 53) {
		entry->classification = CLASS_BROWSING;
		entry->confidence = 0.95f;
		return;
	}

	if (dst_port == 123 || dst_port == 161 || dst_port == 5353) {
		entry->classification = CLASS_OTHER;
		entry->confidence = 0.90f;
		return;
	}

	if (dst_port == 5060 || src_port == 5060 ||
	    dst_port == 5061 || src_port == 5061) {
		entry->classification = CLASS_VOIP;
		entry->confidence = 0.90f;
		return;
	}

	if (proto == FLOW_PROTO_UDP && avg_pkt_size > 60 &&
	    avg_pkt_size < 300 && pkt_per_sec > 20 && pkt_per_sec < 120 &&
	    fwd_ratio > 0.25f && fwd_ratio < 0.75f) {
		entry->classification = CLASS_VOIP;
		entry->confidence = 0.82f;
		return;
	}

	if (proto == FLOW_PROTO_UDP && avg_pkt_size < 200 &&
	    pkt_per_sec > 30 && fwd_ratio > 0.25f && fwd_ratio < 0.75f) {
		entry->classification = CLASS_GAMING;
		entry->confidence = 0.72f;
		return;
	}

	if (proto == FLOW_PROTO_UDP &&
	    ((dst_port >= 7000 && dst_port <= 8000) ||
	     (dst_port >= 27000 && dst_port <= 28000) ||
	     dst_port == 3478 || dst_port == 3479)) {
		entry->classification = CLASS_GAMING;
		entry->confidence = 0.70f;
		return;
	}

	if (bytes_per_sec > 100000 && avg_pkt_size > 1000 &&
	    fwd_ratio < 0.15f) {
		entry->classification = CLASS_VIDEO;
		entry->confidence = 0.75f;
		return;
	}

	if (bytes_per_sec > 500000 && fwd_ratio < 0.05f) {
		entry->classification = CLASS_DOWNLOAD;
		entry->confidence = 0.72f;
		return;
	}

	if (bytes_per_sec > 200000 && fwd_ratio < 0.10f &&
	    avg_pkt_size > 1200) {
		entry->classification = CLASS_DOWNLOAD;
		entry->confidence = 0.65f;
		return;
	}

	if ((dst_port == 443 || src_port == 443) &&
	    bytes_per_sec > 5000 && bytes_per_sec < 100000 &&
	    avg_pkt_size > 200 && avg_pkt_size < 800) {
		entry->classification = CLASS_SOCIAL;
		entry->confidence = 0.50f;
		return;
	}

	if (dst_port == 443 || dst_port == 80 ||
	    src_port == 443 || src_port == 80) {
		entry->classification = CLASS_BROWSING;
		entry->confidence = 0.55f;
		return;
	}

	if (proto == FLOW_PROTO_UDP &&
	    (dst_port == 443 || src_port == 443)) {
		if (bytes_per_sec > 100000 && fwd_ratio < 0.15f) {
			entry->classification = CLASS_VIDEO;
			entry->confidence = 0.65f;
		} else {
			entry->classification = CLASS_BROWSING;
			entry->confidence = 0.50f;
		}
		return;
	}

	entry->classification = CLASS_OTHER;
	entry->confidence = 0.30f;
}

void classifier_classify_flow(struct classifier_ctx *ctx,
			      struct flow_entry *entry)
{
	uint32_t total_pkts = entry->stats.total_pkts_fwd +
			      entry->stats.total_pkts_bwd;
	if (total_pkts < 5)
		return;

	if (classify_by_domain(entry, ctx->dc))
		return;

	if (ctx->model_loaded) {
		float features[NUM_FEATURES];
		float probs[TC_MODEL_N_CLASSES];

		features_extract(entry, features);
		int pred = tc_model_predict(features, probs);

		if (pred >= 0 && pred < CLASSIFICATION_LABELS &&
		    probs[pred] > 0.4f) {
			entry->classification = (enum traffic_class)pred;
			entry->confidence = probs[pred];
			return;
		}
	}

	float features[NUM_FEATURES];
	features_extract(entry, features);
	classify_heuristic(entry, features);
}

const char *classifier_class_name(enum traffic_class cls)
{
	if (cls < CLASSIFICATION_LABELS)
		return traffic_class_names[cls];
	return "unknown";
}
