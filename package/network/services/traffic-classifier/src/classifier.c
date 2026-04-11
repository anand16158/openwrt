#include "classifier.h"
#include "tc_model.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <stdio.h>

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

/* ---- Domain-based classification with app identification ---- */

struct domain_rule {
	const char *suffix;
	const char *app;
	enum traffic_class cls;
	float confidence;
};

static const struct domain_rule domain_rules[] = {
	/* Video streaming */
	{ "youtube.com",        "YouTube",       CLASS_VIDEO,    0.95f },
	{ "ytimg.com",          "YouTube",       CLASS_VIDEO,    0.90f },
	{ "googlevideo.com",    "YouTube",       CLASS_VIDEO,    0.95f },
	{ "youtu.be",           "YouTube",       CLASS_VIDEO,    0.90f },
	{ "netflix.com",        "Netflix",       CLASS_VIDEO,    0.95f },
	{ "nflxvideo.net",      "Netflix",       CLASS_VIDEO,    0.95f },
	{ "nflxso.net",         "Netflix",       CLASS_VIDEO,    0.90f },
	{ "hotstar.com",        "Hotstar",       CLASS_VIDEO,    0.90f },
	{ "hotstar.in",         "Hotstar",       CLASS_VIDEO,    0.90f },
	{ "jiocinema.com",      "JioCinema",     CLASS_VIDEO,    0.90f },
	{ "primevideo.com",     "Prime Video",   CLASS_VIDEO,    0.90f },
	{ "amazonvideo.com",    "Prime Video",   CLASS_VIDEO,    0.90f },
	{ "twitch.tv",          "Twitch",        CLASS_VIDEO,    0.90f },
	{ "ttvnw.net",          "Twitch",        CLASS_VIDEO,    0.90f },
	{ "vimeo.com",          "Vimeo",         CLASS_VIDEO,    0.85f },
	{ "dailymotion.com",    "Dailymotion",   CLASS_VIDEO,    0.85f },
	{ "disneyplus.com",     "Disney+",       CLASS_VIDEO,    0.90f },
	{ "dssott.com",         "Disney+",       CLASS_VIDEO,    0.85f },
	{ "sonyliv.com",        "SonyLIV",       CLASS_VIDEO,    0.85f },
	{ "zee5.com",           "ZEE5",          CLASS_VIDEO,    0.85f },
	{ "mxplayer.in",        "MX Player",     CLASS_VIDEO,    0.85f },
	{ "spotify.com",        "Spotify",       CLASS_VIDEO,    0.85f },
	{ "scdn.co",            "Spotify",       CLASS_VIDEO,    0.80f },
	{ "gaana.com",          "Gaana",         CLASS_VIDEO,    0.80f },
	{ "jiosaavn.com",       "JioSaavn",      CLASS_VIDEO,    0.80f },
	{ "saavn.com",          "JioSaavn",      CLASS_VIDEO,    0.80f },
	{ "wynk.in",            "Wynk Music",    CLASS_VIDEO,    0.80f },

	/* Social media */
	{ "whatsapp.net",       "WhatsApp",      CLASS_SOCIAL,   0.90f },
	{ "whatsapp.com",       "WhatsApp",      CLASS_SOCIAL,   0.90f },
	{ "facebook.com",       "Facebook",      CLASS_SOCIAL,   0.85f },
	{ "fbcdn.net",          "Facebook",      CLASS_SOCIAL,   0.85f },
	{ "fb.com",             "Facebook",      CLASS_SOCIAL,   0.80f },
	{ "instagram.com",      "Instagram",     CLASS_SOCIAL,   0.85f },
	{ "cdninstagram.com",   "Instagram",     CLASS_SOCIAL,   0.85f },
	{ "twitter.com",        "X/Twitter",     CLASS_SOCIAL,   0.80f },
	{ "x.com",              "X/Twitter",     CLASS_SOCIAL,   0.80f },
	{ "twimg.com",          "X/Twitter",     CLASS_SOCIAL,   0.80f },
	{ "tiktok.com",         "TikTok",        CLASS_SOCIAL,   0.85f },
	{ "tiktokcdn.com",      "TikTok",        CLASS_SOCIAL,   0.85f },
	{ "musical.ly",         "TikTok",        CLASS_SOCIAL,   0.80f },
	{ "snapchat.com",       "Snapchat",      CLASS_SOCIAL,   0.85f },
	{ "snap.com",           "Snapchat",      CLASS_SOCIAL,   0.80f },
	{ "sc-cdn.net",         "Snapchat",      CLASS_SOCIAL,   0.80f },
	{ "telegram.org",       "Telegram",      CLASS_SOCIAL,   0.85f },
	{ "t.me",               "Telegram",      CLASS_SOCIAL,   0.85f },
	{ "reddit.com",         "Reddit",        CLASS_SOCIAL,   0.75f },
	{ "redd.it",            "Reddit",        CLASS_SOCIAL,   0.75f },
	{ "redditmedia.com",    "Reddit",        CLASS_SOCIAL,   0.75f },
	{ "linkedin.com",       "LinkedIn",      CLASS_SOCIAL,   0.75f },
	{ "threads.net",        "Threads",       CLASS_SOCIAL,   0.80f },
	{ "discord.com",        "Discord",       CLASS_SOCIAL,   0.85f },
	{ "discord.gg",         "Discord",       CLASS_SOCIAL,   0.80f },
	{ "discordapp.net",     "Discord",       CLASS_SOCIAL,   0.80f },
	{ "pinterest.com",      "Pinterest",     CLASS_SOCIAL,   0.75f },
	{ "pinimg.com",         "Pinterest",     CLASS_SOCIAL,   0.75f },
	{ "signal.org",         "Signal",        CLASS_SOCIAL,   0.85f },
	{ "whispersystems.org", "Signal",        CLASS_SOCIAL,   0.80f },

	/* VoIP / Video calling */
	{ "zoom.us",            "Zoom",          CLASS_VOIP,     0.95f },
	{ "zoom.com",           "Zoom",          CLASS_VOIP,     0.90f },
	{ "zoomgov.com",        "Zoom",          CLASS_VOIP,     0.90f },
	{ "jiomeet.com",        "JioMeet",       CLASS_VOIP,     0.90f },
	{ "webex.com",          "Webex",         CLASS_VOIP,     0.90f },
	{ "gotomeeting.com",    "GoToMeeting",   CLASS_VOIP,     0.85f },
	{ "skype.com",          "Skype",         CLASS_VOIP,     0.90f },
	{ "skypeecs.net",       "Skype",         CLASS_VOIP,     0.85f },

	/* Gaming */
	{ "steampowered.com",   "Steam",         CLASS_GAMING,   0.85f },
	{ "steamcontent.com",   "Steam",         CLASS_GAMING,   0.80f },
	{ "steamstatic.com",    "Steam",         CLASS_GAMING,   0.80f },
	{ "epicgames.com",      "Epic Games",    CLASS_GAMING,   0.85f },
	{ "unrealengine.com",   "Epic Games",    CLASS_GAMING,   0.80f },
	{ "riotgames.com",      "Riot Games",    CLASS_GAMING,   0.85f },
	{ "garena.com",         "Garena",        CLASS_GAMING,   0.85f },
	{ "supercell.com",      "Supercell",     CLASS_GAMING,   0.80f },
	{ "mihoyo.com",         "miHoYo",        CLASS_GAMING,   0.80f },
	{ "hoyoverse.com",      "HoYoverse",     CLASS_GAMING,   0.80f },
	{ "pubg.com",           "PUBG",          CLASS_GAMING,   0.85f },
	{ "playbattlegrounds.com", "PUBG",       CLASS_GAMING,   0.85f },
	{ "ea.com",             "EA",            CLASS_GAMING,   0.75f },
	{ "activision.com",     "Activision",    CLASS_GAMING,   0.80f },
	{ "xbox.com",           "Xbox",          CLASS_GAMING,   0.80f },
	{ "xboxlive.com",       "Xbox",          CLASS_GAMING,   0.80f },
	{ "playstation.com",    "PlayStation",   CLASS_GAMING,   0.80f },
	{ "playstation.net",    "PlayStation",   CLASS_GAMING,   0.80f },
	{ "nintendo.com",       "Nintendo",      CLASS_GAMING,   0.75f },
	{ "nintendo.net",       "Nintendo",      CLASS_GAMING,   0.75f },

	/* Download / Updates */
	{ "dl.google.com",      "Google Play",   CLASS_DOWNLOAD, 0.85f },
	{ "play.google.com",    "Google Play",   CLASS_DOWNLOAD, 0.80f },
	{ "gvt1.com",           "Google Play",   CLASS_DOWNLOAD, 0.80f },
	{ "apple.com",          "Apple",         CLASS_DOWNLOAD, 0.60f },
	{ "mzstatic.com",       "App Store",     CLASS_DOWNLOAD, 0.75f },
	{ "icloud.com",         "iCloud",        CLASS_DOWNLOAD, 0.70f },
	{ "windowsupdate.com",  "Windows Update", CLASS_DOWNLOAD, 0.90f },
	{ "download.microsoft.com", "Microsoft", CLASS_DOWNLOAD, 0.90f },
	{ "officecdn.microsoft.com", "Microsoft Office", CLASS_DOWNLOAD, 0.85f },

	/* Browsing — specific sites */
	{ "google.com",         "Google",        CLASS_BROWSING, 0.70f },
	{ "googleapis.com",     "Google",        CLASS_BROWSING, 0.65f },
	{ "bing.com",           "Bing",          CLASS_BROWSING, 0.70f },
	{ "amazon.in",          "Amazon",        CLASS_BROWSING, 0.70f },
	{ "amazon.com",         "Amazon",        CLASS_BROWSING, 0.70f },
	{ "flipkart.com",       "Flipkart",      CLASS_BROWSING, 0.70f },
	{ "wikipedia.org",      "Wikipedia",     CLASS_BROWSING, 0.70f },

	{ NULL, NULL, 0, 0 }
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
	if (domain_matches(domain, "meet.google.com")) {
		entry->classification = CLASS_VOIP;
		entry->confidence = 0.92f;
		snprintf(entry->app_name, sizeof(entry->app_name), "Google Meet");
		return true;
	}
	if (domain_matches(domain, "teams.microsoft.com") ||
	    domain_matches(domain, "teams.live.com")) {
		entry->classification = CLASS_VOIP;
		entry->confidence = 0.92f;
		snprintf(entry->app_name, sizeof(entry->app_name), "MS Teams");
		return true;
	}
	if (domain_matches(domain, "facetime.apple.com")) {
		entry->classification = CLASS_VOIP;
		entry->confidence = 0.92f;
		snprintf(entry->app_name, sizeof(entry->app_name), "FaceTime");
		return true;
	}
	if (domain_matches(domain, "stun.l.google.com")) {
		entry->classification = CLASS_VOIP;
		entry->confidence = 0.88f;
		snprintf(entry->app_name, sizeof(entry->app_name), "Google Meet");
		return true;
	}

	for (const struct domain_rule *r = domain_rules; r->suffix; r++) {
		if (domain_matches(domain, r->suffix)) {
			entry->classification = r->cls;
			entry->confidence = r->confidence;
			snprintf(entry->app_name, sizeof(entry->app_name),
				 "%s", r->app);
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
