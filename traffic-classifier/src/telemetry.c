#include "telemetry.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

struct telemetry_ctx {
	struct telemetry_config cfg;
	struct flow_table *ft;
	struct sta_tracker *sta;
	struct device_fp_ctx *devfp;
	struct usage_profile_ctx *profiler;
	struct ubus_context *ubus;
	time_t start_time;
	uint32_t export_seq;
};

struct telemetry_ctx *telemetry_init(const struct telemetry_config *cfg,
				     struct flow_table *ft,
				     struct sta_tracker *sta,
				     struct device_fp_ctx *devfp,
				     struct usage_profile_ctx *profiler,
				     struct ubus_context *ubus)
{
	struct telemetry_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	memcpy(&ctx->cfg, cfg, sizeof(*cfg));
	ctx->ft = ft;
	ctx->sta = sta;
	ctx->devfp = devfp;
	ctx->profiler = profiler;
	ctx->ubus = ubus;
	ctx->start_time = time(NULL);

	syslog(LOG_INFO, "telemetry: initialized (interval=%ds, file=%s)",
	       ctx->cfg.interval_sec, ctx->cfg.file_path);
	return ctx;
}

void telemetry_destroy(struct telemetry_ctx *ctx)
{
	free(ctx);
}

/* Per-client aggregation for telemetry */

#define TELEM_MAX_APPS 16

struct telem_app {
	char name[32];
	uint32_t flows;
	uint64_t bytes;
};

struct telem_client {
	uint8_t mac[6];
	char ssid[MAX_SSID_LEN];
	uint64_t total_bytes;
	uint32_t total_flows;
	uint32_t class_counts[CLASSIFICATION_LABELS];
	struct telem_app apps[TELEM_MAX_APPS];
	int app_count;
};

struct telem_agg {
	struct telem_client clients[MAX_STATIONS];
	int count;
	struct sta_tracker *sta;
	uint32_t class_totals[CLASSIFICATION_LABELS];
	uint64_t total_bytes;
};

static int telem_flow_cb(struct flow_entry *entry, void *arg)
{
	struct telem_agg *agg = (struct telem_agg *)arg;
	uint64_t bytes = entry->stats.total_bytes_fwd +
			 entry->stats.total_bytes_bwd;

	if (entry->classification < CLASSIFICATION_LABELS)
		agg->class_totals[entry->classification]++;
	agg->total_bytes += bytes;

	int idx = -1;
	for (int i = 0; i < agg->count; i++) {
		if (memcmp(agg->clients[i].mac, entry->src_mac, 6) == 0) {
			idx = i;
			break;
		}
	}

	if (idx < 0) {
		if (agg->count >= MAX_STATIONS)
			return 0;
		idx = agg->count++;
		memcpy(agg->clients[idx].mac, entry->src_mac, 6);

		const struct sta_entry *sta =
			sta_tracker_find_mac(agg->sta, entry->src_mac);
		if (sta)
			snprintf(agg->clients[idx].ssid, MAX_SSID_LEN,
				 "%s", sta->ssid);
	}

	struct telem_client *c = &agg->clients[idx];
	c->total_bytes += bytes;
	c->total_flows++;
	if (entry->classification < CLASSIFICATION_LABELS)
		c->class_counts[entry->classification]++;

	if (entry->app_name[0]) {
		int ai = -1;
		for (int j = 0; j < c->app_count; j++) {
			if (strcmp(c->apps[j].name, entry->app_name) == 0) {
				ai = j;
				break;
			}
		}
		if (ai < 0 && c->app_count < TELEM_MAX_APPS) {
			ai = c->app_count++;
			snprintf(c->apps[ai].name, sizeof(c->apps[ai].name),
				 "%s", entry->app_name);
		}
		if (ai >= 0) {
			c->apps[ai].flows++;
			c->apps[ai].bytes += bytes;
		}
	}

	return 0;
}

static char *build_json(struct telemetry_ctx *ctx)
{
	struct blob_buf b = {};
	struct telem_agg agg = { .sta = ctx->sta };

	flow_table_for_each(ctx->ft, telem_flow_cb, &agg);

	blob_buf_init(&b, 0);

	blobmsg_add_u64(&b, "timestamp", (uint64_t)time(NULL));
	blobmsg_add_u32(&b, "uptime_sec",
			(uint32_t)(time(NULL) - ctx->start_time));
	blobmsg_add_u32(&b, "export_seq", ctx->export_seq);

	/* Summary */
	void *summary = blobmsg_open_table(&b, "summary");
	blobmsg_add_u32(&b, "active_flows", ctx->ft->count);
	blobmsg_add_u32(&b, "tracked_stations", ctx->sta->count);
	blobmsg_add_u64(&b, "total_bytes", agg.total_bytes);

	void *cls_tbl = blobmsg_open_table(&b, "classification");
	for (int c = 0; c < CLASSIFICATION_LABELS; c++)
		blobmsg_add_u32(&b, traffic_class_names[c],
				agg.class_totals[c]);
	blobmsg_close_table(&b, cls_tbl);
	blobmsg_close_table(&b, summary);

	/* Client list */
	void *arr = blobmsg_open_array(&b, "clients");
	for (int i = 0; i < agg.count; i++) {
		struct telem_client *tc = &agg.clients[i];
		char mac_str[18];
		snprintf(mac_str, sizeof(mac_str),
			 "%02x:%02x:%02x:%02x:%02x:%02x",
			 tc->mac[0], tc->mac[1], tc->mac[2],
			 tc->mac[3], tc->mac[4], tc->mac[5]);

		void *client = blobmsg_open_table(&b, NULL);
		blobmsg_add_string(&b, "mac", mac_str);
		if (tc->ssid[0])
			blobmsg_add_string(&b, "ssid", tc->ssid);
		blobmsg_add_u64(&b, "total_bytes", tc->total_bytes);
		blobmsg_add_u32(&b, "total_flows", tc->total_flows);

		if (ctx->devfp) {
			blobmsg_add_string(&b, "device_type",
				device_fp_get_name(ctx->devfp, tc->mac));
		}

		void *usage = blobmsg_open_table(&b, "class_usage");
		for (int c = 0; c < CLASSIFICATION_LABELS; c++) {
			if (tc->class_counts[c] > 0)
				blobmsg_add_u32(&b, traffic_class_names[c],
						tc->class_counts[c]);
		}
		blobmsg_close_table(&b, usage);

		if (tc->app_count > 0) {
			void *apps = blobmsg_open_array(&b, "apps");
			for (int a = 0; a < tc->app_count; a++) {
				void *app = blobmsg_open_table(&b, NULL);
				blobmsg_add_string(&b, "name",
						   tc->apps[a].name);
				blobmsg_add_u32(&b, "flows",
						tc->apps[a].flows);
				blobmsg_add_u64(&b, "bytes",
						tc->apps[a].bytes);
				blobmsg_close_table(&b, app);
			}
			blobmsg_close_array(&b, apps);
		}

		blobmsg_close_table(&b, client);
	}
	blobmsg_close_array(&b, arr);

	/* Anomalies */
	if (ctx->profiler) {
		struct anomaly_event events[ANOMALY_RING_SIZE];
		int acount = usage_profile_get_anomalies(ctx->profiler,
							 events,
							 ANOMALY_RING_SIZE);
		blobmsg_add_u32(&b, "anomaly_count", acount);

		void *anarr = blobmsg_open_array(&b, "anomalies");
		for (int i = 0; i < acount; i++) {
			struct anomaly_event *ev = &events[i];
			char mac_str[18];
			snprintf(mac_str, sizeof(mac_str),
				 "%02x:%02x:%02x:%02x:%02x:%02x",
				 ev->mac[0], ev->mac[1], ev->mac[2],
				 ev->mac[3], ev->mac[4], ev->mac[5]);

			void *aentry = blobmsg_open_table(&b, NULL);
			blobmsg_add_string(&b, "mac", mac_str);
			blobmsg_add_string(&b, "type",
					   anomaly_type_names[ev->type]);
			blobmsg_add_u64(&b, "timestamp",
					(uint64_t)ev->timestamp);
			blobmsg_add_string(&b, "detail", ev->detail);
			blobmsg_add_u32(&b, "severity",
					(uint32_t)(ev->severity * 100));
			blobmsg_close_table(&b, aentry);
		}
		blobmsg_close_array(&b, anarr);
	}

	char *json = blobmsg_format_json(b.head, true);
	blob_buf_free(&b);
	return json;
}

static int write_file(const char *path, const char *json)
{
	char tmp_path[280];
	snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

	FILE *f = fopen(tmp_path, "w");
	if (!f) {
		syslog(LOG_ERR, "telemetry: cannot open %s for writing",
		       tmp_path);
		return -1;
	}

	fputs(json, f);
	fputc('\n', f);
	fclose(f);

	if (rename(tmp_path, path) < 0) {
		syslog(LOG_ERR, "telemetry: rename %s → %s failed",
		       tmp_path, path);
		return -1;
	}

	return 0;
}

static int send_ubus_event(struct telemetry_ctx *ctx, const char *json)
{
	struct blob_buf b = {};
	blob_buf_init(&b, 0);

	if (!blobmsg_add_json_from_string(&b, json)) {
		blob_buf_free(&b);
		return -1;
	}

	int ret = ubus_send_event(ctx->ubus,
				  "traffic-classifier.telemetry", b.head);
	blob_buf_free(&b);
	return ret;
}

int telemetry_export(struct telemetry_ctx *ctx)
{
	if (!ctx || !ctx->cfg.enabled)
		return 0;

	char *json = build_json(ctx);
	if (!json)
		return -1;

	ctx->export_seq++;

	if (ctx->cfg.file_path[0])
		write_file(ctx->cfg.file_path, json);

	if (ctx->cfg.ubus_notify && ctx->ubus)
		send_ubus_event(ctx, json);

	syslog(LOG_DEBUG, "telemetry: exported snapshot #%u "
	       "(%d flows, %d stations)",
	       ctx->export_seq, ctx->ft->count, ctx->sta->count);

	free(json);
	return 0;
}

bool telemetry_enabled(const struct telemetry_ctx *ctx)
{
	return ctx && ctx->cfg.enabled;
}
