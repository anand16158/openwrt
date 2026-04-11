#include "ubus_api.h"

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <syslog.h>
#include <stdio.h>
#include <arpa/inet.h>

struct flows_dump_ctx {
	struct blob_buf *b;
	struct sta_tracker *sta;
	struct device_fp_ctx *devfp;
};

static int dump_flow_cb(struct flow_entry *entry, void *arg)
{
	struct flows_dump_ctx *ctx = (struct flows_dump_ctx *)arg;
	struct blob_buf *b = ctx->b;
	char addr_buf[INET6_ADDRSTRLEN];
	char mac_str[18];

	void *flow = blobmsg_open_table(b, NULL);

	if (entry->key.is_ipv6)
		inet_ntop(AF_INET6, &entry->key.src_ip, addr_buf, sizeof(addr_buf));
	else
		inet_ntop(AF_INET, &entry->key.src_ip.s6_addr[12], addr_buf, sizeof(addr_buf));
	blobmsg_add_string(b, "src_ip", addr_buf);

	if (entry->key.is_ipv6)
		inet_ntop(AF_INET6, &entry->key.dst_ip, addr_buf, sizeof(addr_buf));
	else
		inet_ntop(AF_INET, &entry->key.dst_ip.s6_addr[12], addr_buf, sizeof(addr_buf));
	blobmsg_add_string(b, "dst_ip", addr_buf);

	blobmsg_add_u32(b, "src_port", entry->key.src_port);
	blobmsg_add_u32(b, "dst_port", entry->key.dst_port);
	blobmsg_add_u32(b, "proto", entry->key.proto);

	blobmsg_add_string(b, "class", classifier_class_name(entry->classification));
	blobmsg_add_u32(b, "confidence", (uint32_t)(entry->confidence * 100));

	blobmsg_add_u64(b, "bytes_fwd", entry->stats.total_bytes_fwd);
	blobmsg_add_u64(b, "bytes_bwd", entry->stats.total_bytes_bwd);
	blobmsg_add_u32(b, "pkts_fwd", entry->stats.total_pkts_fwd);
	blobmsg_add_u32(b, "pkts_bwd", entry->stats.total_pkts_bwd);

	snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
		 entry->src_mac[0], entry->src_mac[1], entry->src_mac[2],
		 entry->src_mac[3], entry->src_mac[4], entry->src_mac[5]);
	blobmsg_add_string(b, "src_mac", mac_str);

	if (entry->dns_hint[0])
		blobmsg_add_string(b, "domain", entry->dns_hint);
	if (entry->app_name[0])
		blobmsg_add_string(b, "app", entry->app_name);

	const struct sta_entry *sta = sta_tracker_find_mac(ctx->sta, entry->src_mac);
	if (sta) {
		blobmsg_add_string(b, "ssid", sta->ssid);
		blobmsg_add_string(b, "ifname", sta->ifname);
		blobmsg_add_u32(b, "signal", (uint32_t)sta->signal);
	}

	if (ctx->devfp) {
		const char *devname = device_fp_get_name(ctx->devfp,
							 entry->src_mac);
		if (devname)
			blobmsg_add_string(b, "device_type", devname);
	}

	blobmsg_close_table(b, flow);
	return 0;
}

static int handle_get_flows(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method,
			    struct blob_attr *msg)
{
	struct tc_ubus_ctx *tc = container_of(obj, struct tc_ubus_ctx, obj);
	struct blob_buf b = {};

	blob_buf_init(&b, 0);

	void *arr = blobmsg_open_array(&b, "flows");
	struct flows_dump_ctx dump_ctx = { .b = &b, .sta = tc->sta, .devfp = tc->devfp };
	flow_table_for_each(tc->ft, dump_flow_cb, &dump_ctx);
	blobmsg_close_array(&b, arr);

	blobmsg_add_u32(&b, "total_flows", tc->ft->count);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return UBUS_STATUS_OK;
}

#define MAX_APPS_PER_CLIENT 16

struct app_counter {
	char name[32];
	uint32_t flows;
	uint64_t bytes;
};

struct client_summary {
	uint8_t mac[6];
	char ssid[MAX_SSID_LEN];
	uint32_t class_counts[CLASSIFICATION_LABELS];
	uint64_t total_bytes;
	uint32_t total_flows;
	struct app_counter apps[MAX_APPS_PER_CLIENT];
	int app_count;
};

struct client_agg_ctx {
	struct client_summary clients[MAX_STATIONS];
	int count;
	struct sta_tracker *sta;
};

static int agg_flow_cb(struct flow_entry *entry, void *arg)
{
	struct client_agg_ctx *ctx = (struct client_agg_ctx *)arg;

	int idx = -1;
	for (int i = 0; i < ctx->count; i++) {
		if (memcmp(ctx->clients[i].mac, entry->src_mac, 6) == 0) {
			idx = i;
			break;
		}
	}

	if (idx < 0) {
		if (ctx->count >= MAX_STATIONS)
			return 0;
		idx = ctx->count++;
		memcpy(ctx->clients[idx].mac, entry->src_mac, 6);

		const struct sta_entry *sta = sta_tracker_find_mac(ctx->sta, entry->src_mac);
		if (sta)
			snprintf(ctx->clients[idx].ssid, MAX_SSID_LEN, "%s", sta->ssid);
	}

	struct client_summary *cs = &ctx->clients[idx];
	uint64_t flow_bytes = entry->stats.total_bytes_fwd +
			      entry->stats.total_bytes_bwd;

	if (entry->classification < CLASSIFICATION_LABELS)
		cs->class_counts[entry->classification]++;
	cs->total_bytes += flow_bytes;
	cs->total_flows++;

	if (entry->app_name[0]) {
		int ai = -1;
		for (int j = 0; j < cs->app_count; j++) {
			if (strcmp(cs->apps[j].name, entry->app_name) == 0) {
				ai = j;
				break;
			}
		}
		if (ai < 0 && cs->app_count < MAX_APPS_PER_CLIENT) {
			ai = cs->app_count++;
			snprintf(cs->apps[ai].name, sizeof(cs->apps[ai].name),
				 "%s", entry->app_name);
		}
		if (ai >= 0) {
			cs->apps[ai].flows++;
			cs->apps[ai].bytes += flow_bytes;
		}
	}

	return 0;
}

static int handle_get_clients(struct ubus_context *ctx, struct ubus_object *obj,
			      struct ubus_request_data *req, const char *method,
			      struct blob_attr *msg)
{
	struct tc_ubus_ctx *tc = container_of(obj, struct tc_ubus_ctx, obj);
	struct blob_buf b = {};
	struct client_agg_ctx agg = { .sta = tc->sta };

	flow_table_for_each(tc->ft, agg_flow_cb, &agg);

	blob_buf_init(&b, 0);
	void *arr = blobmsg_open_array(&b, "clients");

	for (int i = 0; i < agg.count; i++) {
		struct client_summary *cs = &agg.clients[i];
		char mac_str[18];
		snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
			 cs->mac[0], cs->mac[1], cs->mac[2],
			 cs->mac[3], cs->mac[4], cs->mac[5]);

		void *client = blobmsg_open_table(&b, NULL);
		blobmsg_add_string(&b, "mac", mac_str);
		if (cs->ssid[0])
			blobmsg_add_string(&b, "ssid", cs->ssid);
		blobmsg_add_u64(&b, "total_bytes", cs->total_bytes);
		blobmsg_add_u32(&b, "total_flows", cs->total_flows);

		if (tc->devfp) {
			const char *devname = device_fp_get_name(
				tc->devfp, cs->mac);
			float devconf = device_fp_get_confidence(
				tc->devfp, cs->mac);
			blobmsg_add_string(&b, "device_type", devname);
			blobmsg_add_u32(&b, "device_confidence",
					(uint32_t)(devconf * 100));
		}

		void *classes = blobmsg_open_table(&b, "class_usage");
		for (int c = 0; c < CLASSIFICATION_LABELS; c++) {
			if (cs->class_counts[c] > 0)
				blobmsg_add_u32(&b, traffic_class_names[c],
						cs->class_counts[c]);
		}
		blobmsg_close_table(&b, classes);

		if (cs->app_count > 0) {
			void *apps = blobmsg_open_array(&b, "apps");
			for (int a = 0; a < cs->app_count; a++) {
				void *app = blobmsg_open_table(&b, NULL);
				blobmsg_add_string(&b, "name",
						   cs->apps[a].name);
				blobmsg_add_u32(&b, "flows",
						cs->apps[a].flows);
				blobmsg_add_u64(&b, "bytes",
						cs->apps[a].bytes);
				blobmsg_close_table(&b, app);
			}
			blobmsg_close_array(&b, apps);
		}

		blobmsg_close_table(&b, client);
	}

	blobmsg_close_array(&b, arr);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return UBUS_STATUS_OK;
}

static int handle_get_stats(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method,
			    struct blob_attr *msg)
{
	struct tc_ubus_ctx *tc = container_of(obj, struct tc_ubus_ctx, obj);
	struct blob_buf b = {};

	uint32_t class_counts[CLASSIFICATION_LABELS] = {};
	uint64_t total_bytes = 0;

	struct flow_entry *e;
	for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
		e = tc->ft->buckets[i];
		while (e) {
			if (e->classification < CLASSIFICATION_LABELS)
				class_counts[e->classification]++;
			total_bytes += e->stats.total_bytes_fwd +
				       e->stats.total_bytes_bwd;
			e = e->hash_next;
		}
	}

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "active_flows", tc->ft->count);
	blobmsg_add_u32(&b, "tracked_stations", tc->sta->count);
	blobmsg_add_u64(&b, "total_bytes", total_bytes);

	void *classes = blobmsg_open_table(&b, "classification");
	for (int c = 0; c < CLASSIFICATION_LABELS; c++)
		blobmsg_add_u32(&b, traffic_class_names[c], class_counts[c]);
	blobmsg_close_table(&b, classes);

	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return UBUS_STATUS_OK;
}

static int handle_status(struct ubus_context *ctx, struct ubus_object *obj,
			 struct ubus_request_data *req, const char *method,
			 struct blob_attr *msg)
{
	struct tc_ubus_ctx *tc = container_of(obj, struct tc_ubus_ctx, obj);
	struct blob_buf b = {};

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "version", "0.1.0");
	blobmsg_add_string(&b, "status", "running");
	blobmsg_add_u32(&b, "active_flows", tc->ft->count);
	blobmsg_add_u32(&b, "max_flows", tc->ft->max_entries);
	blobmsg_add_u32(&b, "tracked_stations", tc->sta->count);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return UBUS_STATUS_OK;
}

static int handle_get_anomalies(struct ubus_context *ctx,
				struct ubus_object *obj,
				struct ubus_request_data *req,
				const char *method,
				struct blob_attr *msg)
{
	struct tc_ubus_ctx *tc = container_of(obj, struct tc_ubus_ctx, obj);
	struct blob_buf b = {};

	blob_buf_init(&b, 0);

	int total = usage_profile_anomaly_count(tc->profiler);
	blobmsg_add_u32(&b, "total", total);

	struct anomaly_event events[ANOMALY_RING_SIZE];
	int count = usage_profile_get_anomalies(tc->profiler, events,
						ANOMALY_RING_SIZE);

	void *arr = blobmsg_open_array(&b, "anomalies");
	for (int i = 0; i < count; i++) {
		struct anomaly_event *ev = &events[i];
		char mac_str[18];
		snprintf(mac_str, sizeof(mac_str),
			 "%02x:%02x:%02x:%02x:%02x:%02x",
			 ev->mac[0], ev->mac[1], ev->mac[2],
			 ev->mac[3], ev->mac[4], ev->mac[5]);

		void *entry = blobmsg_open_table(&b, NULL);
		blobmsg_add_string(&b, "mac", mac_str);
		blobmsg_add_string(&b, "type",
				   anomaly_type_names[ev->type]);
		blobmsg_add_u64(&b, "timestamp",
				(uint64_t)ev->timestamp);
		blobmsg_add_string(&b, "detail", ev->detail);
		blobmsg_add_u32(&b, "severity",
				(uint32_t)(ev->severity * 100));
		blobmsg_close_table(&b, entry);
	}
	blobmsg_close_array(&b, arr);

	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);
	return UBUS_STATUS_OK;
}

static int handle_get_profiles(struct ubus_context *ctx,
			       struct ubus_object *obj,
			       struct ubus_request_data *req,
			       const char *method,
			       struct blob_attr *msg)
{
	struct tc_ubus_ctx *tc = container_of(obj, struct tc_ubus_ctx, obj);
	struct blob_buf b = {};

	struct client_profile_summary summaries[PROFILE_MAX_CLIENTS];
	int count = usage_profile_get_client_summaries(tc->profiler,
						       summaries,
						       PROFILE_MAX_CLIENTS);

	blob_buf_init(&b, 0);
	void *arr = blobmsg_open_array(&b, "profiles");

	for (int i = 0; i < count; i++) {
		struct client_profile_summary *s = &summaries[i];
		char mac_str[18];
		snprintf(mac_str, sizeof(mac_str),
			 "%02x:%02x:%02x:%02x:%02x:%02x",
			 s->mac[0], s->mac[1], s->mac[2],
			 s->mac[3], s->mac[4], s->mac[5]);

		void *entry = blobmsg_open_table(&b, NULL);
		blobmsg_add_string(&b, "mac", mac_str);
		blobmsg_add_u64(&b, "bytes_current", s->bytes_current_hour);
		blobmsg_add_u64(&b, "bytes_baseline", s->bytes_baseline_avg);
		blobmsg_add_u32(&b, "flows_current", s->flows_current_hour);
		blobmsg_add_u32(&b, "flows_baseline", s->flows_baseline_avg);
		blobmsg_add_u32(&b, "anomaly_count", s->anomaly_count);
		blobmsg_add_u8(&b, "is_anomalous", s->is_anomalous);

		void *dist = blobmsg_open_table(&b, "class_dist");
		for (int c = 0; c < CLASSIFICATION_LABELS; c++) {
			if (s->class_dist[c] > 0)
				blobmsg_add_u32(&b, traffic_class_names[c],
						s->class_dist[c]);
		}
		blobmsg_close_table(&b, dist);

		blobmsg_close_table(&b, entry);
	}
	blobmsg_close_array(&b, arr);

	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);
	return UBUS_STATUS_OK;
}

static int handle_capture_status(struct ubus_context *ctx,
				 struct ubus_object *obj,
				 struct ubus_request_data *req,
				 const char *method,
				 struct blob_attr *msg)
{
	struct tc_ubus_ctx *tc = container_of(obj, struct tc_ubus_ctx, obj);
	struct blob_buf b = {};

	blob_buf_init(&b, 0);

	if (tc->collector) {
		blobmsg_add_u8(&b, "available", true);
		blobmsg_add_u8(&b, "active",
			       data_collect_is_active(tc->collector));
		blobmsg_add_u32(&b, "rows",
				data_collect_row_count(tc->collector));
		blobmsg_add_u32(&b, "max_rows", DATA_COLLECT_MAX_ROWS);
		blobmsg_add_string(&b, "path",
				   data_collect_path(tc->collector));
	} else {
		blobmsg_add_u8(&b, "available", false);
	}

	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);
	return UBUS_STATUS_OK;
}

static int handle_capture_start(struct ubus_context *ctx,
				struct ubus_object *obj,
				struct ubus_request_data *req,
				const char *method,
				struct blob_attr *msg)
{
	struct tc_ubus_ctx *tc = container_of(obj, struct tc_ubus_ctx, obj);
	struct blob_buf b = {};

	if (!tc->collector) {
		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "error",
				   "data capture not configured (-C flag)");
		ubus_send_reply(ctx, req, b.head);
		blob_buf_free(&b);
		return UBUS_STATUS_OK;
	}

	data_collect_start(tc->collector);

	blob_buf_init(&b, 0);
	blobmsg_add_u8(&b, "active", true);
	blobmsg_add_u32(&b, "rows",
			data_collect_row_count(tc->collector));
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);
	return UBUS_STATUS_OK;
}

static int handle_capture_stop(struct ubus_context *ctx,
			       struct ubus_object *obj,
			       struct ubus_request_data *req,
			       const char *method,
			       struct blob_attr *msg)
{
	struct tc_ubus_ctx *tc = container_of(obj, struct tc_ubus_ctx, obj);
	struct blob_buf b = {};

	if (tc->collector)
		data_collect_stop(tc->collector);

	blob_buf_init(&b, 0);
	blobmsg_add_u8(&b, "active", false);
	blobmsg_add_u32(&b, "rows",
			tc->collector ?
			data_collect_row_count(tc->collector) : 0);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);
	return UBUS_STATUS_OK;
}

static const struct ubus_method tc_methods[] = {
	UBUS_METHOD_NOARG("get_flows", handle_get_flows),
	UBUS_METHOD_NOARG("get_clients", handle_get_clients),
	UBUS_METHOD_NOARG("get_stats", handle_get_stats),
	UBUS_METHOD_NOARG("get_anomalies", handle_get_anomalies),
	UBUS_METHOD_NOARG("get_profiles", handle_get_profiles),
	UBUS_METHOD_NOARG("capture_status", handle_capture_status),
	UBUS_METHOD_NOARG("capture_start", handle_capture_start),
	UBUS_METHOD_NOARG("capture_stop", handle_capture_stop),
	UBUS_METHOD_NOARG("status", handle_status),
};

static struct ubus_object_type tc_obj_type =
	UBUS_OBJECT_TYPE("traffic-classifier", tc_methods);

int tc_ubus_init(struct tc_ubus_ctx *ctx)
{
	ctx->obj.name = "traffic-classifier";
	ctx->obj.type = &tc_obj_type;
	ctx->obj.methods = tc_methods;
	ctx->obj.n_methods = ARRAY_SIZE(tc_methods);

	int ret = ubus_add_object(ctx->ubus, &ctx->obj);
	if (ret) {
		syslog(LOG_ERR, "ubus_add_object failed: %s", ubus_strerror(ret));
		return ret;
	}

	syslog(LOG_INFO, "ubus: registered object 'traffic-classifier'");
	return 0;
}

void tc_ubus_cleanup(struct tc_ubus_ctx *ctx)
{
	ubus_remove_object(ctx->ubus, &ctx->obj);
}
