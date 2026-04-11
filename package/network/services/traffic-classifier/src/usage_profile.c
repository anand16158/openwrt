#include "usage_profile.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <syslog.h>
#include <stdio.h>

/*
 * Per-client hourly baseline: stores a rolling average (exponential
 * moving average) of bytes and flows for each hour of day. This
 * converges after ~7 days of data and adapts slowly to changing habits.
 */

#define EMA_ALPHA 0.15f  /* weight for new sample in exponential moving avg */

#define BANDWIDTH_SPIKE_FACTOR  3.0f
#define HEAVY_FLOW_RATIO        0.50f
#define CLASS_SHIFT_THRESHOLD   0.40f

#define SEEN_PORTS_BUCKETS 64

struct hourly_baseline {
	float avg_bytes;
	float avg_flows;
	float class_frac[CLASSIFICATION_LABELS];
	uint32_t samples;
};

struct client_profile {
	uint8_t mac[6];
	bool active;

	/* Current accumulation window (resets each tick) */
	uint64_t cur_bytes;
	uint32_t cur_flows;
	uint32_t cur_class_counts[CLASSIFICATION_LABELS];
	uint64_t max_single_flow_bytes;

	/* 24-hour baseline */
	struct hourly_baseline baseline[PROFILE_HOURS];

	/* Ports seen bitmap — simple hash set for detecting unusual ports */
	uint16_t seen_ports[SEEN_PORTS_BUCKETS];
	int seen_port_count;

	/* Per-client anomaly counter (lifetime) */
	int anomaly_count;
	bool flagged_this_tick;
};

struct usage_profile_ctx {
	struct client_profile clients[PROFILE_MAX_CLIENTS];
	int client_count;

	struct anomaly_event anomaly_ring[ANOMALY_RING_SIZE];
	int anomaly_head;
	int anomaly_total;

	time_t last_tick;
};

struct usage_profile_ctx *usage_profile_init(void)
{
	struct usage_profile_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;
	ctx->last_tick = time(NULL);
	syslog(LOG_INFO, "usage_profile: initialized");
	return ctx;
}

void usage_profile_destroy(struct usage_profile_ctx *ctx)
{
	free(ctx);
}

static struct client_profile *find_or_create_profile(
	struct usage_profile_ctx *ctx, const uint8_t *mac)
{
	for (int i = 0; i < ctx->client_count; i++) {
		if (memcmp(ctx->clients[i].mac, mac, 6) == 0)
			return &ctx->clients[i];
	}

	if (ctx->client_count >= PROFILE_MAX_CLIENTS)
		return NULL;

	struct client_profile *p = &ctx->clients[ctx->client_count++];
	memset(p, 0, sizeof(*p));
	memcpy(p->mac, mac, 6);
	p->active = true;
	return p;
}

static void record_anomaly(struct usage_profile_ctx *ctx,
			   struct client_profile *cp,
			   enum anomaly_type type,
			   float severity,
			   const char *detail)
{
	struct anomaly_event *ev =
		&ctx->anomaly_ring[ctx->anomaly_head % ANOMALY_RING_SIZE];

	memcpy(ev->mac, cp->mac, 6);
	ev->type = type;
	ev->timestamp = time(NULL);
	ev->severity = severity;
	snprintf(ev->detail, sizeof(ev->detail), "%s", detail);

	ctx->anomaly_head = (ctx->anomaly_head + 1) % ANOMALY_RING_SIZE;
	if (ctx->anomaly_total < ANOMALY_RING_SIZE)
		ctx->anomaly_total++;

	cp->anomaly_count++;
	cp->flagged_this_tick = true;

	char mac_str[18];
	snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
		 cp->mac[0], cp->mac[1], cp->mac[2],
		 cp->mac[3], cp->mac[4], cp->mac[5]);
	syslog(LOG_NOTICE, "usage_profile: ANOMALY [%s] client=%s sev=%.0f%% %s",
	       anomaly_type_names[type], mac_str,
	       severity * 100.0f, detail);
}

static bool port_is_known(struct client_profile *cp, uint16_t port)
{
	for (int i = 0; i < cp->seen_port_count && i < SEEN_PORTS_BUCKETS; i++) {
		if (cp->seen_ports[i] == port)
			return true;
	}
	return false;
}

static void port_add(struct client_profile *cp, uint16_t port)
{
	if (port_is_known(cp, port))
		return;
	if (cp->seen_port_count < SEEN_PORTS_BUCKETS)
		cp->seen_ports[cp->seen_port_count++] = port;
}

/*
 * Well-known ports that shouldn't trigger unusual_port anomalies.
 */
static bool is_common_port(uint16_t port)
{
	switch (port) {
	case 53: case 80: case 443: case 993: case 995:
	case 587: case 465: case 25: case 110: case 143:
	case 8080: case 8443: case 3478: case 3479:
	case 5060: case 5061: case 123: case 67: case 68:
		return true;
	default:
		return (port >= 1024);
	}
}

void usage_profile_update(struct usage_profile_ctx *ctx,
			  const struct flow_entry *entry)
{
	if (!ctx)
		return;

	struct client_profile *cp = find_or_create_profile(ctx, entry->src_mac);
	if (!cp)
		return;

	uint64_t flow_bytes = entry->stats.total_bytes_fwd +
			      entry->stats.total_bytes_bwd;

	cp->cur_bytes += flow_bytes;
	cp->cur_flows++;

	if (entry->classification < CLASSIFICATION_LABELS)
		cp->cur_class_counts[entry->classification]++;

	if (flow_bytes > cp->max_single_flow_bytes)
		cp->max_single_flow_bytes = flow_bytes;

	/* Track destination port for unusual-port detection */
	uint16_t dport = entry->key.dst_port;
	bool was_known = port_is_known(cp, dport);
	port_add(cp, dport);

	if (!was_known && cp->seen_port_count > 10 &&
	    !is_common_port(dport) && dport > 0 && dport < 1024) {
		char detail[128];
		snprintf(detail, sizeof(detail),
			 "new low port %u (proto=%u)", dport, entry->key.proto);
		record_anomaly(ctx, cp, ANOMALY_UNUSUAL_PORT, 0.3f, detail);
	}
}

/*
 * Check for anomalies based on accumulated window data vs baseline,
 * then update the baseline with new data.
 */
static void check_and_update_baseline(struct usage_profile_ctx *ctx,
				      struct client_profile *cp, int hour)
{
	struct hourly_baseline *bl = &cp->baseline[hour];
	cp->flagged_this_tick = false;

	/* Need some baseline history before we can detect anomalies */
	if (bl->samples >= 3) {
		/* 1. Bandwidth spike */
		float expected = bl->avg_bytes;
		if (expected > 1000 && cp->cur_bytes > 0) {
			float ratio = (float)cp->cur_bytes / expected;
			if (ratio > BANDWIDTH_SPIKE_FACTOR) {
				char detail[128];
				snprintf(detail, sizeof(detail),
					 "%.1fx above baseline "
					 "(current=%llu, avg=%.0f)",
					 ratio,
					 (unsigned long long)cp->cur_bytes,
					 expected);
				float sev = fminf(1.0f,
					(ratio - BANDWIDTH_SPIKE_FACTOR) /
					(BANDWIDTH_SPIKE_FACTOR * 2));
				record_anomaly(ctx, cp,
					       ANOMALY_BANDWIDTH_SPIKE,
					       sev, detail);
			}
		}

		/* 2. Single heavy flow */
		if (cp->cur_bytes > 0 && cp->max_single_flow_bytes > 0) {
			float frac = (float)cp->max_single_flow_bytes /
				     (float)cp->cur_bytes;
			if (frac > HEAVY_FLOW_RATIO && cp->cur_flows > 3) {
				char detail[128];
				snprintf(detail, sizeof(detail),
					 "single flow = %.0f%% of total "
					 "(%llu / %llu bytes)",
					 frac * 100.0f,
					 (unsigned long long)
					 cp->max_single_flow_bytes,
					 (unsigned long long)cp->cur_bytes);
				record_anomaly(ctx, cp,
					       ANOMALY_NEW_HEAVY_FLOW,
					       frac * 0.6f, detail);
			}
		}

		/* 3. Traffic class shift */
		if (cp->cur_flows >= 5 && bl->samples >= 5) {
			float total_diff = 0;
			uint32_t total_cur = 0;
			for (int c = 0; c < CLASSIFICATION_LABELS; c++)
				total_cur += cp->cur_class_counts[c];

			if (total_cur > 0) {
				for (int c = 0; c < CLASSIFICATION_LABELS; c++) {
					float cur_frac =
						(float)cp->cur_class_counts[c] /
						(float)total_cur;
					float base_frac = bl->class_frac[c];
					float diff = fabsf(cur_frac - base_frac);
					total_diff += diff;
				}
				total_diff /= 2.0f; /* normalize to [0,1] */

				if (total_diff > CLASS_SHIFT_THRESHOLD) {
					char detail[128];
					snprintf(detail, sizeof(detail),
						 "class distribution "
						 "divergence=%.0f%%",
						 total_diff * 100.0f);
					record_anomaly(ctx, cp,
						       ANOMALY_PROTOCOL_SHIFT,
						       total_diff * 0.7f,
						       detail);
				}
			}
		}
	}

	/* Update baseline with EMA */
	if (cp->cur_bytes > 0 || cp->cur_flows > 0) {
		if (bl->samples == 0) {
			bl->avg_bytes = (float)cp->cur_bytes;
			bl->avg_flows = (float)cp->cur_flows;
		} else {
			bl->avg_bytes = EMA_ALPHA * (float)cp->cur_bytes +
					(1.0f - EMA_ALPHA) * bl->avg_bytes;
			bl->avg_flows = EMA_ALPHA * (float)cp->cur_flows +
					(1.0f - EMA_ALPHA) * bl->avg_flows;
		}

		uint32_t total_cur = 0;
		for (int c = 0; c < CLASSIFICATION_LABELS; c++)
			total_cur += cp->cur_class_counts[c];

		if (total_cur > 0) {
			for (int c = 0; c < CLASSIFICATION_LABELS; c++) {
				float cur_frac =
					(float)cp->cur_class_counts[c] /
					(float)total_cur;
				if (bl->samples == 0) {
					bl->class_frac[c] = cur_frac;
				} else {
					bl->class_frac[c] =
						EMA_ALPHA * cur_frac +
						(1.0f - EMA_ALPHA) *
						bl->class_frac[c];
				}
			}
		}

		bl->samples++;
	}

	/* Reset accumulation window */
	cp->cur_bytes = 0;
	cp->cur_flows = 0;
	cp->max_single_flow_bytes = 0;
	memset(cp->cur_class_counts, 0, sizeof(cp->cur_class_counts));
}

void usage_profile_tick(struct usage_profile_ctx *ctx)
{
	if (!ctx)
		return;

	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	int hour = t->tm_hour;

	for (int i = 0; i < ctx->client_count; i++) {
		if (!ctx->clients[i].active)
			continue;
		check_and_update_baseline(ctx, &ctx->clients[i], hour);
	}

	ctx->last_tick = now;
}

int usage_profile_get_anomalies(const struct usage_profile_ctx *ctx,
				struct anomaly_event *buf, int max_count)
{
	if (!ctx || ctx->anomaly_total == 0)
		return 0;

	int count = ctx->anomaly_total < max_count ?
		    ctx->anomaly_total : max_count;

	/* Return most recent first */
	for (int i = 0; i < count; i++) {
		int idx = (ctx->anomaly_head - 1 - i + ANOMALY_RING_SIZE) %
			  ANOMALY_RING_SIZE;
		memcpy(&buf[i], &ctx->anomaly_ring[idx], sizeof(buf[i]));
	}

	return count;
}

int usage_profile_anomaly_count(const struct usage_profile_ctx *ctx)
{
	return ctx ? ctx->anomaly_total : 0;
}

int usage_profile_get_client_summaries(const struct usage_profile_ctx *ctx,
				       struct client_profile_summary *buf,
				       int max_count)
{
	if (!ctx)
		return 0;

	int count = ctx->client_count < max_count ?
		    ctx->client_count : max_count;

	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	int hour = t->tm_hour;

	for (int i = 0; i < count; i++) {
		const struct client_profile *cp = &ctx->clients[i];
		struct client_profile_summary *s = &buf[i];

		memcpy(s->mac, cp->mac, 6);
		s->bytes_current_hour = cp->cur_bytes;
		s->flows_current_hour = cp->cur_flows;
		memcpy(s->class_dist, cp->cur_class_counts,
		       sizeof(s->class_dist));
		s->anomaly_count = cp->anomaly_count;
		s->is_anomalous = cp->flagged_this_tick;

		const struct hourly_baseline *bl = &cp->baseline[hour];
		s->bytes_baseline_avg = (uint64_t)bl->avg_bytes;
		s->flows_baseline_avg = (uint32_t)bl->avg_flows;
	}

	return count;
}
