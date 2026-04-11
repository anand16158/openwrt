#ifndef USAGE_PROFILE_H
#define USAGE_PROFILE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "flow_table.h"

/*
 * Usage Profiling & Anomaly Detection
 *
 * Builds a per-client behavioral baseline from observed traffic and
 * flags deviations as anomalies. Designed for edge deployment with
 * O(1) memory per client (fixed-size ring buffers).
 *
 * Baseline signals (per client, per hour-of-day):
 *   - Average bytes/sec
 *   - Average flow count
 *   - Dominant traffic class distribution
 *
 * Anomaly types detected:
 *   - BANDWIDTH_SPIKE:  current rate >> historical average for this hour
 *   - NEW_HEAVY_FLOW:   single flow consuming > 50% of client bandwidth
 *   - PROTOCOL_SHIFT:   traffic class distribution changed significantly
 *   - UNUSUAL_PORT:     client sending on a port never seen before
 */

#define PROFILE_MAX_CLIENTS   128
#define PROFILE_HOURS         24
#define PROFILE_HISTORY_DAYS  7
#define ANOMALY_RING_SIZE     32

enum anomaly_type {
	ANOMALY_BANDWIDTH_SPIKE = 0,
	ANOMALY_NEW_HEAVY_FLOW,
	ANOMALY_PROTOCOL_SHIFT,
	ANOMALY_UNUSUAL_PORT,
	ANOMALY_TYPE_COUNT
};

static const char * const anomaly_type_names[] = {
	[ANOMALY_BANDWIDTH_SPIKE] = "bandwidth_spike",
	[ANOMALY_NEW_HEAVY_FLOW]  = "new_heavy_flow",
	[ANOMALY_PROTOCOL_SHIFT]  = "protocol_shift",
	[ANOMALY_UNUSUAL_PORT]    = "unusual_port",
};

struct anomaly_event {
	uint8_t mac[6];
	enum anomaly_type type;
	time_t timestamp;
	char detail[128];
	float severity;       /* 0.0 = informational, 1.0 = critical */
};

struct usage_profile_ctx;

struct usage_profile_ctx *usage_profile_init(void);
void usage_profile_destroy(struct usage_profile_ctx *ctx);

/*
 * Feed current flow data into the profiler. Should be called
 * periodically (e.g. every classify cycle). Accumulates stats
 * and triggers anomaly checks.
 */
void usage_profile_update(struct usage_profile_ctx *ctx,
			  const struct flow_entry *entry);

/*
 * Advance the profiling window. Call once per minute to roll up
 * accumulated data into hourly baselines.
 */
void usage_profile_tick(struct usage_profile_ctx *ctx);

/*
 * Retrieve recent anomalies. Returns number of anomalies copied
 * into buf (up to max_count). Most recent first.
 */
int usage_profile_get_anomalies(const struct usage_profile_ctx *ctx,
				struct anomaly_event *buf, int max_count);

/*
 * Get the current anomaly count (total in the ring buffer).
 */
int usage_profile_anomaly_count(const struct usage_profile_ctx *ctx);

/*
 * Per-client summary for API consumers.
 */
struct client_profile_summary {
	uint8_t mac[6];
	uint64_t bytes_current_hour;
	uint64_t bytes_baseline_avg;
	uint32_t flows_current_hour;
	uint32_t flows_baseline_avg;
	uint32_t class_dist[CLASSIFICATION_LABELS];
	int anomaly_count;
	bool is_anomalous;
};

int usage_profile_get_client_summaries(const struct usage_profile_ctx *ctx,
				       struct client_profile_summary *buf,
				       int max_count);

#endif
