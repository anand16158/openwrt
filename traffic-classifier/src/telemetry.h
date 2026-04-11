#ifndef TELEMETRY_H
#define TELEMETRY_H

#include "flow_table.h"
#include "sta_tracker.h"
#include "classifier.h"
#include "dns_cache.h"
#include "device_fingerprint.h"
#include "usage_profile.h"

/*
 * Telemetry: exports classification data as JSON for consumption by
 * uCentral, external dashboards, or local logging.
 *
 * Output modes:
 *   1. File: Write JSON snapshot to a configured path (default:
 *      /tmp/traffic-classifier-telemetry.json)
 *   2. ubus notification: Emit a ubus event that the uCentral agent
 *      or any subscriber can listen for
 */

struct telemetry_ctx;

struct telemetry_config {
	bool enabled;
	int interval_sec;
	char file_path[256];
	bool ubus_notify;
};

struct telemetry_ctx *telemetry_init(const struct telemetry_config *cfg,
				     struct flow_table *ft,
				     struct sta_tracker *sta,
				     struct device_fp_ctx *devfp,
				     struct usage_profile_ctx *profiler,
				     struct ubus_context *ubus);
void telemetry_destroy(struct telemetry_ctx *ctx);

/* Generate and export a telemetry snapshot */
int telemetry_export(struct telemetry_ctx *ctx);

bool telemetry_enabled(const struct telemetry_ctx *ctx);

#endif
