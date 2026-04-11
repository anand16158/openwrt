#ifndef DEVICE_FINGERPRINT_H
#define DEVICE_FINGERPRINT_H

#include <stdint.h>
#include <stdbool.h>
#include "flow_table.h"
#include "dns_cache.h"

/*
 * Device fingerprinting: identifies the type and OS of each connected
 * client based on passive traffic analysis.
 *
 * Signals used:
 *   1. DNS queries — captive portal checks, NTP servers, update domains
 *      reveal the OS (Android, iOS, Windows, macOS, Linux, etc.)
 *   2. DHCP vendor class / hostname patterns (future)
 *   3. Traffic behavioral profile — IoT devices have distinctive
 *      patterns (few destinations, periodic, small payloads)
 *
 * Each station accumulates evidence via "votes" — multiple signals
 * reinforcing each other increase confidence.
 */

#define MAX_DEVICE_TYPES 10

enum device_type {
	DEV_UNKNOWN = 0,
	DEV_ANDROID,
	DEV_IPHONE,
	DEV_WINDOWS,
	DEV_MACOS,
	DEV_LINUX,
	DEV_SMART_TV,
	DEV_IOT,
	DEV_GAMING_CONSOLE,
	DEV_OTHER,
};

/* Use device_type_to_name() to get the string for a device type */

struct device_evidence {
	uint8_t mac[6];
	int votes[MAX_DEVICE_TYPES];
	enum device_type best_guess;
	float confidence;
	bool resolved;
};

struct device_fp_ctx;

struct device_fp_ctx *device_fp_init(struct dns_cache *dc);
void device_fp_destroy(struct device_fp_ctx *ctx);

/*
 * Analyze a flow and accumulate fingerprinting evidence for the
 * source MAC. Call this periodically for active flows.
 */
void device_fp_analyze_flow(struct device_fp_ctx *ctx,
			    const struct flow_entry *entry);

/*
 * Look up the best device type guess for a MAC address.
 * Returns DEV_UNKNOWN if no evidence exists yet.
 */
enum device_type device_fp_get_type(const struct device_fp_ctx *ctx,
				    const uint8_t *mac);
const char *device_fp_get_name(const struct device_fp_ctx *ctx,
			       const uint8_t *mac);
float device_fp_get_confidence(const struct device_fp_ctx *ctx,
			       const uint8_t *mac);

const char *device_type_to_name(enum device_type dt);

#endif
