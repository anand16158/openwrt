#ifndef CLASSIFIER_H
#define CLASSIFIER_H

#include "flow_table.h"
#include "features.h"
#include "dns_cache.h"

/*
 * Three-phase classification:
 *
 * 1. Domain-aware: DNS cache maps IPs to domains. If a flow's destination
 *    matches a known service (youtube.com → video), classify with high
 *    confidence immediately.
 *
 * 2. Port/protocol heuristic: Well-known ports (DNS, SIP) and statistical
 *    thresholds (packet size, rate, direction ratio) catch common patterns.
 *
 * 3. ML model (Phase 2): Statistical features fed to a treelite-compiled
 *    XGBoost decision tree ensemble. Pure C, no runtime dependencies.
 */

struct classifier_ctx;

struct classifier_ctx *classifier_init(const char *model_path,
				       struct dns_cache *dc);
void classifier_destroy(struct classifier_ctx *ctx);

void classifier_classify_flow(struct classifier_ctx *ctx,
			      struct flow_entry *entry);

const char *classifier_class_name(enum traffic_class cls);

#endif
