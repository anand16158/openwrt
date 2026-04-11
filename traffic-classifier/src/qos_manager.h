#ifndef QOS_MANAGER_H
#define QOS_MANAGER_H

#include "flow_table.h"

/*
 * QoS integration: maps traffic classes to DSCP marks via nftables.
 *
 * Creates an nftables table (inet traffic_classifier) with:
 *   - Named sets for each traffic class containing classified IP+port pairs
 *   - Rules that match set members and set DSCP accordingly
 *
 * DSCP mapping (configurable):
 *   video    → AF41 (0x22) — assured forwarding, high throughput
 *   gaming   → EF   (0x2E) — expedited forwarding, low latency
 *   voip     → EF   (0x2E) — expedited forwarding, low latency
 *   social   → AF21 (0x12) — medium priority
 *   browsing → AF11 (0x0A) — default priority
 *   download → CS1  (0x08) — best effort / scavenger
 *   other    → CS0  (0x00) — default
 */

#define QOS_TABLE_NAME "traffic_classifier"

struct qos_dscp_map {
	uint8_t dscp[CLASSIFICATION_LABELS];
};

struct qos_manager;

struct qos_manager *qos_manager_init(bool enabled);
void qos_manager_destroy(struct qos_manager *qm);

/* Apply DSCP marks for all currently classified flows */
int qos_manager_update(struct qos_manager *qm, struct flow_table *ft);

/* Remove all nftables rules created by the classifier */
void qos_manager_flush(struct qos_manager *qm);

/* Check if QoS marking is enabled */
bool qos_manager_enabled(const struct qos_manager *qm);

#endif
