#ifndef DATA_COLLECT_H
#define DATA_COLLECT_H

#include <stdint.h>
#include <stdbool.h>
#include "flow_table.h"

/*
 * Real-traffic Data Collector for ML Retraining
 *
 * Records labeled flow feature vectors to CSV on-device.
 * The output file can be copied off the router and fed directly
 * into the training pipeline (training/build_model.py) to improve
 * the ML model with real-world data.
 *
 * CSV columns: 20 features + label + domain + app_name + timestamp
 *
 * Features controlled via:
 *   - CLI flag -C <path>  to set output path and enable capture
 *   - ubus method "capture_start" / "capture_stop"
 *   - UCI option data_capture_path
 */

#define DATA_COLLECT_DEFAULT_PATH "/tmp/tc-training-data.csv"
#define DATA_COLLECT_MAX_ROWS     50000

struct data_collect_ctx;

struct data_collect_ctx *data_collect_init(const char *output_path);
void data_collect_destroy(struct data_collect_ctx *ctx);

/*
 * Record a classified flow as a training sample.
 * Only logs flows with sufficient packets and a confident classification.
 */
void data_collect_record(struct data_collect_ctx *ctx,
			 const struct flow_entry *entry);

/* Start/stop collection at runtime (via ubus) */
void data_collect_start(struct data_collect_ctx *ctx);
void data_collect_stop(struct data_collect_ctx *ctx);
bool data_collect_is_active(const struct data_collect_ctx *ctx);

/* Stats for the ubus API */
uint32_t data_collect_row_count(const struct data_collect_ctx *ctx);
const char *data_collect_path(const struct data_collect_ctx *ctx);

#endif
