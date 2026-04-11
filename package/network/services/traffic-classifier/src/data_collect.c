#include "data_collect.h"
#include "features.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#define MIN_PKTS_FOR_SAMPLE  10
#define MIN_CONFIDENCE       0.40f

struct data_collect_ctx {
	char path[256];
	FILE *fp;
	uint32_t rows;
	bool active;
	bool header_written;
};

static const char *csv_header =
	"flow_duration_sec,total_fwd_packets,total_bwd_packets,"
	"total_fwd_bytes,total_bwd_bytes,fwd_bwd_bytes_ratio,"
	"avg_packet_size,std_packet_size,avg_iat_usec,std_iat_usec,"
	"min_packet_size,max_packet_size,packets_per_second,"
	"bytes_per_second,fwd_pkt_ratio,avg_fwd_pkt_size,"
	"avg_bwd_pkt_size,tcp_flags_or,syn_count,protocol,"
	"label,class_name,domain,app_name,src_port,dst_port,timestamp\n";

struct data_collect_ctx *data_collect_init(const char *output_path)
{
	struct data_collect_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	snprintf(ctx->path, sizeof(ctx->path), "%s",
		 output_path ? output_path : DATA_COLLECT_DEFAULT_PATH);

	ctx->fp = fopen(ctx->path, "a");
	if (!ctx->fp) {
		syslog(LOG_ERR, "data_collect: cannot open %s", ctx->path);
		free(ctx);
		return NULL;
	}

	/* Check if file is empty → write header */
	fseek(ctx->fp, 0, SEEK_END);
	long sz = ftell(ctx->fp);
	if (sz == 0) {
		fputs(csv_header, ctx->fp);
		fflush(ctx->fp);
		ctx->header_written = true;
	} else {
		ctx->header_written = true;
	}

	ctx->active = true;

	syslog(LOG_INFO, "data_collect: recording to %s (append mode)",
	       ctx->path);
	return ctx;
}

void data_collect_destroy(struct data_collect_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->fp) {
		fflush(ctx->fp);
		fclose(ctx->fp);
	}
	syslog(LOG_INFO, "data_collect: stopped (%u rows recorded)",
	       ctx->rows);
	free(ctx);
}

void data_collect_start(struct data_collect_ctx *ctx)
{
	if (!ctx)
		return;
	if (!ctx->fp) {
		ctx->fp = fopen(ctx->path, "a");
		if (!ctx->fp) {
			syslog(LOG_ERR, "data_collect: cannot reopen %s",
			       ctx->path);
			return;
		}
	}
	ctx->active = true;
	syslog(LOG_INFO, "data_collect: capture started");
}

void data_collect_stop(struct data_collect_ctx *ctx)
{
	if (!ctx)
		return;
	ctx->active = false;
	if (ctx->fp)
		fflush(ctx->fp);
	syslog(LOG_INFO, "data_collect: capture paused (%u rows so far)",
	       ctx->rows);
}

bool data_collect_is_active(const struct data_collect_ctx *ctx)
{
	return ctx && ctx->active;
}

uint32_t data_collect_row_count(const struct data_collect_ctx *ctx)
{
	return ctx ? ctx->rows : 0;
}

const char *data_collect_path(const struct data_collect_ctx *ctx)
{
	return ctx ? ctx->path : "";
}

void data_collect_record(struct data_collect_ctx *ctx,
			 const struct flow_entry *entry)
{
	if (!ctx || !ctx->active || !ctx->fp)
		return;

	if (ctx->rows >= DATA_COLLECT_MAX_ROWS) {
		if (ctx->active) {
			syslog(LOG_NOTICE,
			       "data_collect: max rows (%u) reached, pausing",
			       DATA_COLLECT_MAX_ROWS);
			ctx->active = false;
		}
		return;
	}

	uint32_t total_pkts = entry->stats.total_pkts_fwd +
			      entry->stats.total_pkts_bwd;
	if (total_pkts < MIN_PKTS_FOR_SAMPLE)
		return;

	if (entry->classification == CLASS_UNKNOWN &&
	    entry->confidence < MIN_CONFIDENCE)
		return;

	float features[NUM_FEATURES];
	features_extract(entry, features);

	const char *class_name =
		(entry->classification < CLASSIFICATION_LABELS)
		? traffic_class_names[entry->classification] : "unknown";

	/* Write 20 features */
	for (int i = 0; i < NUM_FEATURES; i++)
		fprintf(ctx->fp, "%.6g,", features[i]);

	/* label, class_name */
	fprintf(ctx->fp, "%d,%s,", entry->classification, class_name);

	/* domain (escape commas) */
	if (entry->dns_hint[0])
		fprintf(ctx->fp, "%s,", entry->dns_hint);
	else
		fprintf(ctx->fp, ",");

	/* app_name */
	if (entry->app_name[0])
		fprintf(ctx->fp, "%s,", entry->app_name);
	else
		fprintf(ctx->fp, ",");

	/* ports + timestamp */
	fprintf(ctx->fp, "%u,%u,%lld\n",
		entry->key.src_port, entry->key.dst_port,
		(long long)time(NULL));

	ctx->rows++;

	/* Flush periodically for crash safety */
	if ((ctx->rows % 100) == 0)
		fflush(ctx->fp);
}
