#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <getopt.h>

#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubus.h>

#include "flow_table.h"
#include "capture.h"
#include "classifier.h"
#include "sta_tracker.h"
#include "dns_cache.h"
#include "qos_manager.h"
#include "telemetry.h"
#include "device_fingerprint.h"
#include "usage_profile.h"
#include "data_collect.h"
#include "ubus_api.h"

#define DEFAULT_INTERFACE    "br-lan"
#define DEFAULT_MAX_FLOWS    8192
#define DEFAULT_MODEL_PATH   "/etc/traffic-classifier/model.json"
#define CLASSIFY_INTERVAL_MS 5000
#define EXPIRE_INTERVAL_MS   10000
#define STA_REFRESH_MS       15000
#define QOS_UPDATE_MS        10000
#define PROFILE_TICK_MS      60000

struct tc_daemon {
	struct flow_table *ft;
	struct capture_ctx *cap;
	struct classifier_ctx *cls;
	struct sta_tracker *sta;
	struct dns_cache *dc;
	struct qos_manager *qos;
	struct telemetry_ctx *telem;
	struct device_fp_ctx *devfp;
	struct usage_profile_ctx *profiler;
	struct data_collect_ctx *collector;
	struct tc_ubus_ctx ubus_ctx;

	struct uloop_fd capture_fd;
	struct uloop_timeout classify_timer;
	struct uloop_timeout expire_timer;
	struct uloop_timeout sta_timer;
	struct uloop_timeout qos_timer;
	struct uloop_timeout telem_timer;
	struct uloop_timeout profile_timer;

	int telem_interval_ms;
};

static struct tc_daemon daemon_ctx;

static void capture_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	struct tc_daemon *d = container_of(fd, struct tc_daemon, capture_fd);
	capture_process(d->cap);
}

static int classify_flow_cb(struct flow_entry *entry, void *ctx)
{
	struct tc_daemon *d = (struct tc_daemon *)ctx;
	classifier_classify_flow(d->cls, entry);
	if (d->devfp)
		device_fp_analyze_flow(d->devfp, entry);
	if (d->profiler)
		usage_profile_update(d->profiler, entry);
	if (d->collector)
		data_collect_record(d->collector, entry);
	return 0;
}

static void classify_timer_cb(struct uloop_timeout *t)
{
	struct tc_daemon *d = container_of(t, struct tc_daemon, classify_timer);
	flow_table_for_each(d->ft, classify_flow_cb, d);
	uloop_timeout_set(t, CLASSIFY_INTERVAL_MS);
}

static void expire_timer_cb(struct uloop_timeout *t)
{
	struct tc_daemon *d = container_of(t, struct tc_daemon, expire_timer);
	flow_table_expire(d->ft, time(NULL), FLOW_TIMEOUT_SEC);
	dns_cache_expire(d->dc, time(NULL));
	uloop_timeout_set(t, EXPIRE_INTERVAL_MS);
}

static void sta_timer_cb(struct uloop_timeout *t)
{
	struct tc_daemon *d = container_of(t, struct tc_daemon, sta_timer);
	sta_tracker_refresh(d->sta);
	uloop_timeout_set(t, STA_REFRESH_MS);
}

static void qos_timer_cb(struct uloop_timeout *t)
{
	struct tc_daemon *d = container_of(t, struct tc_daemon, qos_timer);
	if (d->qos && qos_manager_enabled(d->qos))
		qos_manager_update(d->qos, d->ft);
	uloop_timeout_set(t, QOS_UPDATE_MS);
}

static void profile_timer_cb(struct uloop_timeout *t)
{
	struct tc_daemon *d = container_of(t, struct tc_daemon, profile_timer);
	if (d->profiler)
		usage_profile_tick(d->profiler);
	uloop_timeout_set(t, PROFILE_TICK_MS);
}

static void telem_timer_cb(struct uloop_timeout *t)
{
	struct tc_daemon *d = container_of(t, struct tc_daemon, telem_timer);
	if (d->telem && telemetry_enabled(d->telem))
		telemetry_export(d->telem);
	uloop_timeout_set(t, d->telem_interval_ms);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"  -i <interface>    Capture interface (default: %s)\n"
		"  -m <model_path>   ML model file (default: %s)\n"
		"  -n <max_flows>    Max concurrent flows (default: %d)\n"
		"  -q                Enable QoS DSCP marking via nftables\n"
		"  -t <seconds>      Telemetry export interval (0=disabled)\n"
		"  -T <path>         Telemetry output file path\n"
		"  -C <path>         Enable data capture for ML retraining\n"
		"  -d                Debug mode (foreground, verbose)\n"
		"  -h                Show this help\n",
		prog, DEFAULT_INTERFACE, DEFAULT_MODEL_PATH, DEFAULT_MAX_FLOWS);
}

int main(int argc, char **argv)
{
	const char *ifname = DEFAULT_INTERFACE;
	const char *model_path = DEFAULT_MODEL_PATH;
	const char *telem_path = "/tmp/traffic-classifier-telemetry.json";
	const char *capture_path = NULL;
	int max_flows = DEFAULT_MAX_FLOWS;
	int telem_interval = 0;
	bool debug = false;
	bool qos_enabled = false;
	int opt;

	while ((opt = getopt(argc, argv, "i:m:n:t:T:C:dqh")) != -1) {
		switch (opt) {
		case 'i': ifname = optarg; break;
		case 'm': model_path = optarg; break;
		case 'n': max_flows = atoi(optarg); break;
		case 't': telem_interval = atoi(optarg); break;
		case 'T': telem_path = optarg; break;
		case 'C': capture_path = optarg; break;
		case 'd': debug = true; break;
		case 'q': qos_enabled = true; break;
		case 'h':
		default:
			usage(argv[0]);
			return (opt == 'h') ? 0 : 1;
		}
	}

	openlog("traffic-classifier", LOG_PID | (debug ? LOG_PERROR : 0), LOG_DAEMON);
	syslog(LOG_INFO, "starting (iface=%s, max_flows=%d)", ifname, max_flows);

	uloop_init();

	struct ubus_context *ubus = ubus_connect(NULL);
	if (!ubus) {
		syslog(LOG_ERR, "failed to connect to ubus");
		return 1;
	}
	ubus_add_uloop(ubus);

	struct tc_daemon *d = &daemon_ctx;
	memset(d, 0, sizeof(*d));

	d->ft = flow_table_create(max_flows);
	if (!d->ft) {
		syslog(LOG_ERR, "failed to create flow table");
		return 1;
	}

	d->dc = dns_cache_create(DNS_MAX_ENTRIES);
	if (!d->dc) {
		syslog(LOG_ERR, "failed to create dns cache");
		return 1;
	}

	d->cls = classifier_init(model_path, d->dc);
	if (!d->cls) {
		syslog(LOG_ERR, "failed to init classifier");
		return 1;
	}

	d->sta = sta_tracker_init(ubus);
	if (!d->sta) {
		syslog(LOG_ERR, "failed to init sta tracker");
		return 1;
	}

	d->cap = capture_init(ifname, d->ft, d->dc);
	if (!d->cap) {
		syslog(LOG_ERR, "failed to init capture on %s", ifname);
		return 1;
	}

	d->devfp = device_fp_init(d->dc);
	d->profiler = usage_profile_init();

	if (capture_path)
		d->collector = data_collect_init(capture_path);

	d->qos = qos_manager_init(qos_enabled);
	if (qos_enabled && !d->qos) {
		syslog(LOG_WARNING, "qos init failed, continuing without QoS");
	}

	if (telem_interval > 0) {
		struct telemetry_config tcfg = {
			.enabled = true,
			.interval_sec = telem_interval,
			.ubus_notify = true,
		};
		snprintf(tcfg.file_path, sizeof(tcfg.file_path),
			 "%s", telem_path);
		d->telem = telemetry_init(&tcfg, d->ft, d->sta, d->devfp,
					  d->profiler, ubus);
		d->telem_interval_ms = telem_interval * 1000;
	}

	d->ubus_ctx.ubus = ubus;
	d->ubus_ctx.ft = d->ft;
	d->ubus_ctx.classifier = d->cls;
	d->ubus_ctx.sta = d->sta;
	d->ubus_ctx.devfp = d->devfp;
	d->ubus_ctx.profiler = d->profiler;
	d->ubus_ctx.collector = d->collector;

	if (tc_ubus_init(&d->ubus_ctx) != 0) {
		syslog(LOG_ERR, "failed to register ubus object");
		return 1;
	}

	d->capture_fd.fd = capture_get_fd(d->cap);
	d->capture_fd.cb = capture_fd_cb;
	uloop_fd_add(&d->capture_fd, ULOOP_READ);

	d->classify_timer.cb = classify_timer_cb;
	uloop_timeout_set(&d->classify_timer, CLASSIFY_INTERVAL_MS);

	d->expire_timer.cb = expire_timer_cb;
	uloop_timeout_set(&d->expire_timer, EXPIRE_INTERVAL_MS);

	d->sta_timer.cb = sta_timer_cb;
	uloop_timeout_set(&d->sta_timer, STA_REFRESH_MS);

	if (d->qos && qos_manager_enabled(d->qos)) {
		d->qos_timer.cb = qos_timer_cb;
		uloop_timeout_set(&d->qos_timer, QOS_UPDATE_MS);
		syslog(LOG_INFO, "qos: DSCP marking enabled");
	}

	if (d->telem && telemetry_enabled(d->telem)) {
		d->telem_timer.cb = telem_timer_cb;
		uloop_timeout_set(&d->telem_timer, d->telem_interval_ms);
		syslog(LOG_INFO, "telemetry: export every %ds to %s",
		       telem_interval, telem_path);
	}

	if (d->profiler) {
		d->profile_timer.cb = profile_timer_cb;
		uloop_timeout_set(&d->profile_timer, PROFILE_TICK_MS);
		syslog(LOG_INFO, "usage_profile: anomaly detection enabled (tick=%ds)",
		       PROFILE_TICK_MS / 1000);
	}

	if (d->collector) {
		syslog(LOG_INFO, "data_collect: capturing training data to %s",
		       data_collect_path(d->collector));
	}

	sta_tracker_refresh(d->sta);

	syslog(LOG_INFO, "daemon ready, entering main loop");
	uloop_run();

	tc_ubus_cleanup(&d->ubus_ctx);
	telemetry_destroy(d->telem);
	qos_manager_destroy(d->qos);
	data_collect_destroy(d->collector);
	usage_profile_destroy(d->profiler);
	device_fp_destroy(d->devfp);
	capture_destroy(d->cap);
	classifier_destroy(d->cls);
	sta_tracker_destroy(d->sta);
	dns_cache_destroy(d->dc);
	flow_table_destroy(d->ft);
	ubus_free(ubus);
	uloop_done();

	syslog(LOG_INFO, "shutdown complete");
	closelog();

	return 0;
}
