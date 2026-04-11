#include "qos_manager.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>

#define QOS_CMD_BUF   512
#define QOS_NFT_TABLE "inet " QOS_TABLE_NAME
#define QOS_NFT_CHAIN "classify"

struct qos_manager {
	bool enabled;
	bool table_created;
	struct qos_dscp_map dscp;
	uint32_t update_seq;
};

static const uint8_t default_dscp[CLASSIFICATION_LABELS] = {
	[CLASS_UNKNOWN]  = 0x00,   /* CS0 — default */
	[CLASS_VIDEO]    = 0x22,   /* AF41 — high throughput */
	[CLASS_GAMING]   = 0x2E,   /* EF — low latency */
	[CLASS_SOCIAL]   = 0x12,   /* AF21 — medium */
	[CLASS_BROWSING] = 0x0A,   /* AF11 — normal */
	[CLASS_DOWNLOAD] = 0x08,   /* CS1 — scavenger */
	[CLASS_VOIP]     = 0x2E,   /* EF — low latency */
	[CLASS_OTHER]    = 0x00,   /* CS0 — default */
};

static int run_nft(const char *cmd)
{
	char buf[QOS_CMD_BUF];
	snprintf(buf, sizeof(buf), "nft %s 2>/dev/null", cmd);
	return system(buf);
}

static int setup_nft_table(struct qos_manager *qm)
{
	if (qm->table_created)
		return 0;

	run_nft("add table " QOS_NFT_TABLE);
	run_nft("add chain " QOS_NFT_TABLE " " QOS_NFT_CHAIN
		" { type filter hook forward priority mangle\\; }");

	/* Sets for storing classified destination IPs per class */
	run_nft("add set " QOS_NFT_TABLE " video_ips"
		" { type ipv4_addr\\; timeout 60s\\; }");
	run_nft("add set " QOS_NFT_TABLE " gaming_ips"
		" { type ipv4_addr\\; timeout 60s\\; }");
	run_nft("add set " QOS_NFT_TABLE " voip_ips"
		" { type ipv4_addr\\; timeout 60s\\; }");
	run_nft("add set " QOS_NFT_TABLE " social_ips"
		" { type ipv4_addr\\; timeout 60s\\; }");
	run_nft("add set " QOS_NFT_TABLE " download_ips"
		" { type ipv4_addr\\; timeout 60s\\; }");

	/* DSCP marking rules referencing the sets */
	char cmd[QOS_CMD_BUF];

	snprintf(cmd, sizeof(cmd),
		 "add rule " QOS_NFT_TABLE " " QOS_NFT_CHAIN
		 " ip daddr @video_ips ip dscp set 0x%02x",
		 qm->dscp.dscp[CLASS_VIDEO]);
	run_nft(cmd);

	snprintf(cmd, sizeof(cmd),
		 "add rule " QOS_NFT_TABLE " " QOS_NFT_CHAIN
		 " ip daddr @gaming_ips ip dscp set 0x%02x",
		 qm->dscp.dscp[CLASS_GAMING]);
	run_nft(cmd);

	snprintf(cmd, sizeof(cmd),
		 "add rule " QOS_NFT_TABLE " " QOS_NFT_CHAIN
		 " ip daddr @voip_ips ip dscp set 0x%02x",
		 qm->dscp.dscp[CLASS_VOIP]);
	run_nft(cmd);

	snprintf(cmd, sizeof(cmd),
		 "add rule " QOS_NFT_TABLE " " QOS_NFT_CHAIN
		 " ip daddr @social_ips ip dscp set 0x%02x",
		 qm->dscp.dscp[CLASS_SOCIAL]);
	run_nft(cmd);

	snprintf(cmd, sizeof(cmd),
		 "add rule " QOS_NFT_TABLE " " QOS_NFT_CHAIN
		 " ip daddr @download_ips ip dscp set 0x%02x",
		 qm->dscp.dscp[CLASS_DOWNLOAD]);
	run_nft(cmd);

	qm->table_created = true;
	syslog(LOG_INFO, "qos: nftables table and sets created");
	return 0;
}

struct qos_manager *qos_manager_init(bool enabled)
{
	struct qos_manager *qm = calloc(1, sizeof(*qm));
	if (!qm)
		return NULL;

	qm->enabled = enabled;
	memcpy(qm->dscp.dscp, default_dscp, sizeof(default_dscp));

	if (enabled) {
		if (setup_nft_table(qm) < 0) {
			syslog(LOG_WARNING,
			       "qos: nftables setup failed, disabling");
			qm->enabled = false;
		}
	}

	return qm;
}

void qos_manager_destroy(struct qos_manager *qm)
{
	if (!qm)
		return;
	if (qm->table_created)
		qos_manager_flush(qm);
	free(qm);
}

static const char *class_set_name(enum traffic_class cls)
{
	switch (cls) {
	case CLASS_VIDEO:    return "video_ips";
	case CLASS_GAMING:   return "gaming_ips";
	case CLASS_VOIP:     return "voip_ips";
	case CLASS_SOCIAL:   return "social_ips";
	case CLASS_DOWNLOAD: return "download_ips";
	default: return NULL;
	}
}

struct qos_update_ctx {
	struct qos_manager *qm;
	int updated;
};

static int qos_flow_cb(struct flow_entry *entry, void *arg)
{
	struct qos_update_ctx *ctx = (struct qos_update_ctx *)arg;
	const char *setname;
	char addr_buf[INET_ADDRSTRLEN];
	char cmd[QOS_CMD_BUF];

	if (entry->classification == CLASS_UNKNOWN ||
	    entry->classification == CLASS_OTHER ||
	    entry->classification == CLASS_BROWSING)
		return 0;

	setname = class_set_name(entry->classification);
	if (!setname)
		return 0;

	/* Only handle IPv4 for now (mapped addresses in flow_key) */
	if (entry->key.is_ipv6)
		return 0;

	inet_ntop(AF_INET, &entry->key.dst_ip.s6_addr[12],
		  addr_buf, sizeof(addr_buf));

	snprintf(cmd, sizeof(cmd),
		 "add element " QOS_NFT_TABLE " %s { %s }",
		 setname, addr_buf);
	run_nft(cmd);

	ctx->updated++;
	return 0;
}

int qos_manager_update(struct qos_manager *qm, struct flow_table *ft)
{
	if (!qm || !qm->enabled)
		return 0;

	if (!qm->table_created)
		setup_nft_table(qm);

	struct qos_update_ctx ctx = { .qm = qm, .updated = 0 };
	flow_table_for_each(ft, qos_flow_cb, &ctx);

	qm->update_seq++;

	if (ctx.updated > 0)
		syslog(LOG_DEBUG, "qos: updated %d nftables set entries "
		       "(seq=%u)", ctx.updated, qm->update_seq);

	return ctx.updated;
}

void qos_manager_flush(struct qos_manager *qm)
{
	if (!qm || !qm->table_created)
		return;

	run_nft("delete table " QOS_NFT_TABLE);
	qm->table_created = false;
	syslog(LOG_INFO, "qos: flushed nftables table");
}

bool qos_manager_enabled(const struct qos_manager *qm)
{
	return qm && qm->enabled;
}
