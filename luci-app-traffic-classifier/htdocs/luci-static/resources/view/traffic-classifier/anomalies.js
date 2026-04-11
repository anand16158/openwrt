'use strict';
'require view';
'require rpc';
'require dom';
'require poll';

var callGetAnomalies = rpc.declare({
	object: 'traffic-classifier',
	method: 'get_anomalies',
	expect: {}
});

var callGetProfiles = rpc.declare({
	object: 'traffic-classifier',
	method: 'get_profiles',
	expect: {}
});

var typeColors = {
	'bandwidth_spike': '#e53935',
	'new_heavy_flow':  '#fb8c00',
	'protocol_shift':  '#8e24aa',
	'unusual_port':    '#1e88e5'
};

var typeIcons = {
	'bandwidth_spike': '⬆',
	'new_heavy_flow':  '⚡',
	'protocol_shift':  '🔀',
	'unusual_port':    '🔌'
};

function formatBytes(bytes) {
	if (bytes === 0) return '0 B';
	var k = 1024;
	var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	var i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatTimeAgo(ts) {
	var now = Math.floor(Date.now() / 1000);
	var diff = now - ts;
	if (diff < 60) return diff + 's ago';
	if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
	if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
	return Math.floor(diff / 86400) + 'd ago';
}

function severityColor(sev) {
	if (sev >= 70) return '#e53935';
	if (sev >= 40) return '#fb8c00';
	return '#43a047';
}

function severityLabel(sev) {
	if (sev >= 70) return 'HIGH';
	if (sev >= 40) return 'MEDIUM';
	return 'LOW';
}

function renderAnomalyCards(data) {
	var anomalies = (data && data.anomalies) ? data.anomalies : [];
	var total = data ? (data.total || 0) : 0;

	if (anomalies.length === 0) {
		return E('div', { 'class': 'cbi-section' }, [
			E('div', {
				'style': 'text-align:center;padding:40px;background:#e8f5e9;' +
					'border-radius:8px;border:1px solid #c8e6c9'
			}, [
				E('div', { 'style': 'font-size:48px;margin-bottom:8px' }, '✓'),
				E('div', { 'style': 'font-size:18px;font-weight:bold;color:#2e7d32' },
					'No Anomalies Detected'),
				E('div', { 'style': 'font-size:13px;color:#666;margin-top:4px' },
					'The network is behaving normally. Anomalies will appear here when unusual patterns are detected.')
			])
		]);
	}

	var cards = [];
	for (var i = 0; i < anomalies.length; i++) {
		var a = anomalies[i];
		var color = typeColors[a.type] || '#757575';
		var icon = typeIcons[a.type] || '⚠';
		var sevColor = severityColor(a.severity);
		var sevText = severityLabel(a.severity);

		cards.push(E('div', {
			'style': 'background:#fff;border-left:4px solid ' + color +
				';border-radius:4px;padding:12px 16px;margin-bottom:10px;' +
				'box-shadow:0 1px 3px rgba(0,0,0,0.12)'
		}, [
			E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;margin-bottom:6px' }, [
				E('div', { 'style': 'display:flex;align-items:center;gap:8px' }, [
					E('span', { 'style': 'font-size:18px' }, icon),
					E('span', {
						'style': 'font-weight:bold;text-transform:uppercase;' +
							'font-size:12px;color:' + color
					}, (a.type || '').replace(/_/g, ' ')),
					E('span', {
						'style': 'padding:1px 6px;border-radius:8px;font-size:10px;' +
							'font-weight:bold;color:#fff;background:' + sevColor
					}, sevText + ' (' + a.severity + '%)')
				]),
				E('span', { 'style': 'font-size:12px;color:#999' },
					a.timestamp ? formatTimeAgo(a.timestamp) : '')
			]),
			E('div', { 'style': 'display:flex;align-items:center;gap:8px;margin-bottom:4px' }, [
				E('span', {
					'style': 'font-family:monospace;font-size:12px;' +
						'padding:2px 6px;background:#f5f5f5;border-radius:3px'
				}, a.mac || '-')
			]),
			E('div', { 'style': 'font-size:13px;color:#555' }, a.detail || '')
		]));
	}

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, 'Recent Anomalies (' + total + ')'),
		E('div', {}, cards)
	]);
}

function renderProfilesTable(data) {
	var profiles = (data && data.profiles) ? data.profiles : [];

	if (profiles.length === 0) {
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, 'Client Profiles'),
			E('em', {}, 'Building baselines... profiles appear after the first profiling tick (60s).')
		]);
	}

	profiles.sort(function(a, b) {
		return (b.anomaly_count || 0) - (a.anomaly_count || 0);
	});

	var headerRow = E('tr', { 'class': 'tr table-titles' }, [
		E('th', { 'class': 'th' }, 'Client'),
		E('th', { 'class': 'th' }, 'Status'),
		E('th', { 'class': 'th' }, 'Current'),
		E('th', { 'class': 'th' }, 'Baseline'),
		E('th', { 'class': 'th' }, 'Ratio'),
		E('th', { 'class': 'th' }, 'Anomalies'),
		E('th', { 'class': 'th', 'style': 'min-width:120px' }, 'Usage Bar')
	]);

	var rows = [headerRow];

	for (var i = 0; i < profiles.length; i++) {
		var p = profiles[i];
		var ratio = (p.bytes_baseline > 0) ?
			(p.bytes_current / p.bytes_baseline).toFixed(1) + 'x' : '-';
		var ratioNum = (p.bytes_baseline > 0) ?
			p.bytes_current / p.bytes_baseline : 0;

		var statusBadge;
		if (p.is_anomalous) {
			statusBadge = E('span', {
				'style': 'padding:2px 8px;border-radius:10px;background:#e53935;' +
					'color:#fff;font-size:11px;font-weight:bold'
			}, 'ALERT');
		} else {
			statusBadge = E('span', {
				'style': 'padding:2px 8px;border-radius:10px;background:#43a047;' +
					'color:#fff;font-size:11px;font-weight:bold'
			}, 'NORMAL');
		}

		var barPct = Math.min(100, ratioNum * 33.3);
		var barColor = ratioNum > 3 ? '#e53935' : (ratioNum > 1.5 ? '#fb8c00' : '#43a047');

		var usageBar = E('div', { 'style': 'min-width:100px' }, [
			E('div', {
				'style': 'background:#e0e0e0;border-radius:3px;height:14px;overflow:hidden'
			}, [
				E('div', {
					'style': 'background:' + barColor + ';height:100%;width:' +
						barPct + '%;border-radius:3px;transition:width 0.5s'
				})
			])
		]);

		rows.push(E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td', 'style': 'font-family:monospace;font-size:12px' },
				p.mac || '-'),
			E('td', { 'class': 'td' }, statusBadge),
			E('td', { 'class': 'td' }, formatBytes(p.bytes_current || 0)),
			E('td', { 'class': 'td' }, formatBytes(p.bytes_baseline || 0)),
			E('td', { 'class': 'td', 'style': 'font-weight:bold;color:' + barColor }, ratio),
			E('td', { 'class': 'td' }, String(p.anomaly_count || 0)),
			E('td', { 'class': 'td' }, usageBar)
		]));
	}

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, 'Client Profiles (' + profiles.length + ')'),
		E('table', { 'class': 'table cbi-section-table' }, rows)
	]);
}

function renderSummaryBanner(anomalyData) {
	var total = anomalyData ? (anomalyData.total || 0) : 0;
	var anomalies = (anomalyData && anomalyData.anomalies) ? anomalyData.anomalies : [];

	var typeCounts = {};
	for (var i = 0; i < anomalies.length; i++) {
		var t = anomalies[i].type || 'unknown';
		typeCounts[t] = (typeCounts[t] || 0) + 1;
	}

	var badges = [];
	for (var type in typeCounts) {
		if (typeCounts.hasOwnProperty(type)) {
			var color = typeColors[type] || '#757575';
			badges.push(E('span', {
				'style': 'display:inline-block;padding:3px 10px;border-radius:12px;' +
					'background:' + color + ';color:#fff;font-size:12px;' +
					'font-weight:bold;margin-right:8px'
			}, (type || '').replace(/_/g, ' ') + ': ' + typeCounts[type]));
		}
	}

	var bannerColor = total === 0 ? '#e8f5e9' : (total < 5 ? '#fff3e0' : '#ffebee');
	var borderColor = total === 0 ? '#c8e6c9' : (total < 5 ? '#ffe0b2' : '#ffcdd2');

	return E('div', {
		'style': 'padding:12px 16px;background:' + bannerColor +
			';border:1px solid ' + borderColor + ';border-radius:6px;margin-bottom:16px;' +
			'display:flex;justify-content:space-between;align-items:center'
	}, [
		E('div', {}, [
			E('strong', { 'style': 'font-size:16px' },
				total === 0 ? 'All Clear' : total + ' anomalies detected'),
		]),
		E('div', { 'style': 'display:flex;flex-wrap:wrap' }, badges)
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			callGetAnomalies(),
			callGetProfiles()
		]);
	},

	render: function(data) {
		var anomalyData = data[0] || {};
		var profileData = data[1] || {};

		var content = E('div', {}, [
			E('h2', {}, 'Anomaly Detection'),
			renderSummaryBanner(anomalyData),
			renderAnomalyCards(anomalyData),
			renderProfilesTable(profileData)
		]);

		poll.add(L.bind(function() {
			return Promise.all([callGetAnomalies(), callGetProfiles()]).then(
				L.bind(function(res) {
					var root = document.querySelector(
						'[data-page="traffic-classifier-anomalies"]');
					if (!root) return;

					dom.content(root, [
						E('h2', {}, 'Anomaly Detection'),
						renderSummaryBanner(res[0] || {}),
						renderAnomalyCards(res[0] || {}),
						renderProfilesTable(res[1] || {})
					]);
				}, this)
			);
		}, this), 5);

		return E('div', { 'data-page': 'traffic-classifier-anomalies' }, [content]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
