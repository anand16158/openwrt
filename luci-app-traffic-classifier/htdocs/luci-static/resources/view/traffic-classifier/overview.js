'use strict';
'require view';
'require rpc';
'require dom';
'require poll';

var callStatus = rpc.declare({
	object: 'traffic-classifier',
	method: 'status',
	expect: {}
});

var callGetStats = rpc.declare({
	object: 'traffic-classifier',
	method: 'get_stats',
	expect: {}
});

var callGetClients = rpc.declare({
	object: 'traffic-classifier',
	method: 'get_clients',
	expect: {}
});

var callGetAnomalies = rpc.declare({
	object: 'traffic-classifier',
	method: 'get_anomalies',
	expect: {}
});

var classColors = {
	'unknown':  '#9e9e9e',
	'video':    '#e53935',
	'gaming':   '#8e24aa',
	'social':   '#1e88e5',
	'browsing': '#43a047',
	'download': '#fb8c00',
	'voip':     '#00acc1',
	'other':    '#6d4c41'
};

function formatBytes(bytes) {
	if (bytes === 0) return '0 B';
	var k = 1024;
	var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	var i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function renderStatusCard(status) {
	var table = E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td', 'style': 'width:50%' }, E('strong', {}, 'Version')),
			E('td', { 'class': 'td' }, status.version || '-')
		]),
		E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, E('strong', {}, 'Status')),
			E('td', { 'class': 'td' }, [
				E('span', {
					'style': 'color:' + (status.status === 'running' ? '#43a047' : '#e53935') +
						';font-weight:bold'
				}, (status.status || 'unknown').toUpperCase())
			])
		]),
		E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, E('strong', {}, 'Active Flows')),
			E('td', { 'class': 'td' }, String(status.active_flows || 0))
		]),
		E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, E('strong', {}, 'Max Flows')),
			E('td', { 'class': 'td' }, String(status.max_flows || 0))
		]),
		E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, E('strong', {}, 'Tracked Stations')),
			E('td', { 'class': 'td' }, String(status.tracked_stations || 0))
		])
	]);

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, 'Daemon Status'),
		table
	]);
}

function renderClassificationBars(stats) {
	var classification = stats.classification || {};
	var totalFlows = 0;
	var entries = [];

	for (var cls in classification) {
		if (classification.hasOwnProperty(cls) && classification[cls] > 0) {
			entries.push({ name: cls, count: classification[cls] });
			totalFlows += classification[cls];
		}
	}

	entries.sort(function(a, b) { return b.count - a.count; });

	var rows = [];
	for (var i = 0; i < entries.length; i++) {
		var e = entries[i];
		var pct = totalFlows > 0 ? (e.count / totalFlows * 100) : 0;
		var color = classColors[e.name] || '#757575';

		rows.push(E('div', { 'style': 'margin-bottom:12px' }, [
			E('div', { 'style': 'display:flex;justify-content:space-between;margin-bottom:4px' }, [
				E('span', { 'style': 'font-weight:bold;text-transform:capitalize' }, e.name),
				E('span', {}, e.count + ' flows (' + pct.toFixed(1) + '%)')
			]),
			E('div', {
				'style': 'background:#e0e0e0;border-radius:4px;height:24px;overflow:hidden'
			}, [
				E('div', {
					'style': 'background:' + color +
						';height:100%;width:' + pct + '%;border-radius:4px;' +
						'transition:width 0.5s ease'
				})
			])
		]));
	}

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, 'Traffic Classification'),
		E('div', { 'style': 'padding:8px' }, [
			E('div', { 'style': 'display:flex;justify-content:space-between;margin-bottom:16px' }, [
				E('span', {}, [
					E('strong', {}, 'Total Flows: '),
					String(totalFlows)
				]),
				E('span', {}, [
					E('strong', {}, 'Total Bytes: '),
					formatBytes(stats.total_bytes || 0)
				]),
				E('span', {}, [
					E('strong', {}, 'Stations: '),
					String(stats.tracked_stations || 0)
				])
			]),
			E('div', {}, rows)
		])
	]);
}

function renderDonutChart(stats) {
	var classification = stats.classification || {};
	var entries = [];
	var total = 0;

	for (var cls in classification) {
		if (classification.hasOwnProperty(cls) && classification[cls] > 0) {
			entries.push({ name: cls, count: classification[cls] });
			total += classification[cls];
		}
	}

	if (total === 0) {
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, 'Distribution'),
			E('em', {}, 'No classified flows yet.')
		]);
	}

	entries.sort(function(a, b) { return b.count - a.count; });

	var size = 200;
	var cx = size / 2, cy = size / 2, r = 80, innerR = 50;
	var paths = [];
	var angle = -Math.PI / 2;

	for (var i = 0; i < entries.length; i++) {
		var e = entries[i];
		var sliceAngle = (e.count / total) * 2 * Math.PI;
		var endAngle = angle + sliceAngle;
		var largeArc = sliceAngle > Math.PI ? 1 : 0;
		var color = classColors[e.name] || '#757575';

		var x1 = cx + r * Math.cos(angle);
		var y1 = cy + r * Math.sin(angle);
		var x2 = cx + r * Math.cos(endAngle);
		var y2 = cy + r * Math.sin(endAngle);
		var ix1 = cx + innerR * Math.cos(endAngle);
		var iy1 = cy + innerR * Math.sin(endAngle);
		var ix2 = cx + innerR * Math.cos(angle);
		var iy2 = cy + innerR * Math.sin(angle);

		var d = 'M ' + x1 + ' ' + y1 +
			' A ' + r + ' ' + r + ' 0 ' + largeArc + ' 1 ' + x2 + ' ' + y2 +
			' L ' + ix1 + ' ' + iy1 +
			' A ' + innerR + ' ' + innerR + ' 0 ' + largeArc + ' 0 ' + ix2 + ' ' + iy2 +
			' Z';

		paths.push('<path d="' + d + '" fill="' + color + '"/>');
		angle = endAngle;
	}

	var svg = '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '">' +
		paths.join('') +
		'<text x="' + cx + '" y="' + (cy - 5) + '" text-anchor="middle" font-size="20" font-weight="bold">' + total + '</text>' +
		'<text x="' + cx + '" y="' + (cy + 15) + '" text-anchor="middle" font-size="12" fill="#666">flows</text>' +
		'</svg>';

	var legendItems = [];
	for (var j = 0; j < entries.length; j++) {
		var le = entries[j];
		var pct = (le.count / total * 100).toFixed(1);
		legendItems.push(
			'<div style="display:flex;align-items:center;margin-bottom:4px">' +
			'<span style="width:12px;height:12px;border-radius:2px;background:' +
			(classColors[le.name] || '#757575') + ';margin-right:8px;display:inline-block"></span>' +
			'<span style="text-transform:capitalize">' + le.name + ' — ' + le.count + ' (' + pct + '%)</span>' +
			'</div>'
		);
	}

	var container = E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, 'Distribution')
	]);

	var inner = E('div', {
		'style': 'display:flex;align-items:center;gap:32px;flex-wrap:wrap;padding:8px'
	});
	inner.innerHTML = svg + '<div>' + legendItems.join('') + '</div>';
	container.appendChild(inner);

	return container;
}

var devColors = {
	'Android': '#3ddc84', 'iPhone/iPad': '#007aff', 'Windows': '#00a4ef',
	'macOS': '#a2aaad', 'Linux': '#f9a825', 'Smart TV': '#7b1fa2',
	'IoT': '#ff7043', 'Game Console': '#e53935', 'unknown': '#bdbdbd',
	'other': '#795548'
};

function renderDeviceDistribution(clients) {
	var list = (clients && clients.clients) ? clients.clients : [];
	var counts = {};
	var total = 0;

	for (var i = 0; i < list.length; i++) {
		var dt = list[i].device_type || 'unknown';
		counts[dt] = (counts[dt] || 0) + 1;
		total++;
	}

	if (total === 0)
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, 'Device Types'),
			E('em', {}, 'No clients detected yet.')
		]);

	var entries = [];
	for (var name in counts)
		if (counts.hasOwnProperty(name))
			entries.push({ name: name, count: counts[name] });
	entries.sort(function(a, b) { return b.count - a.count; });

	var rows = [];
	for (var j = 0; j < entries.length; j++) {
		var e = entries[j];
		var pct = (e.count / total * 100).toFixed(1);
		var color = devColors[e.name] || '#757575';

		rows.push(E('div', { 'style': 'margin-bottom:10px' }, [
			E('div', { 'style': 'display:flex;justify-content:space-between;margin-bottom:3px' }, [
				E('span', { 'style': 'font-weight:bold' }, e.name),
				E('span', {}, e.count + ' (' + pct + '%)')
			]),
			E('div', { 'style': 'background:#e0e0e0;border-radius:4px;height:20px;overflow:hidden' }, [
				E('div', {
					'style': 'background:' + color + ';height:100%;width:' + pct +
						'%;border-radius:4px;transition:width 0.5s ease'
				})
			])
		]));
	}

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, 'Device Types (' + total + ' clients)'),
		E('div', { 'style': 'padding:8px' }, rows)
	]);
}

function renderAnomalySummary(anomalyData) {
	var total = anomalyData ? (anomalyData.total || 0) : 0;
	var anomalies = (anomalyData && anomalyData.anomalies) ? anomalyData.anomalies : [];

	if (total === 0)
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, 'Anomaly Status'),
			E('div', {
				'style': 'text-align:center;padding:20px;background:#e8f5e9;' +
					'border-radius:6px;border:1px solid #c8e6c9'
			}, [
				E('span', { 'style': 'font-size:24px;color:#2e7d32;font-weight:bold' },
					'All Clear'),
				E('div', { 'style': 'font-size:12px;color:#666;margin-top:4px' },
					'No anomalies detected')
			])
		]);

	var recent = anomalies.slice(0, 3);
	var items = [];
	for (var i = 0; i < recent.length; i++) {
		var a = recent[i];
		var sevColor = a.severity >= 70 ? '#e53935' : (a.severity >= 40 ? '#fb8c00' : '#43a047');
		items.push(E('div', {
			'style': 'padding:6px 10px;border-left:3px solid ' + sevColor +
				';margin-bottom:6px;background:#fafafa;border-radius:0 4px 4px 0;font-size:12px'
		}, [
			E('div', { 'style': 'display:flex;justify-content:space-between' }, [
				E('strong', {}, (a.type || '').replace(/_/g, ' ')),
				E('span', { 'style': 'font-family:monospace;color:#999' }, a.mac || '')
			]),
			E('div', { 'style': 'color:#666;margin-top:2px' }, a.detail || '')
		]));
	}

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, [
			'Anomalies ',
			E('span', {
				'style': 'display:inline-block;padding:1px 8px;border-radius:10px;' +
					'background:#e53935;color:#fff;font-size:12px;font-weight:bold;' +
					'vertical-align:middle'
			}, String(total))
		]),
		E('div', {}, items),
		total > 3 ? E('div', { 'style': 'text-align:right;font-size:12px;margin-top:4px' }, [
			E('a', { 'href': '#' }, 'View all →')
		]) : E('span')
	]);
}

function buildOverviewContent(status, stats, clients, anomalyData) {
	return [
		E('h2', {}, 'Traffic Classifier'),
		E('div', { 'style': 'display:flex;gap:16px;flex-wrap:wrap' }, [
			E('div', { 'style': 'flex:1;min-width:300px' }, [
				renderStatusCard(status)
			]),
			E('div', { 'style': 'flex:1;min-width:300px' }, [
				renderDonutChart(stats)
			])
		]),
		E('div', { 'style': 'display:flex;gap:16px;flex-wrap:wrap' }, [
			E('div', { 'style': 'flex:1;min-width:300px' }, [
				renderClassificationBars(stats)
			]),
			E('div', { 'style': 'flex:1;min-width:300px' }, [
				renderDeviceDistribution(clients)
			])
		]),
		renderAnomalySummary(anomalyData)
	];
}

return view.extend({
	load: function() {
		return Promise.all([
			callStatus(),
			callGetStats(),
			callGetClients(),
			callGetAnomalies()
		]);
	},

	render: function(data) {
		var status = data[0] || {};
		var stats = data[1] || {};
		var clients = data[2] || {};
		var anomalyData = data[3] || {};

		var view = E('div', {},
			buildOverviewContent(status, stats, clients, anomalyData));

		poll.add(L.bind(function() {
			return Promise.all([
				callStatus(), callGetStats(), callGetClients(), callGetAnomalies()
			]).then(L.bind(function(res) {
				var root = document.querySelector('[data-page="traffic-classifier-overview"]');
				if (!root) return;
				dom.content(root, buildOverviewContent(
					res[0] || {}, res[1] || {}, res[2] || {}, res[3] || {}));
			}, this));
		}, this), 5);

		return E('div', { 'data-page': 'traffic-classifier-overview' }, [view]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
