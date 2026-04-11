'use strict';
'require view';
'require form';
'require rpc';
'require uci';
'require dom';

var callCaptureStatus = rpc.declare({
	object: 'traffic-classifier',
	method: 'capture_status',
	expect: {}
});

var callCaptureStart = rpc.declare({
	object: 'traffic-classifier',
	method: 'capture_start',
	expect: {}
});

var callCaptureStop = rpc.declare({
	object: 'traffic-classifier',
	method: 'capture_stop',
	expect: {}
});

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('traffic-classifier'),
			callCaptureStatus()
		]);
	},

	render: function(data) {
		var captureStatus = data[1] || {};

		var m, s, o;

		m = new form.Map('traffic-classifier',
			'Traffic Classifier Settings',
			'Configure the AI-powered traffic classification daemon. ' +
			'Changes take effect after saving and applying (the daemon will restart).');

		/* General section */
		s = m.section(form.TypedSection, 'daemon', 'General');
		s.anonymous = true;

		o = s.option(form.Value, 'interface', 'Capture Interface',
			'Network interface to capture packets from.');
		o.placeholder = 'br-lan';
		o.rmempty = false;

		o = s.option(form.Value, 'max_flows', 'Max Concurrent Flows',
			'Maximum number of flows tracked simultaneously.');
		o.placeholder = '8192';
		o.datatype = 'uinteger';

		o = s.option(form.Value, 'model', 'ML Model Path',
			'Path to the XGBoost model file. Leave default unless you have a custom model.');
		o.placeholder = '/etc/traffic-classifier/model.json';

		/* QoS section */
		s = m.section(form.TypedSection, 'daemon', 'QoS (Quality of Service)');
		s.anonymous = true;

		o = s.option(form.Flag, 'qos_enabled', 'Enable QoS',
			'Automatically mark packets with DSCP values based on their traffic class ' +
			'using nftables. This enables router-level traffic prioritization.');
		o.default = '0';

		/* Telemetry section */
		s = m.section(form.TypedSection, 'daemon', 'Telemetry');
		s.anonymous = true;

		o = s.option(form.Flag, 'telemetry_enabled', 'Enable Telemetry',
			'Export classification data periodically as JSON for uCentral or external dashboards.');
		o.default = '0';

		o = s.option(form.Value, 'telemetry_interval', 'Export Interval (seconds)',
			'How often to export telemetry snapshots.');
		o.placeholder = '60';
		o.datatype = 'uinteger';
		o.depends('telemetry_enabled', '1');

		o = s.option(form.Value, 'telemetry_path', 'Telemetry File Path',
			'Local file path for JSON telemetry output.');
		o.placeholder = '/tmp/traffic-classifier-telemetry.json';
		o.depends('telemetry_enabled', '1');

		/* Data Capture section */
		s = m.section(form.TypedSection, 'daemon', 'ML Data Capture');
		s.anonymous = true;

		o = s.option(form.Flag, 'data_capture_enabled', 'Enable Data Capture',
			'Record labeled flow features to CSV for ML model retraining. ' +
			'The file can be transferred off the router and fed into the training pipeline.');
		o.default = '0';

		o = s.option(form.Value, 'data_capture_path', 'Capture File Path',
			'CSV output file for training data.');
		o.placeholder = '/tmp/tc-training-data.csv';
		o.depends('data_capture_enabled', '1');

		/* Data capture live controls */
		var captureSection = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, 'Live Data Capture Controls')
		]);

		if (captureStatus.available) {
			var statusColor = captureStatus.active ? '#43a047' : '#fb8c00';
			var statusText = captureStatus.active ? 'RECORDING' : 'PAUSED';
			var pct = captureStatus.max_rows > 0 ?
				(captureStatus.rows / captureStatus.max_rows * 100).toFixed(1) : 0;

			captureSection.appendChild(E('div', {
				'style': 'padding:12px;background:#f5f5f5;border-radius:6px;margin-bottom:12px'
			}, [
				E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;margin-bottom:8px' }, [
					E('div', {}, [
						E('span', {
							'style': 'display:inline-block;width:10px;height:10px;border-radius:50%;' +
								'background:' + statusColor + ';margin-right:8px'
						}),
						E('strong', {}, 'Status: '),
						E('span', { 'style': 'color:' + statusColor + ';font-weight:bold' }, statusText)
					]),
					E('div', {}, [
						E('strong', {}, 'Rows: '),
						captureStatus.rows + ' / ' + captureStatus.max_rows +
						' (' + pct + '%)'
					])
				]),
				E('div', { 'style': 'background:#e0e0e0;border-radius:3px;height:8px;overflow:hidden;margin-bottom:8px' }, [
					E('div', {
						'style': 'background:#1e88e5;height:100%;width:' + pct + '%;border-radius:3px'
					})
				]),
				E('div', { 'style': 'font-size:12px;color:#666' },
					'File: ' + (captureStatus.path || '-'))
			]));

			var btnStyle = 'padding:6px 16px;border:none;border-radius:4px;' +
				'color:#fff;cursor:pointer;font-weight:bold;margin-right:8px';

			captureSection.appendChild(E('div', {
				'style': 'display:flex;gap:8px'
			}, [
				E('button', {
					'class': 'cbi-button cbi-button-apply',
					'style': btnStyle + ';background:#43a047',
					'click': function() {
						callCaptureStart().then(function() {
							window.location.reload();
						});
					}
				}, captureStatus.active ? 'Resume' : 'Start Capture'),
				E('button', {
					'class': 'cbi-button',
					'style': btnStyle + ';background:#fb8c00',
					'click': function() {
						callCaptureStop().then(function() {
							window.location.reload();
						});
					}
				}, 'Pause Capture')
			]));
		} else {
			captureSection.appendChild(E('div', {
				'style': 'padding:16px;background:#fff3e0;border:1px solid #ffe0b2;border-radius:6px'
			}, [
				E('strong', {}, 'Data capture not configured.'),
				E('div', { 'style': 'margin-top:4px;font-size:13px;color:#666' },
					'Enable "ML Data Capture" above and save to start recording training data.')
			]));
		}

		/* Retraining instructions */
		var instructions = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, 'How to Retrain the Model'),
			E('div', { 'style': 'background:#f5f5f5;padding:16px;border-radius:6px;font-size:13px' }, [
				E('p', {}, 'Once you have collected enough training data (1000+ rows), ' +
					'transfer the CSV file from the router and retrain:'),
				E('pre', {
					'style': 'background:#263238;color:#eeffff;padding:12px;border-radius:4px;' +
						'overflow-x:auto;font-size:12px'
				}, [
					'# Copy training data from router\n',
					'scp root@<router-ip>:/tmp/tc-training-data.csv training/real_data.csv\n\n',
					'# Retrain with real data (edit build_model.py DATA_PATH)\n',
					'cd training/\n',
					'python build_model.py --input real_data.csv\n\n',
					'# Copy updated model back to router\n',
					'scp src/tc_model_xgb.c root@<router-ip>:/tmp/\n',
					'# Rebuild package with new model'
				].join(''))
			])
		]);

		var mapRender = m.render();

		return mapRender.then(function(node) {
			node.appendChild(captureSection);
			node.appendChild(instructions);
			return node;
		});
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
