document.addEventListener('DOMContentLoaded', () => {
  const cfg = window.dashboardConfig || {};
  const pre = (window.dashboardConfig || {}).prefetch || {};

  // Highcharts may fail to load (e.g. offline or blocked CDN). Guard against that so
  // the rest of the dashboard (tables) still works even without the chart.
  const hasHighcharts = window.Highcharts && typeof Highcharts.chart === 'function';
  let cracked_chart = null;

  if (hasHighcharts) {
    // Highcharts.chart is a factory function, not a constructor: do NOT use "new" here.
    cracked_chart = Highcharts.chart('cracked_graph', {
      chart: {
        height: '60%',
        plotBackgroundColor: null,
        plotBorderWidth: 0,
        plotShadow: false,
        margin: [0, 0, 0, 0],
        spacingTop: 0, spacingBottom: 0, spacingLeft: 0, spacingRight: 0,
        backgroundColor: 'transparent',
      },
      title: { text: '' },
      tooltip: { pointFormat: '{series.name}: <b>{point.percentage:.1f}%</b>' },
      plotOptions: {
        pie: {
          size: '175%',
          dataLabels: {
            enabled: true,
            distance: -50,
            style: { fontWeight: 'bold', color: 'white' }
          },
          startAngle: -90, endAngle: 90, center: ['50%', '95%'],
          colors: ['#22d3ee', '#ef4444'],
        }
      },
      credits: { enabled: false },
      exporting: { enabled: false },
      series: [{ type: 'pie', name: 'Cracked', innerSize: '50%', showInLegend: false, data: [] }]
    });
    cracked_chart.showLoading();
  }

  function refresh_cracked_chart(initial) {
    if (!hasHighcharts || !cracked_chart) {
      return;
    }
    if (initial && pre.cracked && pre.cracked.length) {
      cracked_chart.series[0].setData(pre.cracked);
      cracked_chart.hideLoading();
      return;
    }
    $.getJSON(cfg.crackedRatioUrl, function (data) {
      cracked_chart.series[0].setData(data);
      cracked_chart.hideLoading();
    });
  }
  setInterval(refresh_cracked_chart, 30000);
  refresh_cracked_chart();

  $('#stat_table').DataTable({
    processing: true,
    serverSide: false,
    paging: false,
    info: false,
    searching: false,
    ordering: false,
    data: pre.stats && pre.stats.length ? pre.stats : undefined,
    ajax: pre.stats && pre.stats.length ? undefined : {
      url: cfg.statsUrl,
      dataSrc: function (json) { return json.data || []; }
    },
    columns: [
      { title: "", data: "label" },
      { title: "", data: "value" },
    ],
    createdRow: function (row, data) { $(row).addClass('border-b border-gray-800'); }
  });

  const nodeTable = $('#node_table').DataTable({
    processing: false,
    serverSide: false,
    searching: false,
    paging: false,
    ordering: false,
    info: false,
    // Use the API as the single source of truth for node status to avoid
    // duplicated rows when both prefetch and AJAX provide the same node.
    // Prefetched node data is no longer used here.
    data: undefined,
    ajax: { url: cfg.nodeStatusUrl, dataSrc: function (json) { return json.data || []; } },
    columns: [
      { title: "Name", data: "name" },
      { title: "Status", data: "status" },
    ]
  });
  nodeTable.on('xhr.dt', function (e, settings, json) {
    updateCacheHint('#dashboard_node_cache_hint', json && json.cache ? json.cache : null, 'Node snapshot');
  });
  setInterval(() => nodeTable.ajax.reload(null, false), 30000);

  const runningTable = $('#running_session_table').DataTable({
    processing: false,
    serverSide: true,
    data: pre.running && pre.running.length ? pre.running : undefined,
    ajax: { url: cfg.runningSessionsUrl },
    columns: [
      { title: "Hashfile", data: "hashfile" },
      { title: "Node", data: "node" },
      { title: "Type", data: "type" },
      { title: "Rule/Mask", data: "rule_mask" },
      { title: "Wordlist", data: "wordlist" },
      { title: "Remaining time", data: "remaining" },
      { title: "Progress", data: "progress" },
      { title: "Speed", data: "speed" },
    ]
  });
  runningTable.on('xhr.dt', function (e, settings, json) {
    updateCacheHint('#running_cache_hint', json && json.cache ? json.cache : null, 'Session cache');
  });

  const errorTable = $('#error_session_table').DataTable({
    processing: false,
    serverSide: true,
    data: pre.errors && pre.errors.length ? pre.errors : undefined,
    ajax: { url: cfg.errorSessionsUrl },
    columns: [
      { title: "Hashfile", data: "hashfile" },
      { title: "Node", data: "node" },
      { title: "Type", data: "type" },
      { title: "Rule/Mask", data: "rule_mask" },
      { title: "Wordlist", data: "wordlist" },
      { title: "Status", data: "status" },
      { title: "Reason", data: "reason" },
    ]
  });
  errorTable.on('xhr.dt', function (e, settings, json) {
    updateCacheHint('#error_cache_hint', json && json.cache ? json.cache : null, 'Session cache');
  });

  setInterval(() => {
    runningTable.ajax.reload(null, false);
    errorTable.ajax.reload(null, false);
  }, 30000);
});
