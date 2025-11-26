document.addEventListener('DOMContentLoaded', () => {
  const cfg = window.hashfileConfig || {};

  $('#hashfile_table').DataTable({
    processing: true,
    serverSide: true,
    pageLength: 25,
    ajax: { url: cfg.crackedUrl },
    columns: [
      { title: cfg.firstColumnTitle || "Hash", data: "hash" },
      { title: "Password", data: "password" },
    ],
    order: [[0, 'asc']]
  });

  const top_password_chart = new Highcharts.chart('top_password_graph', {
    chart: { type: 'bar', marginLeft: 120, backgroundColor: 'transparent' },
    title: { text: '' },
    xAxis: { categories: [], title: { text: null }, labels: { style: { color: '#e5e7eb' } } },
    yAxis: { min: 0, title: { text: null, align: 'high' }, labels: { overflow: 'justify', style: { color: '#e5e7eb' } } },
    tooltip: { valueSuffix: ' hit' },
    plotOptions: { bar: { dataLabels: { enabled: false } } },
    credits: { enabled: false },
    series: [{ name: 'Hits', data: [], color: '#22d3ee' }]
  });

  const pass_len_chart = new Highcharts.chart('pass_len_graph', {
    chart: { type: 'column', backgroundColor: 'transparent' },
    title: { text: '' },
    xAxis: { categories: [], crosshair: true, labels: { style: { color: '#e5e7eb' } } },
    yAxis: { min: 0, title: { text: null }, labels: { style: { color: '#e5e7eb' } } },
    tooltip: { headerFormat: '<span style="font-size:10px">{point.key}</span><table>', pointFormat: '<tr><td style="color:{series.color};padding:0">{series.name}: </td>' + '<td style="padding:0"><b>{point.y}</b></td></tr>', footerFormat: '</table>', shared: true, useHTML: true },
    plotOptions: { column: { pointPadding: 0.2, borderWidth: 0 } },
    credits: { enabled: false },
    series: [{ name: 'Count', data: [], color: '#22d3ee' }]
  });

  const top_pass_charset_chart = new Highcharts.chart('top_pass_charset_graph', {
    chart: { type: 'bar', marginLeft: 120, backgroundColor: 'transparent' },
    title: { text: '' },
    xAxis: { categories: [], title: { text: null }, labels: { style: { color: '#e5e7eb' } } },
    yAxis: { min: 0, title: { text: null }, labels: { overflow: 'justify', style: { color: '#e5e7eb' } } },
    tooltip: { valueSuffix: ' hit' },
    plotOptions: { bar: { dataLabels: { enabled: false } } },
    credits: { enabled: false },
    series: [{ name: 'Hits', data: [], color: '#22d3ee' }]
  });

  function update_top_pass() {
    $.getJSON(cfg.topPasswordsUrl, function (data) {
      top_password_chart.xAxis[0].setCategories(data.categories);
      top_password_chart.series[0].setData(data.data);
    });
  }
  function update_pass_len() {
    $.getJSON(cfg.passwordLengthsUrl, function (data) {
      pass_len_chart.xAxis[0].setCategories(data.categories);
      pass_len_chart.series[0].setData(data.data);
    });
  }
  function update_pass_charset() {
    $.getJSON(cfg.passwordCharsetUrl, function (data) {
      top_pass_charset_chart.xAxis[0].setCategories(data.categories);
      top_pass_charset_chart.series[0].setData(data.data);
    });
  }

  update_top_pass();
  update_pass_len();
  update_pass_charset();
});
