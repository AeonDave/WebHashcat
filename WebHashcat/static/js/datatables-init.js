function initPollingTable(selector, ajaxUrl, columnDefs, cacheHintSelector, cacheLabel) {
    var table = $(selector).DataTable({
        "processing": false,
        "serverSide": true,
        "searching": false,
        "paging": false,
        "ordering": false,
        "info": false,
        "pageLength": 100,
        "columnDefs": columnDefs || [],
        "ajax": {
            "url": ajaxUrl,
        },
    });

    table.on('xhr.dt', function (e, settings, json) {
        if (cacheHintSelector) {
            updateCacheHint(cacheHintSelector, json && json.cache ? json.cache : null, cacheLabel);
        }
    });

    function autoRefresh() {
        table.ajax.reload(null, false);
    }
    setInterval(autoRefresh, 30000);
    return table;
}
