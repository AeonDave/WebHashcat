function updateCacheHint(selector, cacheMeta, label) {
    var target = $(selector);
    if (!target.length) {
        return;
    }
    var prefix = label || 'Cache';
    if (!cacheMeta || cacheMeta.available === false) {
        target.text(prefix + ': cache unavailable');
        target.removeClass('text-success text-warning').addClass('text-danger');
        return;
    }
    var ageSeconds = cacheMeta.age_seconds === null ? '?' : Math.round(cacheMeta.age_seconds);
    var isStale = cacheMeta.is_stale === true;
    target.removeClass('text-success text-warning text-danger').addClass(isStale ? 'text-warning' : 'text-success');
    target.text(prefix + ': ' + (isStale ? 'stale' : 'fresh') + ' (' + ageSeconds + 's ago)');
}
