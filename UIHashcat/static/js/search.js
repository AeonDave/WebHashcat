document.addEventListener('DOMContentLoaded', () => {
  const cfg = window.searchConfig || {};
  const searchTable = $('#search_table').DataTable({
    processing: true,
    serverSide: true,
    pageLength: 25,
    ajax: { url: cfg.listUrl },
    columns: [
      { title: "Name", data: "name" },
      { title: "Status", data: "status" },
      { title: "Lines", data: "lines" },
      { title: "Processing time", data: "processing_time" },
      { title: "Actions", data: "actions", orderable: false, defaultContent: "" },
    ],
    order: [[0, 'asc']]
  });

  function update_searches() {
    searchTable.ajax.reload();
  }
  document.getElementById("update_searches").addEventListener('click', update_searches);
  setInterval(update_searches, 60000);

  function search_action(search_id, action) {
    if (action === "remove" && !window.confirm("Are you sure?")) return;
    $.ajax({
      url: cfg.actionUrl,
      type: 'GET',
      data: { search_id: search_id, action: action },
      success: function (resp) {
        if (action === "view" && resp && resp.content !== undefined) {
          $('#search_view_body').text(resp.content || "(empty)");
          showModal('search_view_modal');
        } else {
          update_searches();
        }
      }
    });
  }
  window.search_action = search_action;

  $('#search_table').on('click', '[data-search-action]', function () {
    const action = $(this).data('search-action');
    const id = $(this).data('search-id');
    search_action(id, action);
  });
});
