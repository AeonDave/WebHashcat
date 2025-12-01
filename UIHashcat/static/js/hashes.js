document.addEventListener('DOMContentLoaded', () => {
  const cfg = window.hashesConfig || {};

  const nodeTable = $('#node_table').DataTable({
    processing: false,
    serverSide: false,
    searching: false,
    paging: false,
    ordering: false,
    info: false,
    ajax: { url: cfg.nodeStatusUrl },
    columns: [
      { title: "Name", data: "name" },
      { title: "Hashcat version", data: "version" },
      { title: "Status", data: "status" },
    ]
  });
  nodeTable.on('xhr.dt', function (e, settings, json) {
    updateCacheHint('#node_cache_hint', json && json.cache ? json.cache : null, 'Node snapshot');
  });
  setInterval(() => nodeTable.ajax.reload(null, false), 30000);

  function parseId(rowId) {
    if (!rowId) return null;
    return rowId.startsWith("row_") ? parseInt(rowId.slice(4), 10) : parseInt(rowId, 10);
  }

  const hashfileTable = $('#hashfile_table').DataTable({
    processing: false,
    serverSide: true,
    ajax: { url: cfg.hashfilesUrl },
    columns: [
      { title: "", data: null, defaultContent: '', className: 'details-control', orderable: false, width: "20px",
        render: () => '<span class="text-primary cursor-pointer">+</span>' },
      { title: "Name", data: "name" },
      { title: "Type", data: "type" },
      { title: "Lines", data: "line_count" },
      { title: "Cracked", data: "cracked" },
      { title: "Usernames", data: "username_included", orderable: false },
      { title: "Sessions", data: "sessions_count", orderable: false },
      { title: "", data: null, orderable: false, className: "text-right", render: (data, type, row) => {
          const hid = parseId(row.DT_RowId);
          const plainName = (row.name || '').replace(/<[^>]*>/g, '');
          // Prefer explicit null/undefined checks so that mode "0" (e.g. MD5) is preserved
          let hashTypeId = row.hash_type_id;
          if (hashTypeId === undefined || hashTypeId === null || hashTypeId === '') {
            hashTypeId = row.hash_type_value;
          }
          if (hashTypeId === undefined || hashTypeId === null || hashTypeId === '') {
            hashTypeId = row.hash_type;
          }
          if (hashTypeId === undefined || hashTypeId === null) {
            hashTypeId = '';
          }
          return `
            <div class="flex gap-2 justify-end">
              <a href="/file/cracked/${hid}"><button class="px-2 py-1 text-xs rounded bg-emerald-900/40 border border-emerald-700 text-emerald-200">Cracked</button></a>
              <a href="/file/uncracked/${hid}"><button class="px-2 py-1 text-xs rounded bg-amber-900/40 border border-amber-700 text-amber-200">Uncracked</button></a>
              <button class="px-2 py-1 text-xs rounded bg-primary/20 border border-primary/40 text-primary" data-modal-target="action_new" data-modal-toggle="action_new" data-hashfile="${plainName}" data-hashfile_id="${hid}" data-hash_type="${hashTypeId}">New session</button>
              <button class="px-2 py-1 text-xs rounded bg-red-900/40 border border-red-700 text-red-200" onClick="hashfile_action(${hid}, 'remove')">Remove</button>
            </div>`;
        } },
    ],
    order: [[1, 'asc']]
  });
  hashfileTable.on('xhr.dt', function (e, settings, json) {
    updateCacheHint('#hashfile_cache_hint', json && json.cache ? json.cache : null, 'Session cache');
  });
  hashfileTable.on('draw.dt', refreshPendingButtons);

  const messageBox = $('#messages');
  function pushMessage(type, content) {
    if (!content) return;
    const cls = type === 'error'
      ? 'border-red-700 bg-red-900/40 text-red-200'
      : 'border-emerald-700 bg-emerald-900/40 text-emerald-100';
    const el = $(`<div class="mb-2 px-3 py-2 rounded border ${cls}">${content}</div>`);
    messageBox.append(el).show();
    setTimeout(() => {
      el.fadeOut(300, () => {
        el.remove();
        if (!messageBox.children().length) messageBox.hide();
      });
    }, 6000);
  }

  const PENDING_TIMEOUT_MS = 60000;
  const pendingSessions = {};
  const pendingClusters = {};
  let actionInFlight = false;
  function setActionButtonsDisabled(disabled) {
    const selectors = [
      'button[onclick*="session_action"]',
      'button[onclick*="cluster_action"]',
    ];
    selectors.forEach(sel => {
      const $buttons = $(sel);
      $buttons.prop('disabled', disabled);
      $buttons.toggleClass('opacity-50 cursor-not-allowed', disabled);
    });
  }
  function refreshPendingButtons() {
    const now = Date.now();
    const prune = (store) => {
      Object.keys(store).forEach(key => {
        if (now - store[key] > PENDING_TIMEOUT_MS) delete store[key];
      });
    };
    prune(pendingSessions);
    prune(pendingClusters);

    Object.keys(pendingSessions).forEach(name => {
      $(`button[data-session="${name}"]`).prop('disabled', true).addClass('opacity-50 cursor-not-allowed');
    });
    Object.keys(pendingClusters).forEach(id => {
      $(`button[data-cluster="${id}"]`).prop('disabled', true).addClass('opacity-50 cursor-not-allowed');
    });

    // Auto-release pending flags if the UI shows sessions/clusters no longer in "Not started".
    $('button[data-session]').each(function () {
      const sess = $(this).data('session');
      if (!sess) return;
      const statusText = $(this).closest('tr').find('td').eq(4).text().trim().toLowerCase(); // assumes status column index 4
      if (statusText && statusText !== "not started") {
        delete pendingSessions[sess];
        $(this).prop('disabled', false).removeClass('opacity-50 cursor-not-allowed');
      }
    });
    $('button[data-cluster]').each(function () {
      const clus = $(this).data('cluster');
      if (!clus) return;
      const row = $(this).closest('tr');
      const statusText = row.find('td').eq(4).text().trim().toLowerCase();
      if (statusText && statusText !== "not started") {
        delete pendingClusters[clus];
        $(this).prop('disabled', false).removeClass('opacity-50 cursor-not-allowed');
      }
    });
  }

  function renderProgress(value) {
    const pct = parseFloat(value) || 0;
    return `
      <div class="w-full">
        <div class="flex justify-between text-xs text-gray-400">
          <span>${pct.toFixed(1)}%</span>
        </div>
        <div class="w-full h-2 bg-gray-800 rounded-full mt-1">
          <div class="h-2 rounded-full bg-primary" style="width:${pct}%"></div>
        </div>
      </div>`;
  }

  function sub_DataTable(vtask_id, table_id) {
    return $('table#' + table_id).DataTable({
      processing: false,
      serverSide: true,
      searching: false,
      paging: false,
      ordering: false,
      info: false,
      ajax: {
        url: cfg.hashfileSessionsUrl,
        data: function (d) { d.hashfile_id = vtask_id; },
      },
      columns: [
        { title: "Node", data: "node" },
        { title: "Type", data: "type" },
        { title: "Rule/Mask", data: "rule_mask" },
        { title: "Wordlist", data: "wordlist" },
        { title: "Status", data: "status" },
        { title: "Remaining time", data: "remaining" },
        { title: "Progress", data: "progress", render: renderProgress },
        { title: "Speed", data: "speed" },
        { title: "", data: "buttons", orderable: false },
      ],
    })
      .on('xhr.dt', function (e, settings, json) {
        updateCacheHint('#hashfile_cache_hint', json && json.cache ? json.cache : null, 'Session cache');
      })
      .on('draw.dt', refreshPendingButtons);
  }

  function format(table_id) {
    return `<table id="${table_id}" class="display nowrap w-full text-sm"></table>`;
  }

  const opened = [];
  $('#hashfile_table tbody').on('click', 'td.details-control', function () {
    const tr = $(this).closest('tr');
    const row = hashfileTable.row(tr);
    const vtask_id = row.data()["DT_RowId"];
    if (row.child.isShown()) {
      row.child.hide();
      tr.removeClass('shown');
      const idx = opened.indexOf(vtask_id);
      if (idx > -1) opened.splice(idx, 1);
    } else {
      const subtable_id = "subtable-" + vtask_id;
      row.child(format(subtable_id)).show();
      tr.addClass('shown');
      opened.push(vtask_id);
      sub_DataTable(vtask_id, subtable_id);
    }
    refreshPendingButtons();
  });

  function reload_hashfile_table() {
    hashfileTable.ajax.reload(function () {
      opened.forEach(function (vtask_id) {
        const row = hashfileTable.row("#" + vtask_id);
        const subtable_id = "subtable-" + vtask_id;
        row.child(format(subtable_id)).show();
        sub_DataTable(vtask_id, subtable_id);
      });
      refreshPendingButtons();
    });
  }

  $('#update_hashfiles').on('click', function () {
    reload_hashfile_table();
  });
  // Auto-refresh hashfiles and subtables to keep status current
  setInterval(reload_hashfile_table, 5000);

  function session_action(session_name, action) {
    if (actionInFlight) return;
    if (action === "remove" && !window.confirm("Are you sure?")) return;
    actionInFlight = true;
    setActionButtonsDisabled(true);
    pendingSessions[session_name] = Date.now();
    $.ajax({
      url: cfg.sessionActionUrl,
      type: 'GET',
      data: { session_name: session_name, action: action },
      dataType: 'json',
      success: function (res) {
        if (res && res.response === "error") {
          pushMessage('error', res.message || 'Node rejected command');
        } else {
          pushMessage('info', `Command "${action}" sent for ${session_name}`);
        }
        reload_hashfile_table();
      },
      error: function (xhr) {
        pushMessage('error', xhr.responseText || `Command "${action}" failed for ${session_name}`);
      },
      complete: function () {
        actionInFlight = false;
        setActionButtonsDisabled(false);
        refreshPendingButtons();
      }
    });
  }
  function cluster_action(cluster_id, action) {
    if (actionInFlight) return;
    if (action === "remove" && !window.confirm("Are you sure you want to remove all sessions in this cluster?")) return;
    actionInFlight = true;
    setActionButtonsDisabled(true);
    pendingClusters[cluster_id] = Date.now();
    $.ajax({
      url: cfg.clusterActionUrl,
      type: 'GET',
      data: { cluster: cluster_id, action: action },
      dataType: 'json',
      success: function (res) {
        if (res && res.response === "partial_error") {
          pushMessage('error', res.message || 'Some nodes did not accept the command');
        } else {
          pushMessage('info', `Command "${action}" sent to cluster ${cluster_id}`);
        }
        reload_hashfile_table();
      },
      error: function (xhr) {
        pushMessage('error', xhr.responseText || `Command "${action}" failed for cluster ${cluster_id}`);
      },
      complete: function () {
        actionInFlight = false;
        setActionButtonsDisabled(false);
        refreshPendingButtons();
      }
    });
  }
  function hashfile_action(hashfile_id, action) {
    if (action === "remove" && !window.confirm("Are you sure?")) return;
    $.ajax({
      url: cfg.hashfileActionUrl,
      type: 'GET',
      data: { hashfile_id: hashfile_id, action: action },
      success: function () { reload_hashfile_table(); }
    });
  }
  window.session_action = session_action;
  window.cluster_action = cluster_action;
  window.hashfile_action = hashfile_action;

  function update_messages() {
    $.getJSON(cfg.messagesUrl, function (data) {
      const box = $('#messages');
      box.empty();
      if (data.messages && data.messages.length) {
        box.show();
        $.each(data.messages, function (key, msg) {
          box.append(`<div class="mb-2 px-3 py-2 rounded border ${msg.type === 'error' ? 'border-red-700 bg-red-900/40 text-red-200' : 'border-emerald-700 bg-emerald-900/40 text-emerald-100'}">${msg.content}</div>`);
        });
      } else {
        box.hide();
      }
    });
  }
  update_messages();
  setInterval(update_messages, 15000);

  $('#action_new').on('show.flowbite.modal', function (event) {
    const button = event.relatedTarget;
    const hashfile_name = button?.getAttribute('data-hashfile') || '';
    const hashfile_id = button?.getAttribute('data-hashfile_id') || '';
    $('#session_modal_title').text(`${hashfile_name}: New session`);
    $('#hashfile_id_dict').val(hashfile_id);
    $('#hashfile_id_mask').val(hashfile_id);
  });
  function openSessionModal(btn) {
    const hashfile_name = $(btn).data('hashfile') || '';
    const hashfile_id = $(btn).data('hashfile_id') || '';
    const hash_type_id = $(btn).data('hash_type');
    $('#session_modal_title').text(`${hashfile_name}: New session`);
    $('#hashfile_id_dict').val(hashfile_id);
    $('#hashfile_id_mask').val(hashfile_id);
    // Accetta anche mode 0 (MD5), quindi non usare un semplice controllo di truthiness
    if (hash_type_id !== undefined && hash_type_id !== null && hash_type_id !== '') {
      const sel = document.getElementById('hash_type_dict');
      const filterInput = document.getElementById('hash_type_dict_filter');
      if (sel) {
        sel.value = String(hash_type_id);
        if (filterInput) {
          const opt = sel.selectedOptions[0];
          filterInput.value = opt ? opt.text : '';
        }
      }
    }
    showModal('action_new');
  }

  $('#hashfile_table tbody').on('click', 'button[data-modal-target="action_new"]', function () {
    openSessionModal(this);
  });

  // Also wire the "Add" hashfile modal when Flowbite autoload is not active.
  document.querySelectorAll('button[data-modal-target="action_add"]').forEach(btn => {
    btn.addEventListener('click', () => showModal('action_add'));
  });
  // Filtered dropdown for "New hashfile" hash type selection (single combined control)
  function initFilterDropdown(selectId, inputId, listId, showSelected = false) {
    const selectEl = document.getElementById(selectId);
    const inputEl = document.getElementById(inputId);
    const listEl = document.getElementById(listId);
    if (!selectEl || !inputEl || !listEl) return;

    const options = Array.from(selectEl.options);
    selectEl.classList.add('hidden'); // keep for form submission

    const render = (query = '') => {
      const q = query.toLowerCase();
      listEl.innerHTML = '';
      options.forEach(opt => {
        const text = opt.text.toLowerCase();
        const val = String(opt.value || '').toLowerCase();
        if (q && !(text.includes(q) || val.includes(q))) return;
        const item = document.createElement('div');
        item.className = 'px-3 py-2 hover:bg-primary/20 cursor-pointer text-sm';
        item.dataset.value = opt.value;
        item.textContent = opt.text;
        item.addEventListener('click', () => {
          selectEl.value = opt.value;
          inputEl.value = opt.text;
          listEl.classList.add('hidden');
        });
        listEl.appendChild(item);
      });
      if (!listEl.childElementCount) {
        const empty = document.createElement('div');
        empty.className = 'px-3 py-2 text-xs text-gray-400';
        empty.textContent = 'No matches';
        listEl.appendChild(empty);
      }
    };

    inputEl.addEventListener('focus', () => {
      render(inputEl.value);
      listEl.classList.remove('hidden');
    });
    inputEl.addEventListener('input', () => {
      render(inputEl.value);
      listEl.classList.remove('hidden');
    });
    document.addEventListener('click', (evt) => {
      const container = inputEl.parentElement;
      if (!container.contains(evt.target)) {
        listEl.classList.add('hidden');
      }
    });

    // Optionally show the current selection as text
    if (showSelected && selectEl.selectedOptions.length) {
      inputEl.value = selectEl.selectedOptions[0].text;
    }
  }
  initFilterDropdown('hash_type', 'hash_type_filter', 'hash_type_dropdown', false);
  initFilterDropdown('hash_type_dict', 'hash_type_dict_filter', 'hash_type_dict_dropdown', true);
  // Tabs fallback (Flowbite sometimes needs explicit init in pure JS usage)
  function activateTab(targetId) {
    ['dict_tab', 'mask_tab'].forEach(id => {
      const panel = document.getElementById(id);
      if (!panel) return;
      if (id === targetId) {
        panel.classList.remove('hidden');
      } else {
        panel.classList.add('hidden');
      }
    });
    document.getElementById('tab-dict')?.classList.toggle('border-primary', targetId === 'dict_tab');
    document.getElementById('tab-mask')?.classList.toggle('border-primary', targetId === 'mask_tab');
  }
  document.getElementById('tab-dict')?.addEventListener('click', () => activateTab('dict_tab'));
  document.getElementById('tab-mask')?.addEventListener('click', () => activateTab('mask_tab'));
  activateTab('dict_tab');

  flatpickr("#end_dict", { enableTime: true });
  flatpickr("#end_mask", { enableTime: true });
});
