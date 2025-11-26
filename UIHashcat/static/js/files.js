function initDropzone(formId, endpoint, csrfToken) {
  const form = document.getElementById(formId);
  if (!form) return;
  const input = form.querySelector('input[type="file"]');
  const statusEl = document.createElement('div');
  statusEl.className = 'absolute inset-0 flex items-center justify-center bg-[#0b1220]/70 text-xs text-primary hidden rounded-lg';
  form.appendChild(statusEl);

  form.addEventListener('submit', (e) => e.preventDefault());
  form.addEventListener('click', () => input.click());
  form.addEventListener('dragover', (e) => {
    e.preventDefault();
    form.classList.add('border-primary');
  });
  form.addEventListener('dragleave', () => form.classList.remove('border-primary'));
  form.addEventListener('drop', (e) => {
    e.preventDefault();
    form.classList.remove('border-primary');
    if (e.dataTransfer.files.length) {
      handleFiles(endpoint, e.dataTransfer.files, csrfToken);
    }
  });
  input.addEventListener('change', () => {
    if (input.files.length) handleFiles(endpoint, input.files, csrfToken);
  });

  function setStatus(message, loading) {
    statusEl.innerHTML = loading
      ? `<div class="flex items-center gap-2"><svg class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor"><circle class="opacity-25" cx="12" cy="12" r="10" stroke-width="4"></circle><path class="opacity-75" stroke-width="4" d="M4 12a8 8 0 018-8"></path></svg><span>${message}</span></div>`
      : `<span class="text-gray-200">${message}</span>`;
    statusEl.classList.toggle('hidden', !message);
    if (loading) {
      form.classList.add('opacity-70');
      form.classList.add('pointer-events-none');
    } else {
      form.classList.remove('opacity-70');
      form.classList.remove('pointer-events-none');
    }
  }

  async function handleFiles(endpoint, files, csrfToken) {
    setStatus(`Uploading ${files.length} file(s)...`, true);
    const formData = new FormData();
    for (const file of files) {
      formData.append('file', file, file.name);
    }
    try {
      await fetch(endpoint, {
        method: 'POST',
        headers: { 'X-CSRFToken': csrfToken },
        body: formData,
      });
    } finally {
      setStatus('Upload complete', false);
    }
    // Force a clean GET instead of reloading a potential POST page
    setTimeout(() => { window.location.href = window.location.pathname; }, 300);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const cfg = window.filesConfig || {};
  if (!cfg.csrf) return;
  Object.entries(cfg.dropzones || {}).forEach(([formId, endpoint]) => {
    initDropzone(formId, endpoint, cfg.csrf);
  });
});
