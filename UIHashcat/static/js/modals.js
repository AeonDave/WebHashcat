// Shared helpers for handling Flowbite modals with a graceful fallback.
//
// This centralizes the show/hide logic so that pages like hashes.js and
// search.js don't need to duplicate the same helper functions.

(function () {
  function showModal(modalId) {
    const modalEl = document.getElementById(modalId);
    if (!modalEl) return;

    // Flowbite 2.x may expose Modal directly or under window.Flowbite.Modal
    const FBModal = window.Modal || (window.Flowbite ? window.Flowbite.Modal : null);
    if (FBModal) {
      const instance = FBModal.getInstance ? FBModal.getInstance(modalEl) : null;
      (instance || new FBModal(modalEl)).show();
    } else {
      // Fallback: toggle Tailwind utility classes
      modalEl.classList.remove('hidden');
      modalEl.classList.add('flex');
    }
  }

  function hideModal(modalId) {
    const modalEl = document.getElementById(modalId);
    if (!modalEl) return;

    const FBModal = window.Modal || (window.Flowbite ? window.Flowbite.Modal : null);
    if (FBModal) {
      const instance = FBModal.getInstance ? FBModal.getInstance(modalEl) : null;
      (instance || new FBModal(modalEl)).hide();
    } else {
      modalEl.classList.add('hidden');
      modalEl.classList.remove('flex');
    }
  }

  // Fallback binding for all [data-modal-hide] buttons when Flowbite does not
  // auto-wire them (for example when using pure JS initialization only).
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-modal-hide]').forEach(btn => {
      const targetId = btn.getAttribute('data-modal-hide');
      if (!targetId) return;
      btn.addEventListener('click', () => hideModal(targetId));
    });
  });

  // Expose helpers globally so page scripts can call window.showModal/
  // window.hideModal without re-defining them.
  window.showModal = showModal;
  window.hideModal = hideModal;
})();
