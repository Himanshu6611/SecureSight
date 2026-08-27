/* PhishGuard — app.js */

(function () {
    'use strict';

    /* ── Tab Switcher ─────────────────────────────────────── */
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.target;

            tabBtns.forEach(b => b.classList.remove('active'));
            tabPanels.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            const panel = document.getElementById(target);
            if (panel) panel.classList.add('active');
        });
    });

    /* ── Loading State on Form Submit ─────────────────────── */
    function attachLoadingState(formId, btnId) {
        const form = document.getElementById(formId);
        const btn = document.getElementById(btnId);
        if (!form || !btn) return;

        form.addEventListener('submit', () => {
            const text = btn.querySelector('.btn-text');
            const spinner = btn.querySelector('.btn-spinner');
            if (text) text.classList.add('d-none');
            if (spinner) spinner.classList.remove('d-none');
            btn.disabled = true;
        });
    }

    attachLoadingState('url-form', 'url-submit-btn');
    attachLoadingState('email-form', 'email-submit-btn');
    attachLoadingState('image-form', 'image-submit-btn');

    /* ── Image Dropzone ───────────────────────────────────── */
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('image-file-input');
    const dropzoneContent = document.getElementById('dropzone-content');
    const dropzonePreview = document.getElementById('dropzone-preview');
    const previewImg = document.getElementById('preview-img');
    const previewName = document.getElementById('preview-name');
    const previewRemove = document.getElementById('preview-remove');

    if (dropzone && fileInput) {
        // Drag events
        dropzone.addEventListener('dragover', e => {
            e.preventDefault();
            dropzone.classList.add('drag-over');
        });

        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('drag-over');
        });

        dropzone.addEventListener('drop', e => {
            e.preventDefault();
            dropzone.classList.remove('drag-over');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                showPreview(files[0]);
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                showPreview(fileInput.files[0]);
            }
        });

        if (previewRemove) {
            previewRemove.addEventListener('click', e => {
                e.stopPropagation();
                fileInput.value = '';
                dropzoneContent.classList.remove('d-none');
                dropzonePreview.classList.add('d-none');
                previewImg.src = '';
                previewName.textContent = '';
            });
        }
    }

    function showPreview(file) {
        if (!file.type.startsWith('image/')) return;
        const reader = new FileReader();
        reader.onload = e => {
            previewImg.src = e.target.result;
            previewName.textContent = file.name;
            dropzoneContent.classList.add('d-none');
            dropzonePreview.classList.remove('d-none');
        };
        reader.readAsDataURL(file);
    }

    /* ── Animate metric bars on load ─────────────────────── */
    function animateBars() {
        const fills = document.querySelectorAll('.metric-bar-fill, .breakdown-bar-fill');
        fills.forEach(el => {
            const target = el.style.width;
            el.style.width = '0%';
            requestAnimationFrame(() => {
                setTimeout(() => { el.style.width = target; }, 80);
            });
        });
    }

    animateBars();

    /* ── Scroll result into view ──────────────────────────── */
    const resultSection = document.getElementById('result-section');
    if (resultSection) {
        setTimeout(() => {
            resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 150);
    }

    /* ── Breakdown chevron sync ───────────────────────────── */
    const breakdownBody = document.getElementById('breakdown-body');
    const breakdownToggle = document.querySelector('.breakdown-toggle');
    if (breakdownBody && breakdownToggle) {
        breakdownBody.addEventListener('show.bs.collapse', () => {
            breakdownToggle.setAttribute('aria-expanded', 'true');
        });
        breakdownBody.addEventListener('hide.bs.collapse', () => {
            breakdownToggle.setAttribute('aria-expanded', 'false');
        });
    }

})();
