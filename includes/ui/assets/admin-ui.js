(function () {
    'use strict';

    var text = window.wpauditorAdminUi || {};

    function ready(callback) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', callback);
        } else {
            callback();
        }
    }

    function initMenuGroups() {
        try {
            var top = document.getElementById('toplevel_page_wpauditor-dashboard');
            if (!top) return;
            var submenu = top.querySelector('.wp-submenu ul, .wp-submenu-wrap');
            if (!submenu || submenu.querySelector('.wpa-group')) return;

            function take(slug) {
                var link = submenu.querySelector('li a[href*="page=' + slug + '"]');
                return link ? link.parentElement : null;
            }

            function openGroup(group, toggle, key, remember) {
                group.classList.add('open');
                toggle.setAttribute('aria-expanded', 'true');
                if (remember) sessionStorage.setItem(key, '1');
            }

            function closeGroup(group, toggle, key) {
                group.classList.remove('open');
                toggle.setAttribute('aria-expanded', 'false');
                sessionStorage.removeItem(key);
            }

            function closeAllGroups() {
                submenu.querySelectorAll('.wpa-group').forEach(function (group) {
                    var toggle = group.querySelector('.wpa-toggle');
                    group.classList.remove('open');
                    if (toggle) toggle.setAttribute('aria-expanded', 'false');
                });
                sessionStorage.removeItem('wpa_free_tools_open');
                sessionStorage.removeItem('wpa_free_hardening_open');
            }

            function makeHeaderGroup(label, slugs, storageKey) {
                var items = [];
                var firstItem = null;
                slugs.forEach(function (slug) {
                    var item = take(slug);
                    if (!item) return;
                    items.push(item);
                    if (!firstItem) firstItem = item;
                });
                if (!items.length) return;

                var group = document.createElement('li');
                group.className = 'wpa-group';
                var toggle = document.createElement('a');
                toggle.href = '#';
                toggle.className = 'wpa-toggle';
                toggle.setAttribute('role', 'button');
                toggle.setAttribute('aria-expanded', 'false');
                var labelElement = document.createElement('span');
                labelElement.textContent = label;
                var caret = document.createElement('span');
                caret.className = 'wpa-caret';
                caret.textContent = '▸';
                toggle.appendChild(labelElement);
                toggle.appendChild(caret);

                var inner = document.createElement('ul');
                inner.className = 'wpa-sublist';
                submenu.insertBefore(group, firstItem);
                group.appendChild(toggle);
                group.appendChild(inner);
                items.forEach(function (item) { inner.appendChild(item); });

                var hasCurrent = !!inner.querySelector('li.current');
                if (hasCurrent || sessionStorage.getItem(storageKey) === '1') {
                    openGroup(group, toggle, storageKey, false);
                }

                toggle.addEventListener('click', function (event) {
                    event.preventDefault();
                    var willOpen = !group.classList.contains('open');
                    closeAllGroups();
                    if (willOpen) openGroup(group, toggle, storageKey, true);
                    else closeGroup(group, toggle, storageKey);
                });
            }

            makeHeaderGroup(text.forensicTools || 'Forensic Tools', [
                'wpauditor-file-forensics',
                'wpauditor-core-integrity',
                'wpauditor-quarantine-manager'
            ], 'wpa_free_tools_open');
            makeHeaderGroup(text.hardening || 'Hardening', [
                'wpauditor-change-login',
                'wpauditor-api-access-control'
            ], 'wpa_free_hardening_open');

            if (!submenu.querySelector('.wpa-group .current')) {
                submenu.querySelectorAll('.wpa-group').forEach(function (group) {
                    var toggle = group.querySelector('.wpa-toggle');
                    group.classList.remove('open');
                    if (toggle) toggle.setAttribute('aria-expanded', 'false');
                });
            }
        } catch (error) {
            if (window.console && console.warn) console.warn('WPAuditor menu grouping skipped:', error);
        }
    }

    function initRetentionRange() {
        var input = document.getElementById('auto_clean_days');
        var output = document.getElementById('auto_clean_days_value');
        if (!input || !output) return;
        input.addEventListener('input', function () { output.textContent = input.value; });
    }

    function initDateRange() {
        var start = document.getElementById('wpaStartDate');
        var end = document.getElementById('wpaEndDate');
        if (!start || !end) return;
        function validate() {
            start.max = end.value;
            end.min = start.value;
            end.setCustomValidity(start.value && end.value && start.value > end.value
                ? (text.dateRangeError || 'The To date must be later than or equal to the From date.')
                : '');
        }
        start.addEventListener('input', validate);
        end.addEventListener('input', validate);
        validate();
    }

    function initSelectableTable(options) {
        var selectAll = document.getElementById(options.selectAllId);
        var checks = Array.prototype.slice.call(document.querySelectorAll(options.checkSelector));
        var actionButton = document.getElementById(options.actionButtonId);
        var countElement = document.getElementById(options.countId);
        if (!checks.length && !selectAll && !actionButton) return;

        function selected() { return checks.filter(function (check) { return check.checked; }); }
        function update() {
            var count = selected().length;
            if (countElement) countElement.textContent = count ? count + ' selected' : '';
            if (selectAll) {
                selectAll.checked = checks.length > 0 && count === checks.length;
                selectAll.indeterminate = count > 0 && count < checks.length;
            }
        }
        if (selectAll) {
            selectAll.addEventListener('change', function () {
                checks.forEach(function (check) { check.checked = selectAll.checked; });
                update();
            });
        }
        checks.forEach(function (check) { check.addEventListener('change', update); });
        if (actionButton) {
            actionButton.addEventListener('click', function (event) {
                if (selected().length) return;
                event.preventDefault();
                window.alert(options.emptyMessage);
            });
        }
        update();
    }

    function initCopyButtons() {
        document.querySelectorAll('.wpa-copy').forEach(function (element) {
            element.addEventListener('click', function () {
                var value = this.dataset.copy || this.textContent || '';
                if (!value || !navigator.clipboard) return;
                navigator.clipboard.writeText(value).then(function () {
                    var oldTitle = element.getAttribute('title') || '';
                    element.setAttribute('title', text.copied || 'Copied!');
                    element.style.opacity = '0.75';
                    window.setTimeout(function () {
                        element.setAttribute('title', oldTitle || text.copyTitle || 'Click to copy');
                        element.style.opacity = '1';
                    }, 900);
                }).catch(function () {});
            });
        });
    }

    function initQuarantineManager() {
        var actionInput = document.getElementById('wpauditor_operation');
        var restoreButton = document.getElementById('wpa-btn-restore');
        var deleteButton = document.getElementById('wpa-btn-delete');
        var search = document.getElementById('wpa-qsearch');
        var clear = document.getElementById('wpa-qsearch-clear');
        var checks = Array.prototype.slice.call(document.querySelectorAll('input.wpa-rowcheck'));
        var selectAll = document.getElementById('wpa-select-all');
        var count = document.getElementById('wpa-selected-count');
        if (!actionInput && !search) return;

        function selectedCount() { return checks.filter(function (check) { return check.checked; }).length; }
        function update() { if (count) count.textContent = selectedCount() ? selectedCount() + ' selected' : ''; }
        if (selectAll) selectAll.addEventListener('change', function () { checks.forEach(function (check) { check.checked = selectAll.checked; }); update(); });
        checks.forEach(function (check) { check.addEventListener('change', update); });
        [[restoreButton, 'restore'], [deleteButton, 'delete']].forEach(function (pair) {
            if (!pair[0]) return;
            pair[0].addEventListener('click', function (event) {
                if (!selectedCount()) { event.preventDefault(); window.alert(text.selectAtLeastOneItem || 'Select at least one item.'); return; }
                actionInput.value = pair[1];
            });
        });
        function filterRows() {
            var query = search ? (search.value || '').toLowerCase().trim() : '';
            document.querySelectorAll('#wpa-qtable tbody tr').forEach(function (row) {
                row.style.display = !query || row.textContent.toLowerCase().indexOf(query) !== -1 ? '' : 'none';
            });
        }
        if (search) search.addEventListener('input', filterRows);
        if (clear && search) clear.addEventListener('click', function () { search.value = ''; filterRows(); search.focus(); });
        update();
    }

    function initProgressiveScans() {
        document.querySelectorAll('.wpa-progressive-scan-config').forEach(function (config) {
            var form = document.getElementById(config.dataset.formId || '');
            var loader = document.getElementById(config.dataset.loaderId || '');
            if (!form || !loader || form.dataset.wpaProgressStarted === '1') return;
            form.dataset.wpaProgressStarted = '1';
            var progress = loader.querySelector('.wpauditor-spinner-progress');
            var spinner = loader.querySelector('.wpauditor-spinner');
            var timer = null;
            function setProgress(value) {
                value = Math.max(0, Math.min(100, parseInt(value, 10) || 0));
                if (progress) progress.textContent = value + '%';
                if (spinner) spinner.setAttribute('aria-valuenow', String(value));
            }
            function poll() {
                var url = new URL(config.dataset.ajaxUrl || '', window.location.href);
                url.searchParams.set('action', 'wpauditor_scan_progress');
                url.searchParams.set('progress_id', config.dataset.progressId || '');
                url.searchParams.set('nonce', config.dataset.nonce || '');
                fetch(url.toString(), { credentials: 'same-origin', cache: 'no-store' })
                    .then(function (response) { return response.ok ? response.json() : null; })
                    .then(function (payload) { if (payload && payload.success && payload.data) setProgress(payload.data.percent); })
                    .catch(function () {});
            }
            timer = window.setInterval(poll, 500);
            poll();
            fetch(form.action, { method: 'POST', body: new FormData(form), credentials: 'same-origin', redirect: 'follow' })
                .then(function (response) {
                    if (!response.ok) throw new Error('Scan request failed');
                    setProgress(100);
                    window.clearInterval(timer);
                    window.location.assign(response.url);
                }).catch(function () {
                    window.clearInterval(timer);
                    HTMLFormElement.prototype.submit.call(form);
                });
        });
    }

    function initCoreResult() {
        var loader = document.getElementById('wpauditor-core-integrity-loader');
        var result = document.getElementById('wpauditor-core-integrity-result');
        if (loader) loader.style.display = 'none';
        if (result) result.classList.remove('wpa-hidden');
    }

    function initConfirmationDialog() {
        var dialog = document.getElementById('wpaActionConfirmDialog');
        if (!dialog || dialog.dataset.initialized === '1') return;
        dialog.dataset.initialized = '1';
        var title = document.getElementById('wpaActionConfirmTitle');
        var description = document.getElementById('wpaActionConfirmDescription');
        var target = document.getElementById('wpaActionConfirmTarget');
        var targetLabel = document.getElementById('wpaActionConfirmTargetLabel');
        var targetValue = document.getElementById('wpaActionConfirmTargetValue');
        var note = document.getElementById('wpaActionConfirmNote');
        var icon = document.getElementById('wpaActionConfirmIcon');
        var closeButton = document.getElementById('wpaActionConfirmClose');
        var cancelButton = dialog.querySelector('.wpa-confirm-dialog-cancel');
        var confirmButton = dialog.querySelector('.wpa-confirm-dialog-confirm');
        var resolver = null;
        var lastFocus = null;

        function finish(result, restoreFocus) {
            dialog.hidden = true;
            document.body.classList.remove('wpa-confirm-dialog-open');
            var pending = resolver;
            resolver = null;
            if (restoreFocus && lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
            if (pending) pending(result);
        }
        function selectedTarget(form, trigger) {
            var source = trigger.dataset.wpaConfirmTargetSource || '';
            if (!form || !source) return { label: '', value: '' };
            if (source === 'selected') {
                var selected = Array.prototype.slice.call(form.querySelectorAll('input[type="checkbox"]:checked')).filter(function (field) { return !!field.name; });
                var unit = trigger.dataset.wpaConfirmTargetUnit || 'item';
                return { label: trigger.dataset.wpaConfirmTargetLabel || 'Selection', value: selected.length + ' selected ' + unit + (selected.length === 1 ? '' : 's') };
            }
            if (source === 'date-range') {
                var from = form.elements.namedItem('clean_from_date');
                var to = form.elements.namedItem('clean_to_date');
                return { label: trigger.dataset.wpaConfirmTargetLabel || 'Date range', value: (from && from.value ? from.value : 'Start') + ' to ' + (to && to.value ? to.value : 'Today') };
            }
            if (source === 'field') {
                var field = form.elements.namedItem(trigger.dataset.wpaConfirmTargetField || '');
                return { label: trigger.dataset.wpaConfirmTargetLabel || 'Target', value: field && field.value ? field.value : '' };
            }
            return { label: '', value: '' };
        }
        function optionsFromTrigger(trigger, form) {
            var dynamicTarget = selectedTarget(form, trigger);
            return {
                action: trigger.dataset.wpaConfirmAction || 'danger',
                title: trigger.dataset.wpaConfirmTitle || 'Continue with this action?',
                description: trigger.dataset.wpaConfirmDescription || 'Review this action before continuing.',
                note: trigger.dataset.wpaConfirmNote || 'This action takes effect immediately after confirmation.',
                confirmLabel: trigger.dataset.wpaConfirmLabel || 'Confirm',
                targetLabel: dynamicTarget.label || trigger.dataset.wpaConfirmTargetLabel || '',
                target: dynamicTarget.value || trigger.dataset.wpaConfirmTarget || ''
            };
        }
        window.wpauditorConfirm = function (options) {
            options = options || {};
            if (resolver) finish(false, false);
            var ipStyle = options.style === 'ip';
            dialog.classList.toggle('wpa-confirm-dialog-simple', !ipStyle);
            dialog.classList.toggle('wpa-confirm-dialog-ip', ipStyle);
            if (icon) icon.hidden = !ipStyle;
            if (closeButton) closeButton.hidden = !ipStyle;
            dialog.dataset.action = options.action || 'danger';
            title.textContent = options.title || 'Continue with this action?';
            description.textContent = options.description || 'Review this action before continuing.';
            note.textContent = options.note || 'This action takes effect immediately after confirmation.';
            confirmButton.textContent = options.confirmLabel || 'Confirm';
            if (target) {
                if (targetLabel) targetLabel.textContent = options.targetLabel || '';
                if (targetValue) targetValue.textContent = options.target || '';
                target.hidden = !options.target;
            }
            lastFocus = document.activeElement;
            dialog.hidden = false;
            document.body.classList.add('wpa-confirm-dialog-open');
            window.requestAnimationFrame(function () { cancelButton.focus(); });
            return new Promise(function (resolve) { resolver = resolve; });
        };
        document.addEventListener('submit', function (event) {
            if (event.defaultPrevented) return;
            var form = event.target;
            var submitter = event.submitter || document.activeElement;
            if (!submitter || !submitter.classList || !submitter.classList.contains('wpa-confirm-submit')) return;
            if (form.dataset.wpaActionConfirmed === '1') { delete form.dataset.wpaActionConfirmed; return; }
            event.preventDefault();
            event.stopPropagation();
            window.wpauditorConfirm(optionsFromTrigger(submitter, form)).then(function (confirmed) {
                if (!confirmed) return;
                form.dataset.wpaActionConfirmed = '1';
                if (typeof form.requestSubmit === 'function') form.requestSubmit(submitter);
                else HTMLFormElement.prototype.submit.call(form);
            });
        });
        if (closeButton) closeButton.addEventListener('click', function () { finish(false, true); });
        cancelButton.addEventListener('click', function () { finish(false, true); });
        confirmButton.addEventListener('click', function () { finish(true, false); });
        dialog.addEventListener('click', function (event) { if (event.target === dialog) finish(false, true); });
        document.addEventListener('keydown', function (event) {
            if (dialog.hidden) return;
            if (event.key === 'Escape') { event.preventDefault(); finish(false, true); return; }
            if (event.key !== 'Tab') return;
            var focusable = Array.prototype.slice.call(dialog.querySelectorAll('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')).filter(function (element) { return !element.hidden; });
            if (!focusable.length) return;
            var first = focusable[0];
            var last = focusable[focusable.length - 1];
            if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
            else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
        });
    }

    ready(function () {
        initMenuGroups();
        initProgressiveScans();
    });
}());
