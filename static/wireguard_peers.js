(() => {
    const root = document;
    const deviceId = Number(root.querySelector('#wg-peer-create-form [name="device_id"]')?.value || 0);
    const interfaceName = root.querySelector('#wg-peer-create-form [name="interface"]')?.value || '';
    const initial = root.getElementById('wg-peer-initial');
    const tbody = root.getElementById('wg-peer-rows');
    const table = root.getElementById('wg-peer-table');
    if (!initial || !tbody || !table) return;

    let peers = JSON.parse(initial.textContent || '[]');
    const dnatEnabled = table.dataset.dnatEnabled === 'true';
    let page = 1;
    let sort = { field: 'name', direction: 1 };
    let exportData = null;
    let exportFormat = 'conf';
    let restoreFocus = null;
    const pageSize = 50;

    const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[char]);

    function format(text, ...values) {
        return values.reduce((result, value, index) =>
            result.replace(`%(p${index})s`, String(value)), text);
    }

    function bytes(value) {
        let amount = Number.parseInt(value, 10) || 0;
        const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
        let unit = 0;
        while (amount >= 1024 && unit < units.length - 1) {
            amount /= 1024;
            unit += 1;
        }
        return `${amount.toFixed(1)} ${units[unit]}`;
    }

    function showMessage(text, error = false) {
        const box = root.getElementById('wg-peer-message');
        box.textContent = text;
        box.classList.toggle('error', error);
        box.classList.toggle('ok', !error);
        box.hidden = !text;
    }

    function clearCopyFeedback() {
        const button = root.getElementById('wg-peer-copy-button');
        button.textContent = T('Скопировать');
        button.classList.remove('copied');
        const feedback = root.getElementById('wg-peer-copy-feedback');
        feedback.textContent = '';
        feedback.classList.remove('error');
    }

    function showCopyFeedback(text, error = false) {
        const button = root.getElementById('wg-peer-copy-button');
        const feedback = root.getElementById('wg-peer-copy-feedback');
        button.textContent = error ? T('Скопировать') : T('Скопировано ✓');
        button.classList.toggle('copied', !error);
        feedback.textContent = text;
        feedback.classList.toggle('error', error);
    }

    function sortValue(peer, field) {
        if (field === 'status') return peer.disabled ? 2 : peer.connected ? 0 : 1;
        if (field === 'dnat') return Number(peer.dnat_port) || 0;
        if (field === 'traffic') {
            return (Number.parseInt(peer.rx, 10) || 0) + (Number.parseInt(peer.tx, 10) || 0);
        }
        return String(peer[field] || '').toLocaleLowerCase();
    }

    function filteredPeers() {
        const needle = root.getElementById('wg-peer-search').value.trim().toLocaleLowerCase();
        return peers.filter((peer) => [peer.name, peer.ip, peer.endpoint]
            .some((value) => String(value || '').toLocaleLowerCase().includes(needle)))
            .sort((left, right) => {
                const a = sortValue(left, sort.field);
                const b = sortValue(right, sort.field);
                if (sort.field === 'endpoint' && Boolean(a) !== Boolean(b)) {
                    return a ? -1 : 1;
                }
                const comparison = typeof a === 'number' && typeof b === 'number'
                    ? a - b
                    : String(a).localeCompare(String(b), undefined, { numeric: true });
                return comparison * sort.direction;
            });
    }

    function render() {
        const found = filteredPeers();
        root.getElementById('wg-peer-count').textContent = peers.length;
        const pages = Math.max(1, Math.ceil(found.length / pageSize));
        page = Math.min(page, pages);
        const visible = found.slice((page - 1) * pageSize, page * pageSize);
        tbody.innerHTML = visible.map((peer) => {
            const disabled = peer.connection_status === 'disabled'
                ? `<span class="badge offline">${escapeHtml(T('Отключён'))}</span>`
                : '';
            const connection = peer.connection_status === 'connected'
                ? `<span class="badge online"><span class="led"></span>${escapeHtml(T('Подключён'))}</span>`
                : peer.connection_status === 'disconnected'
                    ? `<span class="badge unknown">${escapeHtml(T('Не подключён'))}</span>`
                    : '';
            const handshake = peer.connection_status === 'connected' && peer.handshake
                ? `<span class="wg-peer-handshake">${escapeHtml(peer.handshake)}</span>`
                : '';
            const dnatPort = Number.isInteger(peer.dnat_port) ? peer.dnat_port : null;
            const toggleLabel = format(
                peer.disabled ? T('Возобновить %(p0)s') : T('Приостановить %(p0)s'),
                peer.name,
            );
            const ipCell = peer.ip
                ? `<button class="badge wg-peer-copy-value wg-peer-ip-badge" type="button"
                    data-copy-value="${escapeHtml(peer.ip)}"
                    aria-label="${escapeHtml(T('Скопировать IP'))}: ${escapeHtml(peer.ip)}"
                    title="${escapeHtml(T('Нажмите, чтобы скопировать'))}">${escapeHtml(peer.ip)}</button>`
                : '—';
            const dnatCell = dnatEnabled
                ? `<td class="mono">${dnatPort === null ? '—' : `<button class="badge wg-peer-copy-value wg-peer-dnat-copy" type="button" data-copy-value="${dnatPort}" aria-label="${escapeHtml(T('Скопировать порт DNAT'))}: ${dnatPort}" title="${escapeHtml(T('Нажмите, чтобы скопировать'))}">${dnatPort}</button>`}</td>`
                : '';
            const managedDevices = Array.isArray(peer.managed_devices)
                ? peer.managed_devices.filter((device) => Number.isInteger(Number(device.id))
                    && Number(device.id) > 0)
                : [];
            const managedDevice = managedDevices[0] || null;
            const displayName = peer.name || T('Без имени');
            const nameCell = managedDevice
                ? `<a class="wg-peer-name-link" href="/devices/${Number(managedDevice.id)}"
                    aria-label="${escapeHtml(format(T('Открыть карточку %(p0)s'), peer.name || managedDevice.name))}"
                    title="${escapeHtml(T('Открыть карточку устройства'))}">${escapeHtml(displayName)}</a>`
                : peer.name
                    ? `<button class="wg-peer-copy-value wg-peer-name-copy" type="button"
                        data-copy-value="${escapeHtml(peer.name)}"
                        aria-label="${escapeHtml(T('Скопировать имя'))}: ${escapeHtml(peer.name)}"
                        title="${escapeHtml(T('Нажмите, чтобы скопировать'))}"><span class="wg-peer-name-copy-text">${escapeHtml(peer.name)}</span></button>`
                    : escapeHtml(T('Без имени'));
            const addLink = managedDevices.length
                ? ''
                : table.dataset.canAddDevice === 'true'
                    ? `<a class="btn sm wg-peer-add-device"
                        href="/devices?add_name=${encodeURIComponent(peer.name || '')}&amp;add_host=${encodeURIComponent(peer.ip || '')}"
                        aria-label="${escapeHtml(format(T('Добавить %(p0)s в парк'), peer.name || peer.ip || ''))}"
                        title="${escapeHtml(T('Добавить устройство в парк'))}">+</a>`
                    : `<span class="muted" title="${escapeHtml(T('Нет права добавлять устройства'))}">—</span>`;
            return `<tr data-peer-row="${escapeHtml(peer.id)}"${peer.disabled ? ' class="wg-peer-disabled"' : ''}>
                <td><div class="wg-peer-name-cell"><strong>${nameCell}</strong>${addLink}</div></td>
                <td class="mono">${ipCell}</td>
                ${dnatCell}
                <td><div class="wg-peer-state">${disabled}${connection}${handshake}</div></td>
                <td class="mono">${escapeHtml(peer.endpoint || '—')}</td>
                <td class="small nowrap">↓ ${bytes(peer.rx)} · ↑ ${bytes(peer.tx)}</td>
                <td><div class="wg-peer-actions">
                    <button class="btn sm" type="button" data-peer-action="rename"
                        data-peer-id="${escapeHtml(peer.id)}"
                        aria-label="${escapeHtml(format(T('Переименовать %(p0)s'), peer.name))}">${escapeHtml(T('Переименовать'))}</button>
                    <button class="btn sm" type="button" data-peer-action="toggle"
                        data-peer-id="${escapeHtml(peer.id)}"
                        data-disabled="${peer.disabled ? 'true' : 'false'}"
                        aria-label="${escapeHtml(toggleLabel)}">
                        ${escapeHtml(peer.disabled ? T('Возобновить') : T('Приостановить'))}</button>
                    <button class="btn sm" type="button" data-peer-action="regenerate"
                        data-peer-id="${escapeHtml(peer.id)}"
                        aria-label="${escapeHtml(format(T('Перевыпустить ключ и экспортировать для %(p0)s'), peer.name))}">
                        ${escapeHtml(T('Перевыпустить / экспорт'))}</button>
                    <button class="btn sm danger" type="button" data-peer-action="delete"
                        data-peer-id="${escapeHtml(peer.id)}"
                        aria-label="${escapeHtml(format(T('Удалить %(p0)s'), peer.name))}">${escapeHtml(T('Удалить'))}</button>
                </div></td>
            </tr>`;
        }).join('');

        const empty = root.getElementById('wg-peer-empty');
        empty.hidden = visible.length > 0;
        empty.textContent = peers.length === 0
            ? T('На этом интерфейсе нет пиров.')
            : T('По запросу ничего не найдено.');
        const pagination = root.getElementById('wg-peer-pagination');
        pagination.hidden = found.length <= pageSize;
        root.getElementById('wg-peer-page-label').textContent = format(
            T('Страница %(p0)s из %(p1)s · пиров: %(p2)s'), page, pages, found.length,
        );
        root.getElementById('wg-peer-prev').disabled = page <= 1;
        root.getElementById('wg-peer-next').disabled = page >= pages;
        root.querySelectorAll('[data-sort]').forEach((button) => {
            button.closest('th').setAttribute('aria-sort', button.dataset.sort === sort.field
                ? (sort.direction === 1 ? 'ascending' : 'descending')
                : 'none');
        });
    }

    async function post(path, payload) {
        const response = await fetch(path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ device_id: deviceId, interface: interfaceName, ...payload }),
        });
        const body = await response.json();
        if (!response.ok) {
            const message = body.error || format(T('Запрос не выполнен (код %(p0)s).'), response.status);
            throw new Error(T(message));
        }
        return body;
    }

    async function refresh(force = false) {
        if (!force && (root.querySelector('.modal-backdrop.open')
            || root.activeElement?.closest('#wg-peer-create-form, #wg-peer-rename-form'))) return false;
        try {
            const params = new URLSearchParams({ device_id: deviceId, interface: interfaceName });
            const response = await fetch(`/api/wg/peers?${params}`, { credentials: 'same-origin' });
            const body = await response.json();
            if (!response.ok) {
                const message = body.error || T('Не удалось обновить список пиров.');
                throw new Error(T(message));
            }
            peers = body.peers;
            render();
            return true;
        } catch (error) {
            showMessage(error.message, true);
            return false;
        }
    }

    function openModal(id, trigger) {
        restoreFocus = trigger || root.activeElement;
        const modal = root.getElementById(id);
        modal.classList.add('open');
        modal.setAttribute('aria-hidden', 'false');
        modal.querySelector('button, input, textarea')?.focus();
    }

    function closeModal(modal) {
        modal.classList.remove('open');
        modal.setAttribute('aria-hidden', 'true');
        if (modal.id === 'wg-peer-export-modal') {
            clearCopyFeedback();
            root.getElementById('wg-peer-export-text').value = '';
            root.getElementById('wg-peer-export-qr').replaceChildren();
            root.getElementById('wg-peer-export-qr').hidden = true;
            exportData = null;
        }
        restoreFocus?.focus?.();
    }

    function showExport(peer, trigger, warning) {
        clearCopyFeedback();
        exportData = peer;
        exportFormat = 'conf';
        root.getElementById('wg-peer-export-warning').textContent = warning;
        root.getElementById('wg-peer-export-qr').innerHTML = peer.qr || '';
        root.getElementById('wg-peer-export-qr').hidden = true;
        root.getElementById('wg-peer-export-text').hidden = false;
        renderExport();
        openModal('wg-peer-export-modal', trigger);
    }

    function renderExport() {
        if (!exportData) return;
        const text = root.getElementById('wg-peer-export-text');
        const qr = root.getElementById('wg-peer-export-qr');
        const isQr = exportFormat === 'qr';
        text.hidden = isQr;
        qr.hidden = !isQr;
        if (!isQr) text.value = exportData[exportFormat === 'conf' ? 'config' : 'script'] || '';
        root.querySelectorAll('[data-export-format]').forEach((button) => {
            button.classList.toggle('active', button.dataset.exportFormat === exportFormat);
        });
    }

    root.getElementById('wg-peer-create-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const button = form.querySelector('[type="submit"]');
        button.disabled = true;
        try {
            const body = await post('/api/wg/peers/create', { name: form.elements.name.value.trim() });
            form.reset();
            page = 1;
            root.getElementById('wg-peer-search').value = '';
            const refreshed = await refresh(true);
            showExport(body.peer, button,
                T('Эта конфигурация содержит приватный ключ. Скопируйте или скачайте её сейчас; TikPilot его не сохраняет.'));
            showMessage(refreshed
                ? T('Peer создан. Конфигурация доступна только в этом окне.')
                : T('Peer создан, но список не удалось обновить.'), !refreshed);
        } catch (error) {
            showMessage(error.message, true);
        } finally {
            button.disabled = false;
        }
    });

    async function saveSettings(form, statusId, settings) {
        const button = form.querySelector('[type="submit"]');
        const status = root.getElementById(statusId);
        button.disabled = true;
        status.textContent = '';
        try {
            await post('/api/wg/peers/settings', settings);
            status.textContent = T('Настройки WireGuard сохранены.');
            window.setTimeout(() => window.location.reload(), 500);
        } catch (error) {
            status.textContent = error.message;
            showMessage(error.message, true);
            button.disabled = false;
        }
    }

    root.getElementById('wg-peer-endpoint-form').addEventListener('submit', (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        saveSettings(form, 'wg-peer-endpoint-status', {
            public_endpoint: form.elements.public_endpoint.value.trim(),
        });
    });

    root.getElementById('wg-peer-dnat-form').addEventListener('submit', (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        saveSettings(form, 'wg-peer-dnat-status', {
            dnat_base: form.elements.dnat_base.value || null,
            dnat_multiplier: form.elements.dnat_multiplier.value || null,
        });
    });

    root.getElementById('wg-peer-rows').addEventListener('click', async (event) => {
        const copyValue = event.target.closest('[data-copy-value]');
        if (copyValue) {
            try {
                await copyText(copyValue.dataset.copyValue);
                showMessage(T('Скопировано'));
            } catch {
                showMessage(T('Копирование в буфер обмена не удалось.'), true);
            }
            return;
        }
        const button = event.target.closest('[data-peer-action]');
        if (!button) return;
        const peer = peers.find((row) => row.id === button.dataset.peerId);
        if (!peer) return;
        try {
            switch (button.dataset.peerAction) {
                case 'rename': {
                    const form = root.getElementById('wg-peer-rename-form');
                    form.elements.id.value = peer.id;
                    form.elements.name.value = peer.name;
                    openModal('wg-peer-rename-modal', button);
                    break;
                }
                case 'toggle': {
                    const disabled = button.dataset.disabled !== 'true';
                    const questionTemplate = disabled
                        ? T('Приостановить %(p0)s?')
                        : T('Возобновить %(p0)s?');
                    const question = format(questionTemplate, peer.name);
                    if (!window.confirm(question)) return;
                    await post('/api/wg/peers/toggle', { id: peer.id, disabled });
                    showMessage(disabled ? T('Peer приостановлен.') : T('Peer возобновлён.'));
                    await refresh();
                    break;
                }
                case 'delete':
                    if (!window.confirm(format(T('Удалить peer %(p0)s без возможности восстановления?'), peer.name))) return;
                    await post('/api/wg/peers/delete', { id: peer.id });
                    showMessage(T('Peer удалён.'));
                    await refresh();
                    break;
                case 'regenerate': {
                    const question = format(
                        T('Заменить ключ peer %(p0)s? Текущий ключ клиента сразу перестанет работать.'),
                        peer.name,
                    );
                    if (!window.confirm(question)) return;
                    button.disabled = true;
                    const body = await post('/api/wg/peers/regenerate', { id: peer.id });
                    showExport(body.peer, button,
                        T('Ключ на роутере заменён. Сразу установите эту конфигурацию на клиент. TikPilot не сохраняет приватный ключ.'));
                    showMessage(T('Ключ обновлён. Предыдущая конфигурация больше не работает.'));
                    await refresh();
                    break;
                }
            }
        } catch (error) {
            showMessage(error.message, true);
        } finally {
            button.disabled = false;
        }
    });

    root.getElementById('wg-peer-rename-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        try {
            await post('/api/wg/peers/rename', {
                id: form.elements.id.value,
                name: form.elements.name.value.trim(),
            });
            closeModal(root.getElementById('wg-peer-rename-modal'));
            showMessage(T('Имя peer обновлено.'));
            await refresh();
        } catch (error) {
            showMessage(error.message, true);
        }
    });

    root.getElementById('wg-peer-search').addEventListener('input', () => {
        page = 1;
        render();
    });
    root.querySelectorAll('[data-sort]').forEach((button) => button.addEventListener('click', () => {
        const field = button.dataset.sort;
        sort = {
            field,
            direction: sort.field === field ? -sort.direction : (field === 'traffic' ? -1 : 1),
        };
        render();
    }));
    root.getElementById('wg-peer-prev').addEventListener('click', () => { page -= 1; render(); });
    root.getElementById('wg-peer-next').addEventListener('click', () => { page += 1; render(); });

    root.querySelectorAll('[data-peer-close]').forEach((button) => button.addEventListener('click', () => {
        closeModal(button.closest('.modal-backdrop'));
    }));
    root.querySelectorAll('.modal-backdrop').forEach((modal) => modal.addEventListener('click', (event) => {
        if (event.target === modal) closeModal(modal);
    }));
    root.addEventListener('keydown', (event) => {
        const modal = root.querySelector('.modal-backdrop.open');
        if (!modal) return;
        if (event.key === 'Escape') {
            closeModal(modal);
            return;
        }
        if (event.key === 'Tab') {
            const focusable = [...modal.querySelectorAll(
                'button:not([disabled]), input:not([disabled]), textarea:not([disabled])',
            )];
            if (!focusable.length) return;
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (event.shiftKey && root.activeElement === first) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && root.activeElement === last) {
                event.preventDefault();
                first.focus();
            }
        }
    });
    root.querySelectorAll('[data-export-format]').forEach((button) => button.addEventListener('click', () => {
        clearCopyFeedback();
        exportFormat = button.dataset.exportFormat;
        renderExport();
    }));
    async function copyText(text) {
        if (window.isSecureContext && typeof navigator.clipboard?.writeText === 'function') {
            try {
                await navigator.clipboard.writeText(text);
                return;
            } catch {
                // Fall back to a user-initiated copy for trusted local HTTP origins.
            }
        }

        const previousFocus = root.activeElement;
        const buffer = root.createElement('textarea');
        buffer.className = 'wg-peer-copy-buffer';
        buffer.value = text;
        buffer.readOnly = true;
        buffer.tabIndex = -1;
        buffer.setAttribute('aria-hidden', 'true');
        root.body.append(buffer);
        buffer.focus({ preventScroll: true });
        buffer.select();
        let copied = false;
        try {
            copied = root.execCommand('copy');
        } finally {
            buffer.remove();
            previousFocus?.focus?.();
        }
        if (!copied) throw new Error(T('Браузер не разрешил копирование.'));
    }

    root.querySelector('[data-export-copy]').addEventListener('click', async () => {
        if (exportFormat === 'qr') return;
        try {
            await copyText(root.getElementById('wg-peer-export-text').value);
            showCopyFeedback(T('Конфигурация скопирована в буфер обмена.'));
            showMessage(T('Конфигурация скопирована.'));
        } catch (error) {
            showCopyFeedback(error.message, true);
            showMessage(T('Не удалось получить доступ к буферу обмена.'), true);
        }
    });
    root.querySelector('[data-export-download]').addEventListener('click', () => {
        if (!exportData || exportFormat === 'qr') return;
        const extension = exportFormat === 'conf' ? 'conf' : 'rsc';
        const file = new Blob([root.getElementById('wg-peer-export-text').value],
            { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(file);
        const link = root.createElement('a');
        link.href = url;
        link.download = exportData[extension === 'conf' ? 'conf_file' : 'rsc_file'];
        link.click();
        URL.revokeObjectURL(url);
    });

    render();
    window.setInterval(refresh, 30000);
})();
