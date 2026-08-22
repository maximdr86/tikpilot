/**
 * Перевод строк, зашитых в этот файл.
 *
 * Словарь готовит сервер (см. base.html): там он уже на нужном языке.
 * Если строки нет — показываем как есть, по-русски. Это лучше пустоты.
 */
function T(text) {
    return (window.I18N && window.I18N[text]) || text;
}

/* ===========================================================================
   Tikpilot — клиентская логика.
   Обычный JavaScript без фреймворков: страницы рендерит сервер (Jinja2),
   а здесь живут модальные окна, выделение строк, запуск массовых задач
   и опрос прогресса.
   =========================================================================== */

'use strict';

/* --------------------------------------------------------------- утилиты --- */

/** Короткий querySelector. */
const $ = (sel, root = document) => root.querySelector(sel);
/** Короткий querySelectorAll → массив. */
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

/** Всплывающее уведомление. */
function toast(message, kind = '') {
    let wrap = $('.toast-wrap');
    if (!wrap) {
        wrap = document.createElement('div');
        wrap.className = 'toast-wrap';
        document.body.appendChild(wrap);
    }
    const el = document.createElement('div');
    el.className = 'toast ' + kind;
    el.textContent = message;
    wrap.appendChild(el);
    setTimeout(() => el.remove(), 5000);
}

/** Экранирование текста для вставки в HTML. */
function esc(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
}

/** Запрос к API с единообразной обработкой ошибок. */
async function api(url, options = {}) {
    const opts = Object.assign({ headers: {} }, options);
    if (opts.json !== undefined) {
        opts.method = opts.method || 'POST';
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(opts.json);
        delete opts.json;
    }
    const response = await fetch(url, opts);
    if (response.status === 401) {
        window.location.href = '/login';
        throw new Error(T('Требуется вход'));
    }
    let data = null;
    const text = await response.text();
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = { raw: text }; }
    if (!response.ok) {
        throw new Error((data && data.error) || T('Ошибка %s').replace('%s', response.status));
    }
    return data;
}

/* -------------------------------------------------------------- модалки --- */

function openModal(id) {
    const el = document.getElementById(id);
    if (el) { el.classList.add('open'); }
}

function closeModal(id) {
    const el = document.getElementById(id);
    if (el) { el.classList.remove('open'); }
}

// Закрытие по клику на фон и по Escape
document.addEventListener('click', (e) => {
    if (e.target.classList && e.target.classList.contains('modal-backdrop')) {
        e.target.classList.remove('open');
    }
});
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { $$('.modal-backdrop.open').forEach((m) => m.classList.remove('open')); }
});

/* ------------------------------------------------------- реестр действий --- */

let ACTIONS_CACHE = null;

/** Загрузить (один раз) описание массовых действий с сервера. */
async function loadActions() {
    if (!ACTIONS_CACHE) { ACTIONS_CACHE = await api('/api/actions'); }
    return ACTIONS_CACHE;
}

/**
 * Открыть окно запуска массового действия.
 * @param {Object} target — {device_ids:[…]} | {group_id:N} | {all:true}
 * @param {String} targetLabel — описание цели для подтверждения
 * @param {String} preselect — имя действия, которое нужно выбрать сразу
 */
async function openActionModal(target, targetLabel, preselect, values) {
    const actions = await loadActions();
    window.__actionTarget = target;
    window.__actionTargetLabel = targetLabel || '';
    // Значения из библиотеки подставляются в обычную форму, а не в свою:
    // подтверждения, выбор устройств и страховка должны быть те же самые
    window.__actionValues = values || null;

    const select = $('#action-select');
    select.innerHTML = actions
        .map((a) => `<option value="${esc(a.name)}">${esc(a.label)}` +
                    `${a.untested ? ' ' + T('(не проверено)') : ''}` +
                    `${a.dangerous ? ' ⚠' : ''}</option>`)
        .join('');
    if (preselect) { select.value = preselect; }

    $('#action-target-label').textContent = targetLabel || '';
    clearSchedule();
    renderActionParams();
    if (window.__actionValues) {
        Object.entries(window.__actionValues).forEach(([name, value]) => {
            const field = document.querySelector(`[data-param="${name}"]`);
            if (field) { field.value = value; }
        });
        window.__actionValues = null;
    }
    openModal('action-modal');
}

/** Перерисовать форму параметров под выбранное действие. */
function renderActionParams() {
    const actions = ACTIONS_CACHE || [];
    const name = $('#action-select').value;
    const action = actions.find((a) => a.name === name);
    const box = $('#action-params');
    if (!action) { box.innerHTML = ''; return; }

    let html = `<p class="muted small" style="margin-top:0">${esc(action.description)}</p>`;
    if (action.untested) {
        // Стоит выше предупреждения об опасности: сначала «этому нельзя
        // доверять», потом «это опасно». В обратном порядке вторая
        // строка теряется
        html += '<div class="alert warn">' +
            T('Не проверено на живом оборудовании. Написано и покрыто тестами на заглушке, но на настоящем роутере ещё не запускалось. Начните с одной точки, до которой можете доехать.') +
            '</div>';
    }
    if (action.dangerous) {
        html += '<div class="alert error">' + T('Потенциально опасная операция. Проверьте список устройств.') + '</div>';
    }
    // Последовательные действия идут по одной точке. На весь парк это
    // не минуты, а десятки минут, и знать об этом надо до нажатия
    if (action.serial) {
        html += '<div class="alert">' +
            T('Точки обрабатываются по одной, иначе они мешают друг другу и результат врёт. На весь парк это долго.') +
            '</div>';
    }
    // Цена бездействия у страховки выше, чем у самой команды: не подтвердил,
    // и КАЖДАЯ выбранная точка перезагрузится. Сказать это надо до нажатия,
    // а не в журнале постфактум
    if (name === 'safe_change') {
        html += '<div class="alert error">' +
            T('С подтверждением «я сам» каждая выбранная точка перезагрузится, если не подтвердить в срок. Подтверждать надо все, кнопка есть на дашборде.') +
            '</div>';
    }

    action.params.forEach((p) => {
        const id = 'p_' + p.name;
        if (p.type === 'checkbox') {
            html += `<div class="field"><div class="check">
                <input type="checkbox" id="${id}" data-param="${esc(p.name)}" ${p.default ? 'checked' : ''}>
                <label for="${id}">${esc(p.label)}</label></div>
                ${p.help ? `<div class="hint">${esc(p.help)}</div>` : ''}</div>`;
        } else if (p.type === 'textarea') {
            html += `<div class="field"><label for="${id}">${esc(p.label)}${p.required ? ' *' : ''}</label>
                <textarea id="${id}" data-param="${esc(p.name)}" placeholder="${esc(p.placeholder)}">${esc(p.default)}</textarea>
                ${p.help ? `<div class="hint">${esc(p.help)}</div>` : ''}</div>`;
        } else if (p.type === 'device') {
            // Список точек живёт в базе, а не в описании действия: он меняется
            // чаще, чем перезагружается страница. Поэтому пустой список сейчас
            // и подстановка после ответа сервера
            html += `<div class="field"><label for="${id}">${esc(p.label)}${p.required ? ' *' : ''}</label>
                <select id="${id}" data-param="${esc(p.name)}" data-device-list="1">
                    <option value="">${T('Загружаю список...')}</option>
                </select>
                ${p.help ? `<div class="hint">${esc(p.help)}</div>` : ''}</div>`;
        } else if (p.type === 'select') {
            const opts = (p.options || []).map((o) => `<option value="${esc(o[0])}">${esc(o[1])}</option>`).join('');
            html += `<div class="field"><label for="${id}">${esc(p.label)}</label>
                <select id="${id}" data-param="${esc(p.name)}">${opts}</select>
                ${p.help ? `<div class="hint">${esc(p.help)}</div>` : ''}</div>`;
        } else {
            const type = p.type === 'password' ? 'password' : 'text';
            html += `<div class="field"><label for="${id}">${esc(p.label)}${p.required ? ' *' : ''}</label>
                <input type="${type}" id="${id}" data-param="${esc(p.name)}"
                       value="${esc(p.default)}" placeholder="${esc(p.placeholder)}">
                ${p.help ? `<div class="hint">${esc(p.help)}</div>` : ''}</div>`;
        }
    });
    box.innerHTML = html;
    fillDeviceParams();
}

/** Кэш короткого списка точек: в одной модалке его спрашивают не раз. */
let DEVICE_LIST_CACHE = null;

/**
 * Подставить точки в поля выбора устройства.
 *
 * Молча ничего не делает, если таких полей на форме нет — так вызов
 * можно ставить безусловно после каждой перерисовки.
 */
async function fillDeviceParams() {
    const fields = $$('#action-params [data-device-list]');
    if (!fields.length) { return; }
    try {
        if (!DEVICE_LIST_CACHE) {
            const data = await api('/api/devices/brief');
            DEVICE_LIST_CACHE = data.devices || [];
        }
        const options = ['<option value="">' + T('выберите точку') + '</option>']
            .concat(DEVICE_LIST_CACHE.map(
                (d) => `<option value="${d.id}">${esc(d.name)} (${esc(d.host)})</option>`));
        fields.forEach((field) => { field.innerHTML = options.join(''); });
    } catch (err) {
        fields.forEach((field) => {
            field.innerHTML = `<option value="">${T('Не удалось получить список точек')}</option>`;
        });
    }
}

/** Убрать отложенный запуск — задача пойдёт сразу. */
function clearSchedule() {
    const field = $('#action-schedule');
    if (field) { field.value = ''; }
}

/** Поставить задачу на ближайшие 02:00 — обычное окно обслуживания. */
function scheduleTonight() {
    const when = new Date();
    when.setSeconds(0, 0);
    when.setHours(2, 0);
    if (when <= new Date()) { when.setDate(when.getDate() + 1); }

    const pad = (n) => String(n).padStart(2, '0');
    const field = $('#action-schedule');
    if (field) {
        field.value = `${when.getFullYear()}-${pad(when.getMonth() + 1)}-${pad(when.getDate())}`
            + `T${pad(when.getHours())}:${pad(when.getMinutes())}`;
    }
}

/** Собрать значения параметров из формы. */
function collectActionParams() {
    const params = {};
    $$('#action-params [data-param]').forEach((el) => {
        params[el.dataset.param] = el.type === 'checkbox' ? (el.checked ? '1' : '') : el.value;
    });
    return params;
}

/** Отправить задачу на сервер. */
async function submitAction() {
    const actions = ACTIONS_CACHE || [];
    const name = $('#action-select').value;
    const action = actions.find((a) => a.name === name);
    const target = window.__actionTarget || {};

    if (action && action.dangerous) {
        const label = window.__actionTargetLabel || T('выбранные устройства');
        if (!confirm(T('Выполнить «%1» для %2?').replace('%1', action.label).replace('%2', label)
            + '\n\n' + T('Операция необратима.'))) { return; }
    }

    const schedule = ($('#action-schedule') || {}).value || '';
    if (schedule && action && action.dangerous) {
        toast(T('Задача поставлена на ') + schedule.replace('T', ' '), 'ok');
    }

    const button = $('#action-submit');
    button.disabled = true;
    try {
        const payload = Object.assign(
            { action: name, params: collectActionParams(), scheduled_at: schedule },
            target
        );
        const data = await api('/api/jobs', { json: payload });
        closeModal('action-modal');
        toast(T('Задача поставлена в очередь'), 'ok');
        window.location.href = '/jobs/' + data.job_id;
    } catch (err) {
        toast(err.message, 'error');
    } finally {
        button.disabled = false;
    }
}

/* ------------------------------------------------- выделение устройств --- */

/** Идентификаторы отмеченных строк таблицы. */
function selectedDeviceIds() {
    return $$('.row-check:checked').map((cb) => parseInt(cb.value, 10));
}

/** Обновить панель массовых действий под текущее выделение. */
function refreshBulkbar() {
    const ids = selectedDeviceIds();
    const bar = $('#bulkbar');
    if (!bar) { return; }
    bar.classList.toggle('show', ids.length > 0);
    const counter = $('#bulk-count');
    if (counter) { counter.textContent = ids.length; }
    const all = $('#check-all');
    if (all) {
        const boxes = $$('.row-check');
        all.checked = boxes.length > 0 && ids.length === boxes.length;
        all.indeterminate = ids.length > 0 && ids.length < boxes.length;
    }
}

/** Отметить/снять все видимые строки. */
function toggleAll(checked) {
    $$('.row-check').forEach((cb) => { cb.checked = checked; });
    refreshBulkbar();
}

// Делегирование: чекбоксы могут появиться после перерисовки таблицы
document.addEventListener('change', (e) => {
    if (e.target.classList && e.target.classList.contains('row-check')) { refreshBulkbar(); }
});

/* Делегирование кнопок в таблицах.
   Имена объектов передаются через data-атрибуты, а не подставляются в onclick —
   так кавычки и спецсимволы в названиях не могут сломать разметку. */
document.addEventListener('click', (e) => {
    const button = e.target.closest && e.target.closest('[data-edit-device],[data-delete-device],[data-edit-group],[data-delete-group]');
    if (!button) { return; }
    const d = button.dataset;
    if (d.editDevice)   { editDevice(parseInt(d.editDevice, 10)); }
    if (d.deleteDevice) { deleteDevice(parseInt(d.deleteDevice, 10), d.name); }
    if (d.editGroup)    { editGroup(parseInt(d.editGroup, 10), d.name, d.comment, d.color); }
    if (d.deleteGroup)  { deleteGroup(parseInt(d.deleteGroup, 10), d.name); }
});

/* --------------------------------------------------- фильтры устройств --- */

let filterTimer = null;

/**
 * Перезагрузить тело таблицы с учётом фильтров (без перезагрузки страницы).
 *
 * @param {Object} options
 *   silent — фоновое обновление: не трогаем адресную строку.
 */
async function reloadDeviceRows(options = {}) {
    const params = new URLSearchParams({
        q: ($('#f-q') || {}).value || '',
        group_id: ($('#f-group') || {}).value || '',
        status: ($('#f-status') || {}).value || '',
    });
    const tbody = $('#device-rows');
    if (!tbody) { return; }

    // Запоминаем выделение, чтобы автообновление его не сбрасывало
    const selected = new Set(selectedDeviceIds());

    const response = await fetch('/devices/rows?' + params.toString());
    if (response.status === 401) { window.location.href = '/login'; return; }
    tbody.innerHTML = await response.text();

    $$('.row-check').forEach((cb) => {
        if (selected.has(parseInt(cb.value, 10))) { cb.checked = true; }
    });

    // Строки пришли с сервера в исходном порядке — возвращаем выбранную сортировку
    const table = tbody.closest('table');
    if (table && table.dataset.sortCol !== undefined) {
        sortTable(table, parseInt(table.dataset.sortCol, 10), table.dataset.sortDir, true);
    }

    refreshBulkbar();
    markRefreshed();

    if (!options.silent) {
        // Сохраняем фильтры в адресной строке, чтобы ссылку можно было переслать
        history.replaceState(null, '', '/devices?' + params.toString());
    }
}

/** Отложенный вызов перезагрузки (для поля поиска). */
function scheduleReload() {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(reloadDeviceRows, 250);
}

/** Показать время последнего обновления таблицы. */
function markRefreshed() {
    const el = $('#refreshed-at');
    if (el) { el.textContent = new Date().toLocaleTimeString(); }
}

/**
 * Автообновление таблицы устройств.
 *
 * Пропускаем обновление, когда вкладка скрыта (незачем дёргать сервер),
 * когда открыт диалог и когда пользователь набирает текст в поиске —
 * иначе список «прыгал» бы под руками.
 */
let autoRefreshTimer = null;

function startAutoRefresh(seconds) {
    if (autoRefreshTimer) { clearInterval(autoRefreshTimer); }
    if (!seconds || seconds < 3) { return; }

    autoRefreshTimer = setInterval(() => {
        if (document.hidden) { return; }
        if ($('.modal-backdrop.open')) { return; }
        const active = document.activeElement;
        if (active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA')) { return; }
        reloadDeviceRows({ silent: true }).catch(() => { /* сеть моргнула — не страшно */ });
    }, seconds * 1000);
}

/* ------------------------------------------------------ формы устройств --- */

/** Открыть окно добавления устройства. */
function newDevice() {
    const form = $('#device-form');
    form.reset();
    form.dataset.deviceId = '';
    $('#device-modal-title').textContent = T('Новое устройство');
    $('#device-password').placeholder = T('пароль API-пользователя');
    $('#device-form [name=api_port]').value = 8728;
    $('#device-form [name=ftp_port]').value = 21;
    $('#device-form [name=enabled]').checked = true;
    openModal('device-modal');
}

/** Открыть окно редактирования существующего устройства. */
async function editDevice(id) {
    try {
        const data = await api('/api/devices/' + id);
        const form = $('#device-form');
        form.reset();
        form.dataset.deviceId = id;
        $('#device-modal-title').textContent = T('Редактирование: ') + data.name;
        ['name', 'host', 'api_port', 'ftp_port', 'username', 'comment',
         'latency_targets', 'operator'].forEach((key) => {
            const el = form.querySelector(`[name=${key}]`);
            if (el) { el.value = data[key] == null ? '' : data[key]; }
        });
        form.querySelector('[name=group_id]').value = data.group_id || '';
        form.querySelector('[name=use_ssl]').checked = !!data.use_ssl;
        form.querySelector('[name=enabled]').checked = !!data.enabled;
        $('#device-password').placeholder = T('оставьте пустым, чтобы не менять');
        openModal('device-modal');
    } catch (err) {
        toast(err.message, 'error');
    }
}

/** Сохранить устройство (создание или обновление). */
async function saveDevice(event) {
    event.preventDefault();
    const form = $('#device-form');
    const id = form.dataset.deviceId;
    const url = id ? `/api/devices/${id}/update` : '/api/devices';
    try {
        await api(url, { method: 'POST', body: new FormData(form) });
        closeModal('device-modal');
        toast(id ? T('Устройство обновлено') : T('Устройство добавлено'), 'ok');
        if ($('#device-rows')) { reloadDeviceRows(); } else { window.location.reload(); }
    } catch (err) {
        toast(err.message, 'error');
    }
}

/** Удалить одно устройство. */
async function deleteDevice(id, name) {
    if (!confirm(T('Удалить устройство «%s» из Tikpilot?').replace('%s', name)
        + '\n' + T('На само устройство это не влияет.'))) { return; }
    try {
        await api(`/api/devices/${id}/delete`, { method: 'POST' });
        toast(T('Устройство удалено'), 'ok');
        if ($('#device-rows')) { reloadDeviceRows(); } else { window.location.href = '/devices'; }
    } catch (err) {
        toast(err.message, 'error');
    }
}

/** Удалить все отмеченные устройства. */
async function bulkDelete() {
    const ids = selectedDeviceIds();
    if (!ids.length) { return; }
    if (!confirm(T('Удалить %s устройств(а) из Tikpilot?').replace('%s', ids.length))) { return; }
    try {
        await api('/api/devices/bulk-delete', { json: { device_ids: ids } });
        toast(T('Устройства удалены'), 'ok');
        reloadDeviceRows();
    } catch (err) {
        toast(err.message, 'error');
    }
}

/** Переместить отмеченные устройства в выбранную группу. */
async function bulkSetGroup() {
    const ids = selectedDeviceIds();
    const groupId = $('#bulk-group').value;
    if (!ids.length) { return; }
    try {
        await api('/api/devices/bulk-group', { json: { device_ids: ids, group_id: groupId || null } });
        toast(T('Группа изменена'), 'ok');
        reloadDeviceRows();
    } catch (err) {
        toast(err.message, 'error');
    }
}

/** Импорт устройств из CSV. */
async function importCsv(event) {
    event.preventDefault();
    const form = $('#import-form');
    try {
        const data = await api('/api/devices/import', { method: 'POST', body: new FormData(form) });
        closeModal('import-modal');
        toast(T('Импортировано устройств: %s').replace('%s', data.created), 'ok');
        if (data.errors && data.errors.length) { toast(T('Пропущено строк: ') + data.errors.length, 'error'); }
        reloadDeviceRows();
    } catch (err) {
        toast(err.message, 'error');
    }
}

/* ------------------------------------------------------------- группы --- */

function newGroup() {
    const form = $('#group-form');
    form.reset();
    form.dataset.groupId = '';
    $('#group-modal-title').textContent = T('Новая группа');
    openModal('group-modal');
}

function editGroup(id, name, comment, color) {
    const form = $('#group-form');
    form.reset();
    form.dataset.groupId = id;
    form.querySelector('[name=name]').value = name;
    form.querySelector('[name=comment]').value = comment || '';
    form.querySelector('[name=color]').value = color || 'slate';
    $('#group-modal-title').textContent = T('Редактирование группы');
    openModal('group-modal');
}

async function saveGroup(event) {
    event.preventDefault();
    const form = $('#group-form');
    const id = form.dataset.groupId;
    try {
        await api(id ? `/api/groups/${id}/update` : '/api/groups', { method: 'POST', body: new FormData(form) });
        closeModal('group-modal');
        window.location.reload();
    } catch (err) {
        toast(err.message, 'error');
    }
}

async function deleteGroup(id, name) {
    if (!confirm(T('Удалить группу «%s»?').replace('%s', name)
        + '\n' + T('Устройства останутся, но потеряют принадлежность к группе.'))) { return; }
    try {
        await api(`/api/groups/${id}/delete`, { method: 'POST' });
        window.location.reload();
    } catch (err) {
        toast(err.message, 'error');
    }
}

/* -------------------------------------------------------- прогресс задач --- */

/** Опрашивать состояние задачи и обновлять прогресс-бар и таблицу. */
function pollJob(jobId) {
    let ticks = 0;

    async function tick() {
        try {
            const job = await api('/api/jobs/' + jobId);
            const percent = job.total ? Math.round((job.done / job.total) * 100) : 0;

            $('#job-bar').style.width = percent + '%';
            $('#job-progress-text').textContent = T('%1 из %2 (%3%)').replace('%1', job.done).replace('%2', job.total).replace('%3', percent);
            $('#job-ok').textContent = job.ok_count;
            $('#job-fail').textContent = job.fail_count;

            const badge = $('#job-status');
            badge.className = 'badge ' + job.status;
            badge.textContent = { pending: T('В очереди'), running: T('Выполняется'), done: T('Завершена'), cancelled: T('Отменена') }[job.status] || job.status;

            // Таблицу результатов перезагружаем реже, чем счётчики
            if (ticks % 2 === 0 || job.status === 'done' || job.status === 'cancelled') {
                const html = await (await fetch(`/jobs/${jobId}/items`)).text();
                $('#job-items').innerHTML = html;
            }

            if (job.status === 'done' || job.status === 'cancelled') {
                const cancelBtn = $('#job-cancel');
                if (cancelBtn) { cancelBtn.style.display = 'none'; }
                return; // опрос завершён
            }
        } catch (err) {
            /* временная ошибка сети — просто пробуем ещё раз */
        }
        ticks += 1;
        setTimeout(tick, 1500);
    }

    tick();
}

/** Запросить отмену задачи. */
async function cancelJob(jobId) {
    if (!confirm(T('Отменить задачу? Уже начатые устройства доработают до конца.'))) { return; }
    try {
        const data = await api(`/api/jobs/${jobId}/cancel`, { method: 'POST' });
        if (data.status === 'cancelled') {
            // Задача не начиналась и закрыта сразу. Список сам не обновляется,
            // поэтому перечитываем страницу: иначе отменённая задача осталась
            // бы на экране как ожидающая
            toast(T('Задача отменена'), 'ok');
            window.location.reload();
        } else {
            toast(T('Отмена запрошена'), 'ok');
        }
    } catch (err) {
        toast(err.message, 'error');
    }
}

/* ------------------------------------------------------ сортировка таблиц --- */

/**
 * Быстрый фильтр строк таблицы по введённому тексту.
 * Работает по уже загруженным строкам — мгновенно, без обращения к серверу.
 */
function filterTable(input, tableId, counterId) {
    const table = document.getElementById(tableId);
    if (!table || !table.tBodies[0]) { return; }

    const needle = (input.value || '').trim().toLowerCase();
    let shown = 0;
    Array.from(table.tBodies[0].rows).forEach((row) => {
        if (row.querySelector('.empty')) { return; }
        const match = !needle || row.textContent.toLowerCase().includes(needle);
        row.style.display = match ? '' : 'none';
        if (match) { shown += 1; }
    });

    const counter = counterId && document.getElementById(counterId);
    if (counter) { counter.textContent = shown; }
}

/* ------------------------------------------------------------ оформление --- */

/** Переключение светлой/тёмной темы с запоминанием выбора. */
function toggleTheme() {
    const html = document.documentElement;
    const next = html.dataset.theme === 'dark' ? 'light' : 'dark';
    html.dataset.theme = next;
    try { localStorage.setItem('tikpilot-theme', next); } catch (e) { /* приватный режим */ }
}

/* Тема применяется ещё в <head>, до отрисовки страницы — иначе при тёмной
   теме страница успевает мигнуть светлым. Здесь только переключение. */

/* ------------------------------------------------------------- телефон --- */

/**
 * Лист со всеми разделами, который выезжает снизу по кнопке «Ещё».
 *
 * Это то же самое боковое меню, а не его копия: на узком экране оно
 * превращается в лист средствами CSS. Второй список ссылок пришлось бы
 * править дважды, и однажды он бы разошёлся с первым.
 */
function toggleMenu() {
    document.body.classList.toggle('menu-open');
}

function closeMenu() {
    document.body.classList.remove('menu-open');
}

/* Лист закрывается всем, чем ожидается: тапом по ссылке внутри него,
   клавишей Escape и переходом «назад» в истории. Открытый лист поверх
   новой страницы это самая заметная поломка такой вёрстки. */
document.addEventListener('click', (event) => {
    if (event.target.closest('.sidebar a')) { closeMenu(); }
});
document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') { closeMenu(); }
});
window.addEventListener('pageshow', closeMenu);

/* ======================================================= права пользователей */

/**
 * Показать или спрятать форму сброса пароля.
 *
 * Рядом с формой прав, а не вместо неё: это разные разговоры. Права
 * правят вдумчиво и помногу, пароль сбрасывают в одно движение, когда
 * человек звонит и говорит, что не может войти.
 */
function togglePassword(id) {
    const form = document.getElementById('user-pass-' + id);
    if (!form) { return; }
    const shown = form.style.display !== 'none';
    form.style.display = shown ? 'none' : 'block';
    if (!shown) {
        const field = form.querySelector('input[name="password"]');
        if (field) { field.focus(); }
    }
}

/** Показать или спрятать форму прав. */
function toggleUser(id) {
    const form = document.getElementById('user-form-' + id);
    if (form) { form.style.display = form.style.display === 'none' ? 'block' : 'none'; }
}

/** Показать список групп и устройств, только если область ограничена. */
function toggleScope(id) {
    const form = document.getElementById('user-form-' + id);
    const picker = document.getElementById('scope-' + id);
    if (!form || !picker) { return; }
    const all = form.querySelector('input[name="scope_all"]:checked');
    picker.style.display = all && all.value === '1' ? 'none' : 'flex';
}

/**
 * Проставить галочки по набору.
 *
 * Пресет это именно набор галочек, а не отдельная сущность: после нажатия
 * человек правит их дальше как хочет.
 */
function applyPreset(id, keys) {
    const form = document.getElementById('user-form-' + id);
    if (!form) { return; }
    const wanted = new Set(keys);
    form.querySelectorAll('input[name="perm"]').forEach((box) => {
        box.checked = wanted.has(box.value);
    });
}

/* ================================================ публичная ссылка группы */

/** Создать или обновить ссылку и сразу показать её. */
async function makePublicLink(groupId) {
    try {
        const data = await api(`/api/groups/${groupId}/public-link`, { json: { enabled: true } });
        // Показываем адрес и кладём в буфер: почти всегда его тут же отправляют
        await copyText(data.url);
        toast(T('Ссылка скопирована: ') + data.url, 'ok');
        setTimeout(() => window.location.reload(), 1200);
    } catch (err) {
        toast(err.message, 'error');
    }
}

/** Отозвать ссылку. Старый адрес перестаёт работать сразу. */
async function revokePublicLink(groupId, name) {
    if (!confirm(T('Отозвать публичную ссылку на группу «%s»?').replace('%s', name)
        + '\n' + T('Старый адрес сразу перестанет работать.'))) { return; }
    try {
        await api(`/api/groups/${groupId}/public-link`, { json: { enabled: false } });
        toast(T('Ссылка отозвана'), 'ok');
        window.location.reload();
    } catch (err) {
        toast(err.message, 'error');
    }
}

/**
 * Показывать ли оператора связи на публичном листе этой группы.
 *
 * Галочка возвращается на место, если сервер отказал: показывать
 * включённой настройку, которой нет, хуже, чем не показать ничего.
 */
async function togglePublicOperator(groupId, box) {
    const wanted = box.checked;
    box.disabled = true;
    try {
        const r = await api(`/api/groups/${groupId}/public-operator`, { method: 'POST' });
        toast(r.enabled ? T('Оператор виден на публичной ссылке')
                        : T('Оператор скрыт с публичной ссылки'), 'ok');
    } catch (err) {
        box.checked = !wanted;
        toast(err.message, 'error');
    } finally {
        box.disabled = false;
    }
}

/** Скопировать готовый адрес в буфер обмена. */
async function copyPublicLink(token) {
    const url = window.location.origin + '/status/' + token;
    await copyText(url);
    toast(T('Ссылка скопирована: ') + url, 'ok');
}

/**
 * Положить текст в буфер.
 *
 * navigator.clipboard работает только на HTTPS и localhost, а панель часто
 * открыта по обычному http во внутренней сети. Поэтому запасной путь через
 * временное поле ввода.
 */
async function copyText(text) {
    try {
        await navigator.clipboard.writeText(text);
        return;
    } catch (e) { /* нет доступа к буферу — пробуем иначе */ }
    const field = document.createElement('textarea');
    field.value = text;
    field.style.position = 'fixed';
    field.style.opacity = '0';
    document.body.appendChild(field);
    field.select();
    try { document.execCommand('copy'); } catch (e) { /* совсем никак */ }
    document.body.removeChild(field);
}

document.addEventListener('click', (e) => {
    const make = e.target.closest('[data-new-link]');
    if (make) { makePublicLink(make.dataset.newLink); return; }

    const revoke = e.target.closest('[data-revoke-link]');
    if (revoke) { revokePublicLink(revoke.dataset.revokeLink, revoke.dataset.name); return; }

    const copy = e.target.closest('[data-copy-link]');
    if (copy) { copyPublicLink(copy.dataset.copyLink); }
});

/* ============================================================== WireGuard */

let wgConfigs = { rsc: '', conf: '', qr: '' };

/** Обработчики кнопок в таблицах линков и маршрутов. */
function wgInit() {
    document.addEventListener('click', (e) => {
        const script = e.target.closest('[data-wg-script]');
        if (script) { wgScript(script.dataset.wgScript); return; }

        const remove = e.target.closest('[data-wg-remove]');
        if (remove) { wgRemove(remove.dataset.wgRemove); return; }

        const route = e.target.closest('[data-wg-route]');
        if (route) { wgRemoveRoute(route.dataset.wgRoute); }
    });
}

function wgHubId() {
    const select = document.querySelector('select[name="device_id"]');
    return select ? parseInt(select.value, 10) : 0;
}

async function wgSaveHub(deviceId, quiet) {
    const send = () => api('/api/wg/hub', { json: {
        device_id: deviceId,
        interface: $('#wg-iface').value,
        public_host: $('#wg-host').value,
        listen_port: $('#wg-port').value,
        lan_subnets: $('#wg-lans').value,
    }});
    // Тихий режим нужен при создании линка: подсети хаба там уже подставлены
    // из роутера, и требовать отдельного нажатия «Сохранить» значило бы
    // время от времени выпускать линк без маршрутов к сетям за хабом.
    if (quiet) { return send(); }
    try {
        await send();
        toast(T('Настройки хаба сохранены'), 'ok');
        window.location.reload();
    } catch (err) { toast(err.message, 'error'); }
}

async function wgSetTunnel(deviceId) {
    const iface = $('#wg-iface').value;
    if (!iface) { toast(T('Сначала выберите интерфейс'), 'error'); return; }
    try {
        await api('/api/wg/tunnel-address', { json: {
            device_id: deviceId, interface: iface, address: $('#wg-tunnel').value,
        }});
        toast(T('Туннельный адрес записан'), 'ok');
        window.location.reload();
    } catch (err) { toast(err.message, 'error'); }
}

async function wgFirewall(deviceId) {
    try {
        const data = await api('/api/wg/firewall', { json: {
            device_id: deviceId,
            interface: $('#wg-iface').value,
            listen_port: $('#wg-port').value,
        }});
        toast(data.added ? T('Добавлено правил: %s').replace('%s', data.added)
                         : T('Правила уже на месте'), 'ok');
        window.location.reload();
    } catch (err) { toast(err.message, 'error'); }
}

async function wgCreate(deviceId) {
    const name = $('#wg-name').value.trim();
    if (!name) { toast(T('Укажите название площадки'), 'error'); return; }
    try {
        await wgSaveHub(deviceId, true);
        const data = await api('/api/wg/links', { json: {
            device_id: deviceId,
            name: name,
            tunnel_ip: $('#wg-ip').value,
            subnets: $('#wg-subnets').value,
            psk: $('#wg-psk').checked,
        }});
        wgOpenConfig(data);
        toast(T('Линк создан'), 'ok');
    } catch (err) { toast(err.message, 'error'); }
}

async function wgScript(name) {
    try {
        const data = await api('/api/wg/links/script', {
            json: { device_id: wgHubId(), name: name },
        });
        wgOpenConfig(data);
    } catch (err) { toast(err.message, 'error'); }
}

async function wgRemove(name) {
    if (!confirm(T('Удалить линк «%s»?').replace('%s', name) + '\n'
        + T('Будут удалены пир и маршруты с меткой этого линка.'))) { return; }
    try {
        await api('/api/wg/links/delete', { json: { device_id: wgHubId(), name: name } });
        toast(T('Линк удалён'), 'ok');
        window.location.reload();
    } catch (err) { toast(err.message, 'error'); }
}

async function wgAddRoute(deviceId) {
    const subnet = $('#wg-route').value.trim();
    if (!subnet) { toast(T('Укажите подсеть'), 'error'); return; }
    const gateway = $('#wg-route-gw').value;
    if (!gateway) { toast(T('Выберите шлюз'), 'error'); return; }
    try {
        await api('/api/wg/routes', { json: {
            device_id: deviceId, subnet: subnet, gateway: gateway,
        }});
        window.location.reload();
    } catch (err) { toast(err.message, 'error'); }
}

async function wgFixGateways(deviceId) {
    try {
        const data = await api('/api/wg/routes/fix-gateways', { json: { device_id: deviceId } });
        toast(T('Исправлено маршрутов: %s').replace('%s', data.fixed), 'ok');
        window.location.reload();
    } catch (err) { toast(err.message, 'error'); }
}

async function wgRemoveRoute(routeId) {
    if (!confirm(T('Удалить маршрут?'))) { return; }
    try {
        await api('/api/wg/routes/delete', { json: { device_id: wgHubId(), id: routeId } });
        window.location.reload();
    } catch (err) { toast(err.message, 'error'); }
}

/** Показать окно с готовой конфигурацией дальней стороны. */
function wgOpenConfig(data) {
    wgConfigs = { rsc: data.script || '', conf: data.config || '', qr: data.qr || '' };
    // QR рисуется сервером и вставляется как есть: это наш собственный SVG,
    // а не текст, пришедший от устройства или от пользователя
    $('#wg-qr').innerHTML = wgConfigs.qr;
    wgShowTab('rsc');
    openModal('wg-config-modal');
}

function wgShowTab(kind) {
    $('#wg-config-text').value = kind === 'conf' ? wgConfigs.conf : wgConfigs.rsc;
    $('#wg-tab-rsc').classList.toggle('active', kind === 'rsc');
    $('#wg-tab-conf').classList.toggle('active', kind === 'conf');
    // QR только для обычного клиента: скрипт RouterOS с телефона не вносят
    $('#wg-qr-box').hidden = !(kind === 'conf' && wgConfigs.qr);
}

async function wgCopyConfig() {
    await copyText($('#wg-config-text').value);
    toast(T('Скопировано'), 'ok');
}

async function wgApplySpoke() {
    const spoke = $('#wg-spoke').value;
    if (!spoke) { toast(T('Выберите устройство'), 'error'); return; }
    if (!confirm(T('Выполнить этот скрипт на выбранном роутере?') + '\n'
        + T('Ошибка в подсетях может отрезать удалённую точку.'))) { return; }
    try {
        const data = await api('/api/wg/links/apply', {
            json: { spoke_id: parseInt(spoke, 10), script: $('#wg-config-text').value },
        });
        window.location.href = '/jobs/' + data.job_id;
    } catch (err) { toast(err.message, 'error'); }
}

/* ==================================================== сворачиваемые разделы */

/**
 * Сложить или развернуть раздел кликом по заголовку.
 *
 * Состояние живёт в localStorage: страница мониторинга длинная, и складывать
 * одно и то же при каждом заходе быстро надоедает. Ключ привязан к имени
 * раздела, а не к его номеру: порядок блоков на странице ещё поменяется.
 */
function setupFolds() {
    document.querySelectorAll('.panel[data-fold]').forEach((panel) => {
        const key = 'tikpilot-fold-' + panel.dataset.fold;
        const title = panel.querySelector(':scope > h2');
        if (!title) { return; }

        title.classList.add('foldable');
        // Заголовок стал управлением, значит должен работать и с клавиатуры
        title.tabIndex = 0;
        title.setAttribute('role', 'button');

        let closed = false;
        try { closed = localStorage.getItem(key) === '1'; } catch (e) { /* приватный режим */ }
        panel.classList.toggle('folded', closed);
        title.setAttribute('aria-expanded', closed ? 'false' : 'true');

        const toggle = () => {
            const now = panel.classList.toggle('folded');
            title.setAttribute('aria-expanded', now ? 'false' : 'true');
            try { localStorage.setItem(key, now ? '1' : '0'); } catch (e) { /* приватный режим */ }
        };
        title.addEventListener('click', toggle);
        title.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
        });
    });
}

setupFolds();
