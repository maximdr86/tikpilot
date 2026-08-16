/* ===========================================================================
   Сортировка таблиц по клику на заголовок.

   Вынесено из app.js отдельным файлом, потому что нужно и на публичном листе
   состояния, а туда app.js не подключается: там нет ни учётной записи, ни
   API, ни модальных окон, и тащить всё это на страницу для посторонних
   незачем.

   Всё завёрнуто в функцию: app.js объявляет глобальные `$` и `$$`, и второе
   такое же объявление в другом файле уронило бы страницу целиком.
   =========================================================================== */

(function () {
    'use strict';

    const all = (sel, root) => Array.from((root || document).querySelectorAll(sel));

    /**
     * Разметить таблицы с классом `sortable`.
     *
     * Значение для сравнения берётся из атрибута data-sort ячейки, а если его
     * нет — из текста. Это важно для чисел и дат: «сегодня 14:31» и «2 ч 13 мин»
     * как текст сортируются бессмысленно, поэтому в шаблонах у таких ячеек
     * проставлен data-sort с исходным числом или меткой времени.
     *
     * Колонку можно исключить из сортировки классом `no-sort` у заголовка.
     */
    function initSortableTables(root) {
        all('table.sortable', root).forEach((table) => {
            all('thead th', table).forEach((th, index) => {
                if (th.classList.contains('no-sort')) { return; }
                th.classList.add('sortable-col');
                th.addEventListener('click', () => {
                    // Три состояния, а не два: по возрастанию, по убыванию
                    // и обратно как пришло с сервера. Без третьего клика
                    // журнал, отсортированный однажды по «подробностям»,
                    // остаётся таким навсегда, и вернуть хронологию нечем
                    const same = table.dataset.sortCol === String(index);
                    if (same && table.dataset.sortDir === 'desc') {
                        resetSort(table);
                        return;
                    }
                    const dir = same && table.dataset.sortDir === 'asc' ? 'desc' : 'asc';
                    sortTable(table, index, dir);
                });
            });

            // Восстанавливаем ранее выбранную сортировку (например, после перерисовки)
            const saved = savedSort(table);
            if (saved) { sortTable(table, saved.col, saved.dir, true); }
        });
    }

    /** Отсортировать таблицу по колонке. */
    function sortTable(table, index, dir, quiet) {
        const tbody = table.tBodies[0];
        if (!tbody) { return; }

        const rows = Array.from(tbody.rows).filter((r) => !r.querySelector('.empty'));
        if (rows.length < 2) { return; }

        // Запоминаем исходный порядок один раз, чтобы третий клик мог
        // его вернуть
        rows.forEach((row, i) => {
            if (row.dataset.order === undefined) { row.dataset.order = String(i); }
        });

        const value = (row) => {
            const cell = row.cells[index];
            if (!cell) { return ''; }
            return cell.dataset.sort !== undefined ? cell.dataset.sort : cell.textContent.trim();
        };

        // Числами сортируем только если числа во всех непустых ячейках
        const values = rows.map(value).filter((v) => v !== '' && v !== '—');
        const numeric = values.length > 0 && values.every((v) => !isNaN(parseFloat(v)) && isFinite(v));

        const sign = dir === 'asc' ? 1 : -1;
        rows.sort((a, b) => {
            const x = value(a);
            const y = value(b);
            if (numeric) { return sign * (parseFloat(x || 0) - parseFloat(y || 0)); }
            return sign * x.localeCompare(y, 'ru', { numeric: true, sensitivity: 'base' });
        });
        rows.forEach((row) => tbody.appendChild(row));

        table.dataset.sortCol = String(index);
        table.dataset.sortDir = dir;
        all('thead th', table).forEach((th, i) => {
            th.classList.toggle('sorted-asc', i === index && dir === 'asc');
            th.classList.toggle('sorted-desc', i === index && dir === 'desc');
        });

        if (!quiet) { rememberSort(table, index, dir); }
    }

    /**
     * Вернуть таблицу к порядку, в котором её отдал сервер.
     *
     * Исходный номер строки запоминается при первой сортировке: своей
     * копии таблицы у нас нет, а перезагружать страницу ради сброса
     * невежливо, человек мог что-то ввести в фильтры.
     */
    function resetSort(table) {
        const tbody = table.tBodies[0];
        if (!tbody) { return; }
        Array.from(tbody.rows)
            .sort((a, b) => (a.dataset.order || 0) - (b.dataset.order || 0))
            .forEach((row) => tbody.appendChild(row));

        delete table.dataset.sortCol;
        delete table.dataset.sortDir;
        all('thead th', table).forEach((th) => {
            th.classList.remove('sorted-asc', 'sorted-desc');
        });
        try { localStorage.removeItem(sortKey(table)); } catch (e) { /* приватный режим */ }
    }

    /** Ключ для запоминания сортировки: страница + номер таблицы на ней. */
    function sortKey(table) {
        return 'tikpilot-sort:' + window.location.pathname
            + ':' + all('table.sortable').indexOf(table);
    }

    function rememberSort(table, index, dir) {
        try {
            localStorage.setItem(sortKey(table), index + ':' + dir);
        } catch (e) { /* приватный режим */ }
    }

    function savedSort(table) {
        try {
            const raw = localStorage.getItem(sortKey(table));
            if (!raw) { return null; }
            const parts = raw.split(':');
            return { col: parseInt(parts[0], 10), dir: parts[1] };
        } catch (e) { return null; }
    }

    window.initSortableTables = initSortableTables;
    window.sortTable = sortTable;
    window.resetSortedTable = resetSort;

    document.addEventListener('DOMContentLoaded', () => initSortableTables());
}());
