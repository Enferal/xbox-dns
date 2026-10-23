import * as lib from "./lib.js";

const state = {
  csrf: "",
  ui: null,
  client: "",
  cleanups: [],
  renderId: 0,
  lastRoute: "",
  access: null,
};

const PAGES = [
  ["overview", "Обзор"],
  ["domains", "Домены"],
  ["clients", "Клиенты"],
  ["settings", "Настройки"],
  ["logs", "Журнал"],
  ["firewall", "Файрвол"],
  ["maintenance", "Обслуживание"],
];

const COUNTERS = [
  ["dns_queries", "Запросов DNS"],
  ["dns_hijacked", "Ответ адресом VPS"],
  ["dns_forwarded", "Переслано наружу"],
  ["dns_direct", "Закачка напрямую"],
  ["dns_refused", "Отказ DNS"],
  ["tcp_accepted", "TCP-соединений"],
  ["proxy_ok", "Проксировано"],
  ["proxy_no_name", "Без подходящего имени"],
  ["proxy_refused", "Отказ прокси"],
  ["proxy_errors", "Ошибки прокси"],
  ["proxy_overflow", "Переполнение очереди"],
];

const LIST_TABS = [
  ["proxy", "Через прокси", "Имена, которые сервер называет своими. Строка example.com покрывает и поддомены. www и само имя зоны остаются на 443, остальные имена зоны получают отдельные порты."],
  ["direct", "Напрямую", "Имена закачки: получают настоящий адрес, файл качается с домашнего адреса."],
  ["sameport", "Общий порт", "Эти зоны целиком остаются на 443. Уберите зону отсюда, чтобы её имена, кроме www, шли на порты 44400–44463."],
  ["exits", "Выходные IP", "Адреса VPS, которые получает устройство. auto — основной адрес сервера."],
];

// ---------- DOM ----------

function h(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else if (key === "value" || key === "checked" || key === "disabled" || key === "selected") node[key] = value;
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

function badge(text, tone) {
  return h("span", { class: `badge ${tone || ""}`, text });
}

function card(title, ...children) {
  return h("section", { class: "card" }, title ? h("h2", { text: title }) : null, ...children);
}

function field(label, control, hint) {
  return h("label", { class: "field" }, h("span", { class: "field-label", text: label }), control, hint ? h("small", { text: hint }) : null);
}

function button(text, onclick, cls = "") {
  return h("button", { type: "button", class: cls, onclick, text });
}

function select(options, value, onchange) {
  return h(
    "select",
    { onchange },
    options.map(([key, label]) => h("option", { value: key, selected: key === value, text: label })),
  );
}

function table(headers, rows, empty = "Пусто") {
  if (!rows.length) return h("p", { class: "muted", text: empty });
  return h(
    "div",
    { class: "table-wrap" },
    h("table", {}, h("thead", {}, h("tr", {}, headers.map((name) => h("th", { text: name })))), h("tbody", {}, rows.map((cells) => h("tr", {}, cells.map((cell) => h("td", {}, cell)))))),
  );
}

function pre(text, cls = "") {
  return h("pre", { class: `output ${cls}`, text: text || "" });
}

function diffView(diff) {
  const parts = Object.entries(diff || {});
  if (!parts.length) return h("p", { class: "muted", text: "Изменений нет." });
  return h(
    "div",
    {},
    parts.map(([, text]) => h("pre", { class: "output diff" }, text.split("\n").map((line) => h("div", { class: lib.diffLineClass(line), text: line || " " })))),
  );
}

function toast(text, tone = "") {
  const box = document.getElementById("toasts");
  const item = h("div", { class: `toast ${tone}`, role: "status", text });
  box.append(item);
  setTimeout(() => item.remove(), tone === "bad" ? 9000 : 4500);
}

function onCleanup(fn) {
  state.cleanups.push(fn);
}

function runCleanups() {
  for (const fn of state.cleanups.splice(0)) {
    try {
      fn();
    } catch (error) {
      console.error(error);
    }
  }
}

function busy(btn, promise) {
  btn.disabled = true;
  btn.classList.add("busy");
  return promise.finally(() => {
    btn.disabled = false;
    btn.classList.remove("busy");
  });
}

// ---------- API ----------

class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.status = status;
    this.data = data || {};
  }
}

async function api(path, body) {
  const options = { method: body === undefined ? "GET" : "POST", headers: {}, credentials: "same-origin", cache: "no-store" };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.headers["X-CSRF-Token"] = state.csrf;
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, options);
  } catch (error) {
    throw new ApiError("Нет связи с сервером", 0, {});
  }
  let data = {};
  try {
    data = await response.json();
  } catch (error) {
    data = {};
  }
  if (response.status === 401) {
    showLogin("Сессия закончилась. Войдите снова.");
    throw new ApiError(data.error || "Нужен вход", 401, data);
  }
  if (!response.ok) throw new ApiError(data.error || `Ошибка ${response.status}`, response.status, data);
  return data;
}

function errorText(error) {
  if (!(error instanceof ApiError)) return String(error && error.message ? error.message : error);
  const errors = error.data && error.data.errors;
  if (errors && typeof errors === "object") {
    return `${error.message}: ${Object.entries(errors).map(([key, value]) => `${key} — ${value}`).join("; ")}`;
  }
  return error.message;
}

function report(error) {
  if (error instanceof ApiError && error.status === 401) return;
  toast(errorText(error), "bad");
}

function errorsBox(errors) {
  const items = Object.entries(errors || {});
  if (!items.length) return null;
  return h("div", { class: "alert bad" }, h("strong", { text: "Не прошло проверку" }), h("ul", {}, items.map(([key, value]) => h("li", {}, h("code", { text: key }), ` — ${value}`))));
}

function tunnelHint(access) {
  if (!access || access.mode !== "tunnel") return null;
  return h(
    "div",
    { class: "tunnel" },
    h("p", { text: "Панель работает без HTTPS и слушает только 127.0.0.1 на VPS. Открывайте её через SSH-туннель." }),
    h("p", { class: "muted", text: "На своём компьютере (OpenSSH в Linux, macOS, Windows 10+):" }),
    pre(access.command),
    h("p", { class: "muted" }, "Пока команда работает, откройте ", h("code", { text: access.url }), "."),
    h("p", { class: "muted", text: `PuTTY: ${access.putty}` }),
  );
}

// ---------- каркас ----------

function showLogin(message = "") {
  runCleanups();
  state.csrf = "";
  const root = clear(document.getElementById("app"));
  const input = h("input", { type: "password", autocomplete: "current-password", required: true, autofocus: true });
  const note = h("p", { class: "login-note", text: message });
  const submit = h("button", { type: "submit", class: "primary", text: "Войти" });
  const form = h(
    "form",
    {
      class: "login card",
      onsubmit: async (event) => {
        event.preventDefault();
        note.textContent = "";
        submit.disabled = true;
        try {
          const response = await fetch("/api/login", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json", "X-Requested-With": "egress-ui" },
            body: JSON.stringify({ password: input.value }),
          });
          const data = await response.json().catch(() => ({}));
          if (!response.ok) {
            note.textContent = data.error || `Ошибка ${response.status}`;
            input.select();
            return;
          }
          state.csrf = data.csrf;
          state.ui = data.ui;
          state.client = data.client || "";
          input.value = "";
          startApp();
        } catch (error) {
          note.textContent = "Нет связи с сервером";
        } finally {
          submit.disabled = false;
        }
      },
    },
    h("h1", { text: "egress-proxy" }),
    h("p", { class: "muted", text: "Панель управления DNS и прокси" }),
    field("Пароль", input),
    submit,
    note,
    state.access && state.access.mode === "tunnel" ? h("details", {}, h("summary", { text: "Как зайти через SSH-туннель" }), tunnelHint(state.access)) : null,
  );
  root.append(h("main", { class: "login-wrap" }, form));
  input.focus();
}

function currentRoute() {
  const name = location.hash.replace(/^#\/?/, "").split("?")[0];
  return PAGES.some(([key]) => key === name) ? name : "overview";
}

function startApp() {
  const root = clear(document.getElementById("app"));
  const nav = h(
    "nav",
    { class: "nav" },
    PAGES.map(([key, label]) => h("a", { href: `#/${key}`, "data-page": key, text: label })),
  );
  const header = h(
    "header",
    { class: "top" },
    h("div", { class: "brand" }, h("strong", { text: "egress-proxy" }), h("span", { class: "muted", text: ` UI ${state.ui ? state.ui.version : ""}` })),
    nav,
    button("Выйти", async () => {
      try {
        await api("/api/logout", {});
      } catch (error) {
        /* сессия уже могла закончиться */
      }
      showLogin("Вы вышли.");
    }, "ghost"),
  );
  const main = h("main", { id: "page", class: "page" });
  root.append(header, main);
  renderRoute();
}

async function renderRoute() {
  runCleanups();
  const route = currentRoute();
  const renderId = ++state.renderId;
  for (const link of document.querySelectorAll(".nav a")) {
    link.classList.toggle("active", link.dataset.page === route);
  }
  const main = document.getElementById("page");
  if (!main) return;
  if (state.lastRoute !== route || !main.firstChild) clear(main).append(h("p", { class: "muted", text: "Загрузка…" }));
  state.lastRoute = route;
  const view = h("div", { class: "view" });
  try {
    await ROUTES[route](view);
    if (renderId !== state.renderId) return;
    clear(main).append(view);
  } catch (error) {
    if (renderId !== state.renderId) return;
    if (error instanceof ApiError && error.status === 401) return;
    clear(main).append(card("Ошибка", h("p", { text: errorText(error) }), button("Повторить", renderRoute)));
  }
}

window.addEventListener("hashchange", () => {
  if (state.csrf) renderRoute();
});

// ---------- общие действия ----------

async function applyDraft(draft, { restart = true } = {}) {
  const config = await api("/api/config");
  const result = await api("/api/config/apply", { ...draft, etag: draft.etag || config.etag, restart });
  if (result.ok) toast(result.message || "Готово", "ok");
  else if (result.rolled_back) toast("Служба не поднялась с новыми настройками. Прежние файлы возвращены.", "bad");
  else toast(errorText(new ApiError("Не применено", 400, result)), "bad");
  return result;
}

async function addClient(address) {
  const config = await api("/api/config");
  const next = lib.addCsv(config.env.ALLOW_CLIENTS, address);
  if (next === config.env.ALLOW_CLIENTS) {
    toast(`${address} уже в ALLOW_CLIENTS`);
    return null;
  }
  if (!window.confirm(`Добавить ${address} в ALLOW_CLIENTS и перезапустить службу?`)) return null;
  return applyDraft({ env: { ALLOW_CLIENTS: next }, etag: config.etag });
}

function applyResult(result) {
  if (!result) return null;
  const parts = [];
  if (result.message) parts.push(h("p", { text: result.message }));
  if (result.errors) parts.push(errorsBox(result.errors));
  if (result.backup) parts.push(h("p", { class: "muted", text: `Резервная копия: ${lib.backupLabel(result.backup)}` }));
  const logs = (result.service && result.service.logs) || [];
  if (logs.length) parts.push(h("details", { open: true }, h("summary", { text: "Журнал службы" }), pre(logs.map((item) => item.msg).join("\n"))));
  if (result.check && result.check.messages) parts.push(pre(result.check.messages));
  return h("div", { class: `alert ${result.ok ? "ok" : "bad"}` }, parts);
}

// ---------- Обзор ----------

async function pageOverview(view) {
  const data = await api("/api/overview");
  const service = data.service || {};
  const tone = lib.serviceTone(service.state);
  const actions = h("div", { class: "row" });
  for (const [action, label, cls] of [["start", "Запустить", ""], ["restart", "Перезапустить", "primary"], ["stop", "Остановить", "danger"]]) {
    const btn = button(label, () => {
      if (action === "stop" && !window.confirm("Остановить службу? Устройства потеряют DNS.")) return;
      busy(btn, api("/api/service", { action })).then((result) => {
        toast(result.ok ? "Готово" : result.error || "Не получилось", result.ok ? "ok" : "bad");
        renderRoute();
      }, report);
    }, cls);
    actions.append(btn);
  }
  const serviceCard = card(
    "Служба",
    h("div", { class: "status-line" }, badge(service.state || "unknown", tone), h("span", { class: "muted", text: service.sub || service.detail || "" })),
    h(
      "dl",
      { class: "facts" },
      fact("Работает", lib.formatUptime(service.uptime)),
      fact("Перезапусков", service.restarts ?? "—"),
      fact("PID", service.pid || "—"),
      service.enabled ? fact("Автозапуск", service.enabled) : null,
      service.health ? fact("Health", service.health) : null,
    ),
    data.ui && data.ui.service_backend === "none" ? h("p", { class: "muted", text: "Управление службой выключено." }) : actions,
  );

  const env = data.env || {};
  const dnsCard = card(
    "DNS для устройства",
    data.dns_addresses && data.dns_addresses.length
      ? h("div", { class: "big-list" }, data.dns_addresses.map((address) => h("code", { class: "big", text: address })))
      : h("p", { class: "muted", text: "Адрес не определён" }),
    h(
      "dl",
      { class: "facts" },
      fact("Порт DNS", env.DNS_PORT),
      fact("Порты прокси", env.PROXY_PORTS),
      fact("Свои порты", env.SPLIT_HTTPS === "0" ? "выключены, все на 443" : "44400–44463"),
      fact("IPv6", env.IPV6 === "1" ? "включён" : "выключен"),
      fact("Клиенты", env.ALLOW_CLIENTS || "все"),
    ),
  );

  const runtime = data.runtime;
  let countersBody;
  if (!runtime) {
    countersBody = h("p", { class: "muted", text: "Счётчиков нет: служба ещё не записала STATUS_FILE (старая версия или не запущена)." });
  } else {
    const counters = runtime.counters || {};
    countersBody = h(
      "div",
      {},
      runtime.stale ? h("p", { class: "alert warn", text: "Статус не обновлялся больше 30 с — служба, возможно, остановлена." }) : null,
      h("div", { class: "counters" }, COUNTERS.map(([key, label]) => h("div", { class: "counter" }, h("span", { class: "counter-value", text: String(counters[key] || 0) }), h("span", { class: "counter-label", text: label })))),
      h("p", { class: "muted", text: `С запуска ${lib.formatTime(runtime.started_at, true)}. Сейчас открыто: DNS ${runtime.dns_inflight}, прокси ${runtime.proxy_inflight}.` }),
    );
  }
  const countersCard = card("Счётчики с запуска", countersBody);

  const warnings = data.warnings || [];
  const warningsCard = warnings.length ? card("Предупреждения", h("ul", { class: "warnings" }, warnings.map((text) => h("li", { text })))) : null;

  const recent = data.recent || {};
  const refusedRows = (recent.refused || []).slice(0, 10).map((item) => [
    h("code", { text: item.client }),
    String(item.count),
    lib.formatTime(item.last, true),
    button("Добавить", () => addClient(item.client).then((result) => result && renderRoute(), report), "small"),
  ]);
  const refusedCard = card(
    "Последние отказы",
    h("p", { class: "muted", text: `По последним ${recent.lines || 0} строкам журнала.` }),
    table(["Адрес", "Раз", "Последний", ""], refusedRows, "Отказов нет."),
  );
  const tops = card(
    "Топы",
    h(
      "div",
      { class: "grid3" },
      topTable("Домены", recent.top_domains),
      topTable("Клиенты", recent.top_clients),
      topTable("Порты", recent.top_ports),
    ),
    (recent.errors || []).length ? h("details", {}, h("summary", { text: `Последние ошибки (${recent.errors.length})` }), pre(recent.errors.map((item) => `${lib.formatTime(item.ts)} ${item.msg}`).join("\n"))) : null,
  );

  view.append(
    h("div", { class: "page-head" }, h("h1", { text: "Обзор" }), button("Обновить", renderRoute, "ghost")),
    h("div", { class: "grid2" }, serviceCard, dnsCard),
    warningsCard,
    countersCard,
    refusedCard,
    tops,
  );
  const timer = setInterval(() => {
    if (document.visibilityState === "visible") renderRoute();
  }, 20000);
  onCleanup(() => clearInterval(timer));
}

function fact(label, value) {
  return [h("dt", { text: label }), h("dd", { text: value === undefined || value === null || value === "" ? "—" : String(value) })];
}

function topTable(title, items) {
  return h("div", {}, h("h3", { text: title }), table(["", "Раз"], (items || []).map(([name, count]) => [h("code", { text: String(name) }), String(count)]), "Нет данных"));
}

// ---------- Домены ----------

async function pageDomains(view) {
  const [config, presets] = await Promise.all([api("/api/config"), api("/api/presets")]);
  const sameBuiltin = presets.same_port || "";
  const original = { ...config.files };
  const drafts = {};
  for (const [kind] of LIST_TABS) drafts[kind] = config.files[kind] ?? "";
  let sameUsesBuiltin = false;
  if (original.sameport == null) {
    drafts.sameport = sameBuiltin;
    original.sameport = sameBuiltin;
    sameUsesBuiltin = true;
  }
  let tab = new URLSearchParams(location.hash.split("?")[1] || "").get("tab") || "proxy";
  if (!LIST_TABS.some(([key]) => key === tab)) tab = "proxy";
  let textMode = false;

  const tabs = h("div", { class: "tabs" });
  const body = h("div", {});
  const result = h("div", {});
  const changed = () => LIST_TABS.some(([kind]) => drafts[kind] !== (original[kind] ?? ""));
  const pending = h("span", { class: "muted" });

  function draftFiles() {
    const files = {};
    for (const [kind] of LIST_TABS) if (drafts[kind] !== (original[kind] ?? "")) files[kind] = drafts[kind];
    return files;
  }

  function renderTabs() {
    clear(tabs);
    for (const [key, label] of LIST_TABS) {
      const count = lib.listValues(drafts[key]).length;
      const dirty = drafts[key] !== (original[key] ?? "");
      tabs.append(button(`${label} (${count})${dirty ? " *" : ""}`, () => {
        tab = key;
        renderAll();
      }, key === tab ? "tab active" : "tab"));
    }
    pending.textContent = changed() ? "Есть несохранённые изменения." : "";
  }

  function renderBody() {
    clear(body);
    const [, label, hint] = LIST_TABS.find(([key]) => key === tab);
    body.append(h("p", { class: "muted", text: hint }));
    if (tab === "direct" && original.direct === null) {
      body.append(h("p", { class: "alert warn", text: "Файла нет: служба использует встроенный список закачки. Сохранение создаст файл." }));
    }
    if (tab === "sameport" && sameUsesBuiltin && drafts.sameport === sameBuiltin) {
      body.append(h("p", { class: "alert warn", text: "Файла ещё нет: показаны зоны приставки, они остаются на 443. «Применить» запишет этот список в файл." }));
    }
    const input = h("input", { type: "text", placeholder: tab === "exits" ? "203.0.113.5 или auto" : "example.com", autocomplete: "off" });
    const comment = h("input", { type: "text", placeholder: "комментарий (необязательно)", autocomplete: "off" });
    const add = () => {
      let value = input.value.trim();
      if (tab !== "exits") {
        value = lib.normalizeDomain(value);
        if (!value) {
          toast("Нужен домен вида example.com", "bad");
          return;
        }
      } else if (!value) {
        return;
      }
      const next = lib.addEntry(drafts[tab], value, comment.value.trim().replace(/#/g, ""));
      if (!next.added) toast(`${value} уже в списке`);
      drafts[tab] = next.text;
      input.value = "";
      comment.value = "";
      renderAll();
    };
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") add();
    });
    body.append(h("div", { class: "row" }, input, comment, button("Добавить", add, "primary")));
    const tools = h("div", { class: "row" }, button(textMode ? "Списком" : "Правка текстом", () => {
      textMode = !textMode;
      renderAll();
    }, "ghost"));
    if (tab === "proxy" && presets.xbox_domains) {
      tools.append(button("Добавить пресет Xbox", () => {
        let added = 0;
        for (const item of lib.parseList(presets.xbox_domains)) {
          const next = lib.addEntry(drafts.proxy, item.value, item.comment);
          if (next.added) added += 1;
          drafts.proxy = next.text;
        }
        toast(added ? `Добавлено имён: ${added}` : "Все имена пресета уже в списке");
        renderAll();
      }, "ghost"));
    }
    if (tab === "direct" && presets.direct) {
      tools.append(button("Взять список из примера", () => {
        if (drafts.direct.trim() && !window.confirm("Заменить текущий список примером?")) return;
        drafts.direct = presets.direct;
        renderAll();
      }, "ghost"));
    }
    if (tab === "sameport" && drafts.sameport !== sameBuiltin) {
      tools.append(button("Зоны приставки", () => {
        if (drafts.sameport.trim() && !window.confirm("Заменить список зонами приставки?")) return;
        drafts.sameport = sameBuiltin;
        renderAll();
      }, "ghost"));
    }
    if (drafts[tab] !== (original[tab] ?? "")) {
      tools.append(button("Отменить правки вкладки", () => {
        drafts[tab] = original[tab] ?? "";
        renderAll();
      }, "ghost"));
    }
    body.append(tools);
    if (textMode) {
      const area = h("textarea", { rows: 18, spellcheck: "false", value: drafts[tab] });
      area.addEventListener("input", () => {
        drafts[tab] = area.value;
        renderTabs();
      });
      body.append(area);
    } else {
      const rows = lib.parseList(drafts[tab]).map((item) => [
        h("code", { text: item.value }),
        h("span", { class: "muted", text: item.comment }),
        button("Удалить", () => {
          drafts[tab] = lib.removeEntry(drafts[tab], item.value);
          renderAll();
        }, "small danger"),
      ]);
      body.append(table([label, "Комментарий", ""], rows, "Список пуст."));
    }
  }

  function renderAll() {
    renderTabs();
    renderBody();
  }

  const validateBtn = button("Проверить", () => {
    clear(result);
    busy(validateBtn, api("/api/config/validate", { files: draftFiles() })).then((data) => {
      result.append(checkView(data));
    }, report);
  });
  const applyBtn = button("Применить", () => {
    if (!changed()) {
      toast("Изменений нет");
      return;
    }
    clear(result);
    const sent = draftFiles();
    busy(applyBtn, api("/api/config/apply", { files: sent, etag: config.etag })).then((data) => {
      result.append(applyResult(data));
      if (data.ok) {
        toast(data.message || "Применено", "ok");
        if (Object.prototype.hasOwnProperty.call(sent, "sameport")) sameUsesBuiltin = false;
        for (const [kind] of LIST_TABS) original[kind] = drafts[kind];
        config.etag = null;
        api("/api/config").then((fresh) => {
          config.etag = fresh.etag;
        }, report);
        renderAll();
      }
    }, report);
  }, "primary");

  const matchInput = h("input", { type: "text", placeholder: "user.auth.xboxlive.com", autocomplete: "off" });
  const matchOut = h("div", {});
  const matchBtn = button("Проверить имя", () => {
    clear(matchOut);
    const payload = { name: matchInput.value.trim(), proxy: drafts.proxy, sameport: drafts.sameport };
    if (!(original.direct === null && drafts.direct === "")) payload.direct = drafts.direct;
    busy(matchBtn, api("/api/diag/match", payload)).then((data) => {
      const verdicts = {
        proxy: ["через прокси, порт 443", "ok"],
        alias: ["через прокси, свой порт", "ok"],
        direct: ["напрямую (закачка)", "warn"],
        none: ["мимо сервера", "muted"],
      };
      const [text, tone] = verdicts[data.alias ? "alias" : data.verdict];
      matchOut.append(
        h("p", {}, h("code", { text: data.name }), " — ", badge(text, tone), data.proxy_rule ? ` правило ${data.proxy_rule}` : "", data.direct_rule ? ` правило закачки ${data.direct_rule}` : "", ` (глубина ${data.depth})`),
      );
    }, report);
  });
  matchInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") matchBtn.click();
  });

  renderAll();
  view.append(
    h("div", { class: "page-head" }, h("h1", { text: "Домены" })),
    card(null, tabs, body),
    card(null, h("div", { class: "row" }, validateBtn, applyBtn, pending), result),
    card("Попадает ли имя", h("p", { class: "muted", text: "Проверка по текущему черновику с учётом MAX_WILDCARD_DEPTH." }), h("div", { class: "row" }, matchInput, matchBtn), matchOut),
  );
}

function checkView(data) {
  const parts = [];
  if (data.errors && Object.keys(data.errors).length) parts.push(errorsBox(data.errors));
  else if (data.ok) parts.push(h("p", { class: "alert ok", text: "Проверка прошла: служба примет эти настройки." }));
  if (data.diff) parts.push(h("h3", { text: "Что изменится" }), diffView(data.diff));
  if (data.check) {
    if (data.check.messages) parts.push(h("h3", { text: "Сообщения проверки" }), pre(data.check.messages));
    if (data.check.plan) parts.push(h("details", {}, h("summary", { text: "План службы (--check-config)" }), pre(JSON.stringify(data.check.plan, null, 2))));
  }
  for (const text of data.warnings || []) parts.push(h("p", { class: "muted", text: `⚠ ${text}` }));
  return h("div", {}, parts);
}

// ---------- Клиенты ----------

async function pageClients(view) {
  const [config, stats] = await Promise.all([api("/api/config"), api("/api/stats")]);
  const original = config.env.ALLOW_CLIENTS;
  let draft = original;
  const list = h("div", {});
  const result = h("div", {});
  const input = h("input", { type: "text", placeholder: "203.0.113.8 или 198.51.100.0/24", autocomplete: "off" });

  function render() {
    clear(list);
    const items = lib.parseCsv(draft);
    if (!items.length) list.append(h("p", { class: "alert warn", text: "Список пуст: DNS и прокси пускают любой адрес из интернета." }));
    list.append(table(["Адрес или сеть", ""], items.map((item) => [h("code", { text: item }), button("Убрать", () => {
      draft = lib.removeCsv(draft, item);
      render();
    }, "small danger")]), ""));
    if (draft !== original) list.append(h("p", { class: "muted", text: "Есть несохранённые изменения." }));
  }

  const add = (value) => {
    const text = String(value || "").trim();
    if (!lib.isIpLike(text)) {
      toast("Нужен IP-адрес или сеть, например 203.0.113.8 или 198.51.100.0/24", "bad");
      return;
    }
    draft = lib.addCsv(draft, text);
    input.value = "";
    render();
  };
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") add(input.value);
  });
  const saveBtn = button("Применить", () => {
    if (draft === original) {
      toast("Изменений нет");
      return;
    }
    if (!draft && !window.confirm("Пустой список пустит всех. Продолжить?")) return;
    clear(result);
    busy(saveBtn, api("/api/config/apply", { env: { ALLOW_CLIENTS: draft }, etag: config.etag })).then((data) => {
      result.append(applyResult(data));
      if (data.ok) renderRoute();
    }, report);
  }, "primary");

  const mine = state.client && !lib.parseCsv(draft).includes(state.client)
    ? h("p", { class: "muted" }, `Вы зашли в панель с адреса `, h("code", { text: state.client }), ". ", button("Добавить его", () => add(state.client), "small"))
    : null;

  const refusedRows = (stats.refused || []).map((item) => [
    h("code", { text: item.client }),
    String(item.count),
    lib.formatTime(item.last, true),
    button("Добавить", () => add(item.client), "small"),
  ]);
  const topRows = (stats.top_clients || []).map(([client, count]) => [h("code", { text: client }), String(count)]);

  render();
  view.append(
    h("div", { class: "page-head" }, h("h1", { text: "Клиенты" })),
    card("ALLOW_CLIENTS", h("p", { class: "muted", text: "Кто может спрашивать DNS и ходить через прокси. Адрес из журнала «Отказ … клиенту» — тот, который нужно добавить." }), mine, h("div", { class: "row" }, input, button("Добавить", () => add(input.value))), list, h("div", { class: "row" }, saveBtn), result),
    card("Отказанные адреса", h("p", { class: "muted", text: `По последним ${stats.lines || 0} строкам журнала.` }), table(["Адрес", "Раз", "Последний", ""], refusedRows, "Отказов нет.")),
    card("Активные клиенты", table(["Адрес", "Запросов"], topRows, "Нет данных.")),
  );
}

// ---------- Настройки ----------

async function pageSettings(view) {
  const [config, presets, backups] = await Promise.all([api("/api/config"), api("/api/presets"), api("/api/config/backups")]);
  const inputs = {};
  const errors = {};
  const result = h("div", {});
  const form = h("div", { class: "form-grid" });
  const portsInfo = h("small", { class: "muted" });

  for (const item of config.fields) {
    const input = h("input", { type: "text", value: config.env[item.key], spellcheck: "false", autocomplete: "off", name: item.key });
    inputs[item.key] = input;
    errors[item.key] = h("small", { class: "error" });
    const extra = [];
    if (item.key === "PROXY_PORTS") {
      extra.push(h("div", { class: "row" }, button("Пресет UFC 5", () => {
        input.value = presets.ufc5_ports;
        updatePorts();
      }, "small ghost"), button("Только 80,443", () => {
        input.value = "80,443";
        updatePorts();
      }, "small ghost"), portsInfo));
      input.addEventListener("input", updatePorts);
    }
    form.append(h("div", { class: "field" }, h("span", { class: "field-label" }, h("code", { text: item.key })), input, h("small", { class: "muted", text: `${item.hint} По умолчанию: ${item.default || "пусто"}.` }), extra, errors[item.key]));
  }

  function updatePorts() {
    const count = lib.countPorts(inputs.PROXY_PORTS.value);
    portsInfo.textContent = count === null ? "" : `портов: ${count}`;
  }
  updatePorts();

  function values() {
    const found = {};
    for (const [key, input] of Object.entries(inputs)) if (input.value.trim() !== config.env[key]) found[key] = input.value.trim();
    return found;
  }

  function showErrors(map) {
    for (const [key, node] of Object.entries(errors)) node.textContent = (map && map[key]) || "";
  }

  const restart = h("input", { type: "checkbox", checked: true });
  const checkBtn = button("Проверить", () => {
    clear(result);
    showErrors({});
    busy(checkBtn, api("/api/config/validate", { env: values() })).then((data) => {
      showErrors(data.errors);
      result.append(checkView(data));
    }, report);
  });
  const applyBtn = button("Применить", () => {
    const env = values();
    if (!Object.keys(env).length) {
      toast("Изменений нет");
      return;
    }
    clear(result);
    showErrors({});
    busy(applyBtn, api("/api/config/apply", { env, etag: config.etag, restart: restart.checked })).then((data) => {
      showErrors(data.errors);
      result.append(applyResult(data));
      if (data.diff) result.append(diffView(data.diff));
      if (data.ok) {
        toast(data.message || "Применено", "ok");
        setTimeout(renderRoute, 1500);
      }
    }, report);
  }, "primary");

  const backupRows = (backups.backups || []).map((item) => [
    lib.backupLabel(item.id),
    item.reason || "",
    button("Вернуть", () => {
      if (!window.confirm(`Вернуть файлы из копии ${lib.backupLabel(item.id)} и перезапустить службу? Текущие файлы сохранятся в новую копию.`)) return;
      api("/api/config/restore", { id: item.id, etag: config.etag }).then((data) => {
        clear(result);
        result.append(applyResult(data));
        if (data.ok) {
          toast(data.message || "Возвращено", "ok");
          setTimeout(renderRoute, 1500);
        }
      }, report);
    }, "small"),
  ]);

  view.append(
    h("div", { class: "page-head" }, h("h1", { text: "Настройки" })),
    card(
      "egress.env",
      h("p", { class: "muted" }, "Файл ", h("code", { text: config.paths.env }), ". Перед записью черновик проверяется самой службой (--check-config), старые файлы копируются. Если служба не поднимется, файлы вернутся."),
      form,
      h("div", { class: "row" }, checkBtn, applyBtn, h("label", { class: "check" }, restart, " перезапустить службу")),
      result,
    ),
    card("Резервные копии", table(["Когда", "Причина", ""], backupRows, "Копий пока нет. Они появляются при каждом применении.")),
  );
}

// ---------- Журнал ----------

async function pageLogs(view) {
  const sources = (state.ui && state.ui.log_sources) || [];
  if (!sources.length) {
    view.append(h("h1", { text: "Журнал" }), card(null, h("p", { class: "muted", text: "Журнал недоступен: управление службой выключено." })));
    return;
  }
  const sourceLabels = { proxy: "Служба", ui: "Web UI", update: "Обновление" };
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  let source = sources.includes(params.get("source")) ? params.get("source") : sources[0];
  const entries = [];
  const filter = { kinds: new Set(), query: "" };
  let paused = false;
  let stream = null;
  const LIMIT = 3000;
  const SHOWN = 600;

  const list = h("div", { class: "log", role: "log" });
  const status = h("span", { class: "muted" });
  const counter = h("span", { class: "muted" });

  function row(entry) {
    return h(
      "div",
      { class: `log-row kind-${entry.kind}` },
      h("span", { class: "log-time", text: lib.formatTime(entry.ts) }),
      h("span", { class: `badge kind-${entry.kind}`, text: lib.KIND_LABELS[entry.kind] || entry.kind }),
      h("span", { class: "log-msg", text: entry.msg }),
    );
  }

  function renderList() {
    clear(list);
    const shown = lib.filterEntries(entries, filter).slice(-SHOWN);
    for (const entry of shown) list.append(row(entry));
    counter.textContent = `показано ${shown.length} из ${entries.length}`;
    list.scrollTop = list.scrollHeight;
  }

  function connect() {
    if (stream) stream.close();
    entries.length = 0;
    renderList();
    status.textContent = "подключение…";
    stream = new EventSource(`/api/logs/stream?source=${encodeURIComponent(source)}&backlog=300`);
    stream.onopen = () => {
      status.textContent = "в эфире";
    };
    stream.onmessage = (event) => {
      let entry;
      try {
        entry = JSON.parse(event.data);
      } catch (error) {
        return;
      }
      lib.pushLimited(entries, entry, LIMIT);
      if (paused || !lib.matchesFilter(entry, filter)) return;
      const stick = list.scrollTop + list.clientHeight >= list.scrollHeight - 40;
      list.append(row(entry));
      while (list.childElementCount > SHOWN) list.firstElementChild.remove();
      if (stick) list.scrollTop = list.scrollHeight;
      counter.textContent = `в списке ${entries.length}`;
    };
    stream.addEventListener("logout", () => {
      stream.close();
      showLogin("Сессия закончилась. Войдите снова.");
    });
    stream.addEventListener("end", () => {
      status.textContent = "поток закончился";
      stream.close();
    });
    stream.onerror = () => {
      status.textContent = "нет связи, переподключение…";
    };
  }
  onCleanup(() => stream && stream.close());

  const kinds = h(
    "div",
    { class: "row chips" },
    Object.entries(lib.KIND_LABELS).map(([kind, label]) => {
      const box = h("input", { type: "checkbox" });
      box.addEventListener("change", () => {
        if (box.checked) filter.kinds.add(kind);
        else filter.kinds.delete(kind);
        renderList();
      });
      return h("label", { class: `chip kind-${kind}` }, box, ` ${label}`);
    }),
  );
  const search = h("input", { type: "search", placeholder: "поиск: клиент, домен, порт, текст" });
  let searchTimer = 0;
  search.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      filter.query = search.value;
      renderList();
    }, 200);
  });
  const pauseBtn = button("Пауза", () => {
    paused = !paused;
    pauseBtn.textContent = paused ? "Продолжить" : "Пауза";
    if (!paused) renderList();
  });
  const sourceSelect = select(sources.map((key) => [key, sourceLabels[key] || key]), source, () => {
    source = sourceSelect.value;
    connect();
  });

  view.append(
    h("div", { class: "page-head" }, h("h1", { text: "Журнал" }), status),
    card(
      null,
      h("div", { class: "row" }, field("Источник", sourceSelect), search, pauseBtn, button("Очистить", () => {
        entries.length = 0;
        renderList();
      }, "ghost"), counter),
      kinds,
      list,
    ),
  );
  connect();
}

// ---------- Файрвол ----------

async function pageFirewall(view) {
  const data = await api("/api/firewall");
  view.append(h("div", { class: "page-head" }, h("h1", { text: "Файрвол" }), button("Обновить", renderRoute, "ghost")));
  if (!data.available) {
    view.append(card("ufw недоступен", h("p", { text: data.error || "Нет данных" }), h("p", { class: "muted", text: "Правила на хосте задаются вручную, например:" }), pre("ufw allow OpenSSH\nufw allow 53\nufw allow 80/tcp\nufw allow 443/tcp\nufw allow 44400:44463/tcp\nufw enable")));
    return;
  }
  const output = h("div", {});
  const showSteps = (result) => {
    clear(output);
    const steps = result.steps || [{ command: result.command, ok: result.ok, output: result.output }];
    output.append(h("div", { class: `alert ${result.ok ? "ok" : "bad"}` }, steps.map((step) => h("div", {}, h("code", { text: `$ ${step.command}` }), pre(step.output)))));
  };

  const statusCard = card(
    "Состояние",
    h("div", { class: "status-line" }, badge(data.active ? "включён" : "выключен", data.active ? "ok" : "bad"), h("span", { class: "muted", text: data.defaults || "" })),
    h("p", { class: "muted", text: `Порты службы: DNS ${data.service.dns_port}, прокси ${data.service.proxy_ports}${data.service.alias_ports ? `, свои порты сайтов ${data.service.alias_ports}` : ""}. Клиенты: ${data.service.clients || "все"}. Защищённые порты (SSH и UI): ${(data.protected_ports || []).join(", ")}.` }),
    data.active
      ? null
      : button("Включить ufw", () => {
        if (!window.confirm(`Перед включением будет открыт SSH (${(data.ssh_ports || []).join(", ")}). Включить?`)) return;
        api("/api/firewall/enable", {}).then((result) => {
          showSteps(result);
          renderRoute();
        }, report);
      }, "primary"),
  );

  const rows = (data.rules || []).map((rule) => [
    String(rule.num),
    h("code", { text: rule.to }),
    badge(`${rule.action} ${rule.direction}`, rule.action === "ALLOW" ? "ok" : "bad"),
    rule.source,
    rule.comment,
    rule.protected
      ? h("span", { class: "muted", title: "Правило для SSH или Web UI", text: "защищено" })
      : button("Удалить", () => {
        if (!window.confirm(`Удалить правило [${rule.num}] ${rule.raw}?`)) return;
        api("/api/firewall/delete", { num: rule.num, rule: rule.raw }).then((result) => {
          showSteps(result);
          renderRoute();
        }, report);
      }, "small danger"),
  ]);

  const action = select([["allow", "allow"], ["deny", "deny"], ["reject", "reject"], ["limit", "limit"]], "allow");
  const port = h("input", { type: "text", placeholder: "443 или 15000-15099" });
  const proto = select([["tcp", "tcp"], ["udp", "udp"], ["any", "tcp+udp"]], "tcp");
  const source = h("input", { type: "text", placeholder: "any или 203.0.113.8", value: "any" });
  const comment = h("input", { type: "text", value: "egress-ui" });
  const addBtn = button("Добавить правило", () => {
    busy(addBtn, api("/api/firewall/rule", { action: action.value, port: port.value.trim(), proto: proto.value, source: source.value.trim(), comment: comment.value.trim() })).then((result) => {
      showSteps(result);
      if (result.ok) renderRoute();
    }, report);
  }, "primary");

  const planOut = h("div", {});
  const planFor = (mode) => {
    clear(planOut);
    api("/api/firewall/plan", { mode }).then((plan) => {
      const nothing = !plan.add.length && !plan.delete.length;
      planOut.append(
        h("h3", { text: mode === "all" ? "Открыть порты службы для всех" : "Порты службы только для ALLOW_CLIENTS" }),
        nothing ? h("p", { class: "alert ok", text: "Правила уже такие. Делать нечего." }) : null,
        plan.add.length ? h("div", {}, h("p", { text: "Будут добавлены:" }), pre(plan.add.join("\n"))) : null,
        plan.delete.length ? h("div", {}, h("p", { text: "Будут удалены:" }), pre(plan.delete.map((item) => `[${item.num}] ${item.rule}`).join("\n"))) : null,
        nothing ? null : button("Выполнить", () => {
          if (!window.confirm("Выполнить эти команды ufw?")) return;
          api("/api/firewall/mode", { mode }).then((result) => {
            showSteps(result);
            renderRoute();
          }, report);
        }, "primary"),
      );
    }, (error) => {
      planOut.append(h("p", { class: "alert bad", text: errorText(error) }));
    });
  };

  view.append(
    h("div", { class: "grid2" }, statusCard, card("Режимы", h("p", { class: "muted", text: "Сначала покажу команды, потом выполню по кнопке." }), h("div", { class: "row" }, button("Для всех", () => planFor("all")), button("Только клиенты", () => planFor("clients"))), planOut)),
    output,
    card("Правила", table(["№", "Куда", "Действие", "Откуда", "Комментарий", ""], rows, "Правил нет.")),
    card("Новое правило", h("div", { class: "row" }, field("Действие", action), field("Порт", port), field("Протокол", proto), field("Откуда", source), field("Комментарий", comment)), addBtn),
  );
}

// ---------- Обслуживание ----------

async function pageMaintenance(view) {
  const dnsName = h("input", { type: "text", value: "user.auth.xboxlive.com", autocomplete: "off" });
  const dnsType = select([["A", "A"], ["AAAA", "AAAA"], ["HTTPS", "HTTPS"]], "A");
  const dnsOut = h("div", {});
  const dnsBtn = button("Спросить", () => {
    clear(dnsOut);
    busy(dnsBtn, api("/api/diag/dns", { name: dnsName.value.trim(), type: dnsType.value })).then((data) => {
      if (!data.ok) {
        dnsOut.append(h("p", { class: "alert bad", text: data.error }));
        return;
      }
      dnsOut.append(h("dl", { class: "facts" }, fact("Код", data.rcode), fact("Ответ", data.answers.join(", ") || "пусто"), fact("TTL", data.ttl.join(", ")), data.cname ? fact("CNAME", data.cname) : null, fact("Время", `${data.ms} мс`)));
    }, report);
  });

  const portsOut = h("div", {});
  const portsBtn = button("Проверить порты", () => {
    clear(portsOut);
    busy(portsBtn, api("/api/diag/ports", {})).then((data) => {
      const bad = data.ports.filter((item) => !item.ok);
      portsOut.append(
        h("p", { class: `alert ${bad.length ? "bad" : "ok"}`, text: bad.length ? `Не отвечают: ${bad.map((item) => item.port).join(", ")}` : `Все ${data.ports.length} портов принимают TCP на 127.0.0.1.` }),
        h("details", {}, h("summary", { text: "Подробно" }), table(["Порт", "Итог", ""], data.ports.map((item) => [String(item.port), item.ok ? badge("открыт", "ok") : badge("закрыт", "bad"), item.ok ? `${item.ms} мс` : item.error]))),
      );
    }, report);
  });

  const versionBox = h("div", {});
  const updateLog = h("pre", { class: "output log-pre" });
  const updateStatus = h("p", { class: "muted" });
  let pollTimer = 0;
  onCleanup(() => clearTimeout(pollTimer));

  function renderInfo(info) {
    clear(versionBox);
    if (!info.available) {
      versionBox.append(h("p", { class: "muted", text: info.error || "Нет данных о версии" }));
    } else {
      versionBox.append(
        h(
          "dl",
          { class: "facts" },
          fact("Ветка", info.branch),
          fact("Коммит", `${info.short || ""} ${info.subject || ""}`),
          fact("Дата", info.date),
          fact("Каталог", info.repo),
          fact("Локальные правки", info.dirty ? "есть" : "нет"),
          info.behind !== undefined ? fact("Новых коммитов", info.behind ?? "—") : null,
          fact("Установлен тот же код", info.installed_matches ? "да" : "нет"),
        ),
      );
    }
    if (info.incoming && info.incoming.length) versionBox.append(h("h3", { text: "Придёт с обновлением" }), pre(info.incoming.join("\n")));
    if (info.fetch_ok === false) versionBox.append(h("p", { class: "alert bad", text: `git fetch: ${info.fetch_output}` }));
  }

  function poll(started) {
    api("/api/update/status").then((data) => {
      updateLog.textContent = (data.entries || []).map((item) => `${lib.formatTime(item.ts)} ${item.msg}`).join("\n");
      updateLog.scrollTop = updateLog.scrollHeight;
      const finished = lib.updateFinished(data.entries || []);
      const running = data.state === "active" || data.state === "activating";
      updateStatus.textContent = finished === "ok" ? "Обновление завершено." : finished === "fail" ? "Обновление не удалось." : running ? "Идёт обновление…" : `Состояние: ${data.state}`;
      if (!finished && (running || Date.now() - started < 15000)) pollTimer = setTimeout(() => poll(started), 2000);
    }, (error) => {
      if (error instanceof ApiError && error.status === 401) return;
      updateStatus.textContent = "Нет связи: UI, вероятно, перезапускается…";
      pollTimer = setTimeout(() => poll(started), 3000);
    });
  }

  const fetchBtn = button("Проверить обновления", () => {
    busy(fetchBtn, api("/api/update/fetch", {})).then(renderInfo, report);
  });
  const updateBtn = button("Обновить", () => {
    if (!window.confirm("Скачать новую версию и перезапустить службу и UI? В конце панель попросит войти снова.")) return;
    busy(updateBtn, api("/api/update/start", {})).then((data) => {
      if (!data.ok) {
        toast(data.error || data.output || "Не запустилось", "bad");
        return;
      }
      toast("Обновление запущено", "ok");
      poll(Date.now());
    }, report);
  }, "primary");

  const supported = state.ui && state.ui.update;
  const access = state.ui && state.ui.access;
  view.append(
    h("div", { class: "page-head" }, h("h1", { text: "Обслуживание" })),
    access && access.mode === "tunnel"
      ? card("Доступ через SSH-туннель", tunnelHint(access), h("p", { class: "muted", text: "Включить HTTPS на внешнем адресе: повторно запустите sh deploy/install-ui.sh и выберите HTTPS." }))
      : null,
    h(
      "div",
      { class: "grid2" },
      card("DNS-запрос к своему серверу", h("div", { class: "row" }, dnsName, dnsType, dnsBtn), dnsOut),
      card("Порты службы", h("p", { class: "muted", text: "TCP-подключение к DNS и портам прокси на 127.0.0.1." }), portsBtn, portsOut),
    ),
    card(
      "Версия и обновление",
      versionBox,
      supported
        ? h("div", {}, h("div", { class: "row" }, fetchBtn, updateBtn), h("p", { class: "muted", text: "Обновление: git pull --ff-only, проверка нового кода, перезапуск службы (при ошибке — откат), затем перезапуск UI." }), updateStatus, updateLog)
        : h("p", { class: "muted", text: "Обновление из панели работает только при установке через systemd. В Docker: git pull && docker compose up -d --build." }),
    ),
  );
  try {
    renderInfo(await api("/api/update"));
  } catch (error) {
    report(error);
  }
  if (supported) {
    api("/api/update/status").then((data) => {
      if (data.state === "active" || data.state === "activating") poll(Date.now());
    }, () => {});
  }
}

const ROUTES = {
  overview: pageOverview,
  domains: pageDomains,
  clients: pageClients,
  settings: pageSettings,
  logs: pageLogs,
  firewall: pageFirewall,
  maintenance: pageMaintenance,
};

async function boot() {
  try {
    const response = await fetch("/api/session", { credentials: "same-origin", cache: "no-store" });
    const data = await response.json();
    state.access = data.access || null;
    if (data.authenticated) {
      state.csrf = data.csrf;
      state.ui = data.ui;
      state.client = data.client || "";
      startApp();
      return;
    }
  } catch (error) {
    showLogin("Нет связи с сервером");
    return;
  }
  showLogin();
}

boot();
