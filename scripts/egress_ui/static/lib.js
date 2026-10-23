// Логика без DOM: списки, форматирование, фильтр журнала. Проверяется node --test.

export const KIND_LABELS = {
  dns: "DNS",
  proxy: "Прокси",
  direct: "Напрямую",
  refused: "Отказ",
  error: "Ошибка",
  tcp: "TCP",
  trace: "Пакет DNS",
  other: "Прочее",
};

const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function splitLine(raw) {
  const index = raw.indexOf("#");
  const body = index >= 0 ? raw.slice(0, index) : raw;
  const comment = index >= 0 ? raw.slice(index + 1).trim() : "";
  return { value: body.trim(), comment };
}

export function parseList(text) {
  const found = [];
  String(text || "")
    .split(/\r?\n/)
    .forEach((raw, index) => {
      const { value, comment } = splitLine(raw);
      if (value) found.push({ line: index, value, comment });
    });
  return found;
}

export function listValues(text) {
  return parseList(text).map((item) => item.value);
}

function sameValue(left, right) {
  return left.toLowerCase().replace(/\.$/, "") === right.toLowerCase().replace(/\.$/, "");
}

export function removeEntry(text, value) {
  const lines = String(text || "").split(/\r?\n/);
  const kept = lines.filter((raw) => {
    const { value: token } = splitLine(raw);
    return !token || !sameValue(token, value);
  });
  return kept.join("\n");
}

export function addEntry(text, value, comment = "") {
  const source = String(text || "");
  if (listValues(source).some((item) => sameValue(item, value))) {
    return { text: source, added: false };
  }
  const line = comment ? `${value}  # ${comment}` : value;
  const base = source.replace(/\s*$/, "");
  return { text: (base ? `${base}\n` : "") + `${line}\n`, added: true };
}

// Принимает «https://Www.Example.com/path», «*.example.com.» и т. п.
export function normalizeDomain(input) {
  let text = String(input || "").trim().toLowerCase();
  text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  text = text.split(/[/?#]/, 1)[0];
  text = text.replace(/:\d+$/, "");
  while (text.startsWith("*.")) text = text.slice(2);
  text = text.replace(/\.$/, "");
  if (!text || text.length > 253 || !text.includes(".")) return null;
  if (/^[0-9.]+$/.test(text) || text.includes(":")) return null;
  const labels = text.split(".");
  return labels.every((label) => LABEL_RE.test(label) || /^xn--[a-z0-9-]+$/.test(label)) ? text : null;
}

export function isIpLike(value) {
  const text = String(value || "").trim();
  const v4 = /^(\d{1,3})(\.\d{1,3}){3}(\/\d{1,2})?$/;
  if (v4.test(text)) {
    const [address, prefix] = text.split("/");
    const okOctets = address.split(".").every((part) => Number(part) <= 255);
    return okOctets && (prefix === undefined || Number(prefix) <= 32);
  }
  const [address, prefix, extra] = text.split("/");
  if (extra !== undefined || !address.includes(":") || !/^[0-9a-fA-F:.]+$/.test(address)) return false;
  if ((address.match(/::/g) || []).length > 1) return false;
  return prefix === undefined || (/^\d{1,3}$/.test(prefix) && Number(prefix) <= 128);
}

export function parseCsv(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function addCsv(value, item) {
  const items = parseCsv(value);
  if (items.includes(item)) return items.join(",");
  items.push(item);
  return items.join(",");
}

export function removeCsv(value, item) {
  return parseCsv(value)
    .filter((entry) => entry !== item)
    .join(",");
}

export function formatUptime(seconds) {
  if (seconds === null || seconds === undefined || !Number.isFinite(Number(seconds))) return "—";
  let rest = Math.max(0, Math.floor(Number(seconds)));
  const days = Math.floor(rest / 86400);
  rest %= 86400;
  const hours = Math.floor(rest / 3600);
  rest %= 3600;
  const minutes = Math.floor(rest / 60);
  const secs = rest % 60;
  if (days) return `${days} д ${hours} ч`;
  if (hours) return `${hours} ч ${minutes} мин`;
  if (minutes) return `${minutes} мин ${secs} с`;
  return `${secs} с`;
}

function pad(number) {
  return String(number).padStart(2, "0");
}

export function formatTime(ts, withDate = false) {
  if (!ts) return "";
  const date = new Date(Number(ts) * 1000);
  const time = `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  if (!withDate) return time;
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${time}`;
}

export function backupLabel(id) {
  const match = /^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})(?:-(\d+))?$/.exec(String(id || ""));
  if (!match) return String(id || "");
  const [, y, mo, d, h, mi, s, n] = match;
  return `${y}-${mo}-${d} ${h}:${mi}:${s}${n ? ` (${n})` : ""}`;
}

export function matchesFilter(entry, filter) {
  if (filter.kinds && filter.kinds.size && !filter.kinds.has(entry.kind)) return false;
  const query = String(filter.query || "").trim().toLowerCase();
  if (!query) return true;
  const haystack = [entry.msg, entry.client, entry.domain, entry.port === null ? "" : entry.port]
    .map((item) => String(item ?? "").toLowerCase())
    .join(" ");
  return query.split(/\s+/).every((word) => haystack.includes(word));
}

export function filterEntries(entries, filter) {
  return entries.filter((entry) => matchesFilter(entry, filter));
}

export function pushLimited(list, item, limit) {
  list.push(item);
  if (list.length > limit) list.splice(0, list.length - limit);
  return list;
}

export function diffLineClass(line) {
  if (line.startsWith("+++") || line.startsWith("---")) return "diff-file";
  if (line.startsWith("@@")) return "diff-hunk";
  if (line.startsWith("+")) return "diff-add";
  if (line.startsWith("-")) return "diff-del";
  return "";
}

export function serviceTone(state) {
  if (state === "active") return "ok";
  if (state === "activating" || state === "reloading" || state === "deactivating") return "warn";
  if (state === "failed") return "bad";
  return "muted";
}

export function countPorts(spec) {
  let total = 0;
  for (const token of parseCsv(spec)) {
    const [left, right] = token.split("-").map((part) => Number(part.trim()));
    if (!Number.isInteger(left)) return null;
    if (right === undefined) total += 1;
    else if (Number.isInteger(right) && right >= left) total += right - left + 1;
    else return null;
  }
  return total;
}

export function updateFinished(entries) {
  for (let index = entries.length - 1; index >= 0; index -= 1) {
    const message = String(entries[index].msg || "");
    if (message.includes("Обновление завершено")) return "ok";
    if (message.includes("Обновление не удалось")) return "fail";
  }
  return "";
}
