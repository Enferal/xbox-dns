import assert from "node:assert/strict";
import test from "node:test";

import * as lib from "../../scripts/egress_ui/static/lib.js";

test("parseList сохраняет номер строки и комментарий", () => {
  const items = lib.parseList("# шапка\nxboxlive.com\n\n  ea.com  # EA\r\n");
  assert.deepEqual(items, [
    { line: 1, value: "xboxlive.com", comment: "" },
    { line: 3, value: "ea.com", comment: "EA" },
  ]);
});

test("removeEntry убирает только нужную строку", () => {
  const text = "# Xbox\nxboxlive.com\nxbox.com # магазин\n# xbox.com старое\n";
  assert.equal(lib.removeEntry(text, "XBOX.com"), "# Xbox\nxboxlive.com\n# xbox.com старое\n");
});

test("addEntry не дублирует и дописывает перевод строки", () => {
  assert.deepEqual(lib.addEntry("a.com", "b.com", "тест"), { text: "a.com\nb.com  # тест\n", added: true });
  assert.deepEqual(lib.addEntry("a.com\n", "A.com."), { text: "a.com\n", added: false });
  assert.deepEqual(lib.addEntry("", "a.com"), { text: "a.com\n", added: true });
});

test("normalizeDomain", () => {
  assert.equal(lib.normalizeDomain("https://Www.Example.com:443/path?q"), "www.example.com");
  assert.equal(lib.normalizeDomain("*.xboxlive.com."), "xboxlive.com");
  assert.equal(lib.normalizeDomain("xn--e1afmkfd.xn--p1ai"), "xn--e1afmkfd.xn--p1ai");
  assert.equal(lib.normalizeDomain("com"), null);
  assert.equal(lib.normalizeDomain("1.2.3.4"), null);
  assert.equal(lib.normalizeDomain("bad_name.com"), null);
  assert.equal(lib.normalizeDomain(""), null);
});

test("isIpLike", () => {
  for (const ok of ["203.0.113.8", "198.51.100.0/24", "2001:db8::1", "2001:db8::/32", "::1"]) assert.ok(lib.isIpLike(ok), ok);
  for (const bad of ["256.1.1.1", "1.2.3.4/33", "example.com", "1.2.3", "2001:db8::/129", "1::2::3", ""]) assert.ok(!lib.isIpLike(bad), bad);
});

test("csv", () => {
  assert.deepEqual(lib.parseCsv(" a, ,b,"), ["a", "b"]);
  assert.equal(lib.addCsv("a,b", "c"), "a,b,c");
  assert.equal(lib.addCsv("a,b", "a"), "a,b");
  assert.equal(lib.addCsv("", "a"), "a");
  assert.equal(lib.removeCsv("a, b,c", "b"), "a,c");
});

test("formatUptime", () => {
  assert.equal(lib.formatUptime(null), "—");
  assert.equal(lib.formatUptime(5), "5 с");
  assert.equal(lib.formatUptime(125), "2 мин 5 с");
  assert.equal(lib.formatUptime(3 * 3600 + 120), "3 ч 2 мин");
  assert.equal(lib.formatUptime(2 * 86400 + 3 * 3600 + 59), "2 д 3 ч");
});

test("backupLabel", () => {
  assert.equal(lib.backupLabel("20261023-021500"), "2026-10-23 02:15:00");
  assert.equal(lib.backupLabel("20261023-021500-2"), "2026-10-23 02:15:00 (2)");
  assert.equal(lib.backupLabel("x"), "x");
});

test("фильтр журнала по виду и поиску", () => {
  const entries = [
    { kind: "dns", msg: "DNS a.xboxlive.com A", client: "10.0.0.1", domain: "a.xboxlive.com", port: null },
    { kind: "proxy", msg: "Прокси a.ea.com:443", client: "10.0.0.2", domain: "a.ea.com", port: 443 },
    { kind: "refused", msg: "Отказ DNS клиенту 1.2.3.4", client: "1.2.3.4", domain: "", port: null },
  ];
  assert.equal(lib.filterEntries(entries, { kinds: new Set(), query: "" }).length, 3);
  assert.deepEqual(lib.filterEntries(entries, { kinds: new Set(["proxy", "refused"]), query: "" }).map((e) => e.kind), ["proxy", "refused"]);
  assert.deepEqual(lib.filterEntries(entries, { kinds: new Set(), query: "10.0.0.2 443" }).map((e) => e.kind), ["proxy"]);
  assert.deepEqual(lib.filterEntries(entries, { kinds: new Set(), query: "XBOXLIVE" }).map((e) => e.kind), ["dns"]);
});

test("pushLimited и прочее", () => {
  const list = [1, 2, 3];
  lib.pushLimited(list, 4, 3);
  assert.deepEqual(list, [2, 3, 4]);
  assert.equal(lib.diffLineClass("+++ a"), "diff-file");
  assert.equal(lib.diffLineClass("+x"), "diff-add");
  assert.equal(lib.diffLineClass("-x"), "diff-del");
  assert.equal(lib.diffLineClass("@@ -1 +1 @@"), "diff-hunk");
  assert.equal(lib.serviceTone("active"), "ok");
  assert.equal(lib.serviceTone("failed"), "bad");
  assert.equal(lib.countPorts("80,443,15000-15099"), 102);
  assert.equal(lib.countPorts("80,x"), null);
  assert.equal(lib.updateFinished([{ msg: "Обновление egress-proxy: начало" }, { msg: "Обновление завершено" }]), "ok");
  assert.equal(lib.updateFinished([{ msg: "Обновление не удалось" }]), "fail");
  assert.equal(lib.updateFinished([{ msg: "идёт" }]), "");
});
