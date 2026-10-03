// Smoke tests for extension/lib.js filtering: minimization, expired
// pruning, big-three exclusion. Run with: node tests/test_lib.mjs
import {
  selectCookies, baseDomain, isBigThree, looksLikeSession, isExpired,
  DEFAULT_SETTINGS
} from "../extension/lib.js";

let failures = 0;
const ok = (cond, name) => {
  if (!cond) { console.error("FAIL:", name); failures++; }
  else console.log("ok:", name);
};

const C = (name, domain, extra = {}) =>
  ({ name, value: "v", domain, path: "/", ...extra });

const jar = [
  C("sessionid", ".example.com", { httpOnly: true }),
  C("_ga", ".example.com"),
  C("prefs", ".example.com"),
  C("auth_token", "api.example.com", { httpOnly: true }),
  C("old", ".example.com", { expirationDate: 1000 }),          // long expired
  C("SID", ".google.com", { httpOnly: true }),                 // big three
];

ok(baseDomain("a.b.example.co.uk") === "example.co.uk", "baseDomain ccTLD");
ok(isBigThree("mail.google.com") && isBigThree("x.com") && !isBigThree("example.com"), "isBigThree");
ok(looksLikeSession(C("sessionid", "x", { httpOnly: true })), "looksLikeSession httpOnly");
ok(looksLikeSession(C("remember_me", "x")), "looksLikeSession name");
ok(!looksLikeSession(C("_ga", "x")), "looksLikeSession tracking");
ok(isExpired(C("old", "x", { expirationDate: 1000 })), "isExpired");
ok(!isExpired(C("s", "x", { expirationDate: 9999999999 })), "not expired");

let r = selectCookies(jar, { ...DEFAULT_SETTINGS }, null);
ok(r.cookies.length === 4 && r.summary.skipped_expired === 1 && r.summary.skipped_big_three === 1,
  "default: expired + big three held back, got " + r.cookies.length);

r = selectCookies(jar, { ...DEFAULT_SETTINGS, minimizeSessions: true }, null);
const names = r.cookies.map((c) => c.name).sort();
ok(r.cookies.length === 2 && names.join(",") === "auth_token,sessionid",
  "minimize: only session cookies, got " + names.join(","));
ok(r.summary.skipped_not_session === 2, "minimize: skipped_not_session counted");

r = selectCookies(jar, { ...DEFAULT_SETTINGS, mode: "include", domains: ["example.com"] }, null);
ok(r.cookies.every((c) => baseDomain(c.domain) === "example.com"), "include mode");

if (failures) process.exit(1);
console.log("lib: all pass");
