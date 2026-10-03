// Cookie Sync Plus. Reads the cookies Chrome holds, applies the rules from
// the settings page (which sites, how recent, session-only, never Google,
// Meta or X), optionally seals them with AES-256-GCM, and hands the list to
// the native host on this computer, which writes it to a local folder.
// Nothing leaves this machine from here.
//
// Exports run on the schedule, on a click of the toolbar icon, on demand
// (drop sync-request.flag in the sync folder, polled about once a minute)
// and, when instant sync is on, shortly after a sign-in cookie changes on a
// site the rules allow. The badge shows the count from the last export, or
// ! when the host could not be reached.
//
// The loop is closed on the agent side: after injecting, the agent writes
// inject.meta.json, the bot's sync job copies it back into this folder as
// agent-health.json, and the host hands it back here on poll_health. The
// settings page shows whether the bot is actually staying signed in.

import {
  loadSettings,
  selectCookies,
  recentDomainSet,
  cookieAllowed,
  baseDomain,
  looksLikeSession,
  DEFAULT_SETTINGS
} from "./lib.js";
import { encryptCookies, ENC_FORMAT } from "./crypto.js";

const NATIVE_HOST = "com.cookiesyncplus.host";
const ALARM = "cookie-sync-plus";
const POLL_ALARM = "cookie-sync-plus-poll";
const INSTANT_ALARM = "cookie-sync-plus-instant";
const INSTANT_DELAY_MS = 30 * 1000;       // settle time after a sign-in cookie changes
const INSTANT_MIN_GAP_MS = 2 * 60 * 1000; // at most one change-driven export per 2 minutes
const ACTIVITY_KEEP_MS = 180 * 86400000;  // the cookie-change ledger keeps 180 days
const ACTIVITY_MAX = 5000;
const HEALTH_POLL_MS = 10 * 60 * 1000;    // ask the host for agent health at most every 10 minutes

function shape(c) {
  return {
    name: c.name,
    value: c.value,
    domain: c.domain,
    host_key: c.domain,
    path: c.path,
    expires: c.expirationDate ?? null,
    secure: c.secure,
    httpOnly: c.httpOnly,
    httponly: c.httpOnly,
    sameSite: c.sameSite,
    samesite: c.sameSite,
    session: c.session,
    storeId: c.storeId
  };
}

async function setBadge(ok, text, title) {
  await chrome.action.setBadgeBackgroundColor({ color: ok ? "#1f7a4d" : "#a33a3a" });
  await chrome.action.setBadgeText({ text });
  if (title) await chrome.action.setTitle({ title });
}

// A stable fingerprint of the export, so the scheduled run can skip
// rewriting (and re-syncing) a cookie jar that has not changed.
async function exportHash(shaped) {
  const canon = JSON.stringify(
    shaped.map((c) => [c.name, c.domain, c.path, c.value, c.expires ?? 0, c.secure, c.httpOnly])
  );
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canon));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function exportCookies(reason) {
  const settings = await loadSettings();
  const all = await chrome.cookies.getAll({});
  const recent = await recentDomainSet(settings.recentDays);
  const { cookies, summary } = selectCookies(all, settings, recent);
  const shaped = cookies.map(shape);
  const sealed = Boolean(settings.passphrase);

  const record = (ok, detail, extra) => ({
    at: new Date().toISOString(),
    count: shaped.length,
    sites: summary.sites,
    total: all.length,
    reason,
    sealed,
    ok,
    detail,
    ...(extra || {})
  });

  // The schedule is only a heartbeat: if nothing changed, do not touch the
  // files, so the bot's pull job has nothing new to copy and inject.
  if (reason === "alarm") {
    const hash = await exportHash(shaped);
    const { last_export_hash } = await chrome.storage.local.get("last_export_hash");
    if (hash && hash === last_export_hash) {
      await chrome.storage.local.set({ last_export: record(true, "unchanged", { unchanged: true }) });
      const when = new Date().toLocaleTimeString();
      await setBadge(true, String(shaped.length),
        "Cookie Sync Plus: " + shaped.length + " cookies from " + summary.sites + " sites, unchanged at " + when + ". Click to export now.");
      return { ok: true, unchanged: true };
    }
  }

  let payload;
  if (sealed) {
    const envelope = await encryptCookies(shaped, settings.passphrase);
    payload = {
      format: ENC_FORMAT,
      reason,
      exported_at: new Date().toISOString(),
      cookie_count: shaped.length,
      total_in_chrome: all.length,
      filter: summary,
      payload: envelope
    };
  } else {
    payload = {
      format: "cookiesync-plain",
      reason,
      exported_at: new Date().toISOString(),
      cookie_count: shaped.length,
      total_in_chrome: all.length,
      filter: summary,
      cookies: shaped
    };
  }

  try {
    const response = await chrome.runtime.sendNativeMessage(NATIVE_HOST, payload);
    const ok = Boolean(response && response.ok);
    const hash = await exportHash(shaped);
    await chrome.storage.local.set({
      last_export: record(ok, response || null),
      last_export_hash: ok ? hash : undefined
    });
    const when = new Date(payload.exported_at).toLocaleTimeString();
    await setBadge(
      ok,
      ok ? String(payload.cookie_count) : "!",
      ok
        ? "Cookie Sync Plus: " + payload.cookie_count + " cookies from " + summary.sites + " sites at " + when +
          (sealed ? " (sealed)." : ".") + " Click to export now."
        : "Cookie Sync Plus: the native host answered with an error. Click to retry."
    );
    return response;
  } catch (err) {
    await chrome.storage.local.set({ last_export: record(false, String(err)) });
    await setBadge(false, "!", "Cookie Sync Plus: could not reach the native host. Register it, then click to retry.");
    throw err;
  }
}

async function pollRequest() {
  try {
    const response = await chrome.runtime.sendNativeMessage(NATIVE_HOST, { cmd: "poll_request" });
    if (response && response.export) {
      await exportCookies("request");
    }
  } catch (_) {}
}

// Closed loop: the agent's sync job copies inject.meta.json back into the
// sync folder as agent-health.json; the host hands it to us here. Throttled
// so we are not spawning the host every minute.
async function pollHealth() {
  const { last_health_check } = await chrome.storage.local.get("last_health_check");
  if (last_health_check && Date.now() - last_health_check < HEALTH_POLL_MS) return;
  try {
    const response = await chrome.runtime.sendNativeMessage(NATIVE_HOST, { cmd: "poll_health" });
    if (response && response.ok) {
      await chrome.storage.local.set({
        agent_health: response.health || null,
        last_health_check: Date.now()
      });
    }
  } catch (_) {}
}

async function ensureAlarms(force) {
  const settings = await loadSettings();
  const every = Math.max(1, Number(settings.everyMinutes) || DEFAULT_SETTINGS.everyMinutes);
  const existing = await chrome.alarms.get(ALARM);
  if (force || !existing || existing.periodInMinutes !== every) {
    await chrome.alarms.create(ALARM, { periodInMinutes: every });
  }
  if (!(await chrome.alarms.get(POLL_ALARM))) {
    await chrome.alarms.create(POLL_ALARM, { periodInMinutes: 1 });
  }
}

// --- the cookie-change ledger (which sites are in use) and instant sync ---

const pendingActivity = new Map();
let flushTimer = null;

function noteActivity(domain) {
  pendingActivity.set(baseDomain(domain), Date.now());
  if (flushTimer) return;
  flushTimer = setTimeout(flushActivity, 2000);
}

async function flushActivity() {
  flushTimer = null;
  if (!pendingActivity.size) return;
  const { activity } = await chrome.storage.local.get("activity");
  const next = { ...(activity || {}) };
  for (const [d, t] of pendingActivity) next[d] = t;
  pendingActivity.clear();
  const cutoff = Date.now() - ACTIVITY_KEEP_MS;
  let entries = Object.entries(next).filter(([, t]) => t >= cutoff);
  if (entries.length > ACTIVITY_MAX) {
    entries.sort((a, b) => b[1] - a[1]);
    entries = entries.slice(0, ACTIVITY_MAX);
  }
  await chrome.storage.local.set({ activity: Object.fromEntries(entries) });
}

async function scheduleInstant() {
  if (await chrome.alarms.get(INSTANT_ALARM)) return;
  const { last_export } = await chrome.storage.local.get("last_export");
  const lastAt = last_export && last_export.at ? Date.parse(last_export.at) : 0;
  const when = Math.max(Date.now() + INSTANT_DELAY_MS, lastAt + INSTANT_MIN_GAP_MS);
  await chrome.alarms.create(INSTANT_ALARM, { when });
}

chrome.cookies.onChanged.addListener(async ({ cookie, cause }) => {
  if (!cookie || !cookie.domain) return;
  noteActivity(cookie.domain);
  if (cause !== "explicit" && cause !== "overwrite") return;
  if (!looksLikeSession(cookie)) return;
  const settings = await loadSettings();
  if (!settings.instantSync) return;
  if (!cookieAllowed(cookie, settings, null)) return;
  await scheduleInstant();
});

// --- lifecycle ---

chrome.runtime.onInstalled.addListener(async ({ reason, previousVersion }) => {
  await ensureAlarms(true);
  try { await exportCookies("installed"); } catch (_) {}
  const firstTime = reason === "install";
  const gainedSettings = reason === "update" && /^1\./.test(previousVersion || "");
  if (firstTime || gainedSettings) {
    try { await chrome.runtime.openOptionsPage(); } catch (_) {}
  }
});

chrome.runtime.onStartup.addListener(async () => {
  await ensureAlarms(false);
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.settings) {
    ensureAlarms(false).catch(() => {});
  }
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === ALARM) {
    try { await exportCookies("alarm"); } catch (_) {}
  } else if (alarm.name === POLL_ALARM) {
    await pollRequest();
    await pollHealth();
  } else if (alarm.name === INSTANT_ALARM) {
    try { await exportCookies("change"); } catch (_) {}
  }
});

chrome.action.onClicked.addListener(async () => {
  try { await exportCookies("click"); } catch (_) {}
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "export-now") {
    exportCookies(msg.reason || "message")
      .then((r) => sendResponse({ ok: true, response: r }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
  if (msg && msg.type === "health-now") {
    pollHealth()
      .then(() => sendResponse({ ok: true }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
  if (msg && msg.type === "open-settings") {
    chrome.runtime.openOptionsPage()
      .then(() => sendResponse({ ok: true }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
});
