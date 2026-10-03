# Cookie Sync Plus

Give your cloud agent the sites you are already signed into — and now, optionally, **sealed**.

A Chrome extension and a small native host. Local only. No password pasted anywhere. Hand the folder to your agent and it installs itself.

This is a fork of [markfulton/agent-cookie-sync](https://github.com/markfulton/agent-cookie-sync) v1.2.1 (MIT), extended with:

- **Sealed exports (AES-256-GCM).** Set a passphrase in the extension and every export is encrypted before it reaches the sync folder. The folder then holds ciphertext only — whoever moves the file (rclone, Syncthing, the agent's pull job) never sees a live session. The agent unseals with the same passphrase (`inject-cookies.py --passphrase-env`).
- **Session minimization.** An "Only session cookies" mode exports just the cookies that look like sessions (server-set, or a session-like name). Tracking and preference cookies stay behind: smaller export, less exposure.
- **Closed-loop agent health.** After each inject, the agent writes `inject.meta.json` with per-domain results. Copy it back into the sync folder as `agent-health.json` and the extension's settings page shows whether your agent is actually staying signed in.
- **Change-aware exports.** The scheduled run is a heartbeat: if the cookie jar has not changed, the files are left alone instead of being rewritten and re-synced.
- **Expired pruning + audit log.** Dead cookies are dropped at export time; every export is appended to `export.log` in the sync folder.

## What this is

Cloud agents browse from a computer of their own. Fresh browser, no sessions, signed out of everything you use, so the first piece of real work hits a login wall.

This is the bridge. A Chrome extension reads the cookies of the sites you are signed into, only the sites you choose if you like, and hands them to a native host, which writes them to a folder on your own machine, every 15 minutes, the moment you sign in somewhere, or on demand. Your agent syncs that folder, then injects the cookies into its own Chrome over DevTools Protocol so the window is actually signed in. Folder sync alone is not enough. Setup is one prompt to your agent, or a few steps by hand.

No password ever moves. Chrome holds a session cookie for every site you are signed into, and the cookie is what proves you are you. Your passwords stay in your password manager.

## Install

You need Chrome and Python 3.

### The easy way: let your agent do it

Download this repository (**Code**, **Download ZIP**) or clone it, extract it somewhere you will find again, then paste this to your agent:

```
Please install and set up the Cookie Sync Plus Chrome extension and native host I just extracted to my computer's Downloads folder. I'll give you the extension id, tell me where to find it. Then set a recurring sync every 15 minutes from the cookie export folder to your computer, inject those cookies into your Chrome via CDP after each pull (see agent/inject-cookies.py), copy inject.meta.json back to my sync folder as agent-health.json after every inject, and support on-demand sync with Request-Sync.ps1 / request-sync.sh. Do not use these cookies to sign in to any Google, Meta or X account, as that can trigger a security warning on my account; use your own MCP or plugin for those.
```

That one prompt does the whole setup, the recurring sync included. It stops once, to walk you through loading the extension in Chrome and to take the extension ID from you, because that part only you can do.

### By hand

**Windows**

```powershell
powershell -ExecutionPolicy Bypass -File Install.ps1
```

Then load the extension: Chrome, `chrome://extensions`, Developer mode on, **Load unpacked**, pick the `extension` folder the script printed, and copy the extension ID from its card. Register the host with that ID:

```powershell
powershell -ExecutionPolicy Bypass -File Register-NativeHost.ps1 -ExtensionId YOUR_EXTENSION_ID
```

**macOS and Linux**

Load the extension the same way, copy the ID, then one script does the rest:

```bash
bash register-mac-linux.sh YOUR_EXTENSION_ID
```

**Both**

Reload the extension on `chrome://extensions`, then click its toolbar icon once. The badge turns into your cookie count and `cookies.json` lands in the sync folder: `%LOCALAPPDATA%\AgentCookieSync` on Windows, `~/.agentcookiesync` elsewhere.

The settings page opens by itself the first time. Come back to it any time: right click the toolbar icon, **Options**.

Last, tell your agent once:

> Set a recurring sync every 15 minutes from that export folder to your computer, inject the cookies into your Chrome with agent/inject-cookies.py after each pull, copy inject.meta.json back to my sync folder as agent-health.json, and wire on-demand sync via Request-Sync.ps1 / request-sync.sh.

## Sealed exports

In the extension's settings, under **Sealed export**, set a passphrase. From then on every export is sealed with AES-256-GCM (PBKDF2-HMAC-SHA256, 210,000 iterations, fresh random salt per export) before it is written. The sync folder then holds `cookies.enc.json` (ciphertext) instead of `cookies.json`, and switching modes deletes the stale file so plaintext is never left behind.

Your agent unseals at inject time:

```bash
export AGENT_COOKIE_PASSPHRASE="your passphrase"
python3 agent/inject-cookies.py --cookies cookies.enc.json
```

or `--passphrase-file ~/.config/cookie-sync-plus/passphrase`, or `--prompt-passphrase` for interactive use. Sealed exports need the `cryptography` package: `pip install -r agent/requirements.txt`.

The passphrase itself lives in the extension's local storage on your computer and is never part of any export. Lose it and the sealed files cannot be opened — there is no recovery.

## Read this before you switch it on

- **The export file is your keys.** `cookies.json` signs in as you on every site in it. Treat the sync folder like a password vault — or seal the export and treat the passphrase like one.
- **Every agent on the account shares every login.** They share one cloud computer, so a login one agent gets, they all get.
- **Sync from a work profile.** Use a Chrome profile holding only the accounts you would hand to an employee. Not your personal one.
- **Revoking is three moves.** Remove the extension, delete the sync folder, change the password on anything you want signed out.
- **Leave Google and Meta to their own tools.** Tell the agent not to sign in to Google, Meta or X with these cookies. See below.

The extension and the host never touch the network. The sync to your agent is the agent's job and your decision. Found a way to make this leak? [SECURITY.md](SECURITY.md), not a public issue.

## Final instruction for the agent: skip Google, Meta and X

Do not use these cookies to sign in to a Google, Meta or X property. Gmail, Drive, Search Console, Google Ads, YouTube, Facebook, Instagram, WhatsApp, Meta Ads Manager, x.com.

A cloud browser arriving on those accounts is exactly what their risk systems are built to catch. The cost is a security warning, a locked account or a disabled ad account, not a failed task.

Use their own MCP servers, plugins or official APIs for those connections. They authenticate the way the account expects and they do the job better.

Everything else is fair game, and it is most of what you actually work in: Canva, the CRM, the help desk, Stripe, the invoicing tool, your product's admin dashboard, the project tracker.

## Choose what syncs

Right click the toolbar icon, **Options**. Every change saves as you make it, and the page tells you what the next export will carry before you run it.

**Which sites.** Three rules: every site you are signed into, only the sites you tick, or every site except the ones you tick. The list groups cookies by site, shows how many each holds and when you last used it, and has a search box and a switch for sites that look signed in. A separate switch, on by default, holds back Google, Meta and X no matter what else you pick.

**Only session cookies.** When on, the export carries only cookies that look like sessions (server-set, or a session-like name). Tracking and preference cookies stay behind.

**Only sites used recently.** Today, the last 7, 30 or 90 days, or any time. Chrome does not record when a cookie was created, so this reads your browsing history (the extension asks for that permission once, when you first pick a window, and reads it on this computer only) plus the cookie changes it has seen since it was installed.

**Timing.** The scheduled export runs every 15 minutes unless you change it. If nothing changed since the last export, the files are left alone. Instant sync, on by default, exports within about a minute of a sign-in cookie changing on a site your rules allow, so a fresh login reaches your agent on its next pull instead of up to 15 minutes later. At most one of those every two minutes.

**Agent health.** After each inject your agent writes `inject.meta.json`; copy it back into the sync folder as `agent-health.json` and the settings page shows the last inject: how many cookies landed, on how many sites, and which sites failed.

The rules that applied are written into `cookies.meta.json` under `filter`, so your agent can see what it was given. Every export is also appended to `export.log` in the sync folder.

## What is in here

```
extension/manifest.json          Manifest V3, cookies + alarms + nativeMessaging (history is optional)
extension/background.js          exports on the schedule, on click, on demand, and on sign in
extension/lib.js                 the site rules: which sites, how recent, never the big three
extension/crypto.js              AES-256-GCM sealed exports (WebCrypto)
extension/options.html, .css, .js  the settings page
extension/icons/                 the cookie-and-padlock icon at 16, 32, 48 and 128
native-host/cookie_sync_host.py  writes the file; answers poll_request and poll_health; keeps export.log
Request-Sync.ps1                 Windows: drop sync-request.flag for a fresh export
request-sync.sh                  macOS/Linux: same on-demand flag
agent/inject-cookies.py          agent computer: inject cookies.json / cookies.enc.json into Chrome via CDP
agent/requirements.txt           websocket-client, cryptography
agent/README.md                  how the agent pulls, injects, unseals, and reports health
Install.ps1                      Windows: copies the files, writes the launcher
Register-NativeHost.ps1          Windows: registers the host for your extension ID
register-mac-linux.sh            macOS and Linux: both steps in one run
tests/                           pytest + node tests, including a JS<->Python crypto interop test
```

## Stay logged in on the agent

After your agent copies `cookies.json` (or `cookies.enc.json`), it must inject into its own Chrome. Use `agent/inject-cookies.py` against a browser that has `--remote-debugging-port` (most agent platforms already do). The script uses Chrome DevTools `Storage.setCookies` and never prints cookie values.

```bash
python3 agent/inject-cookies.py --cookies /path/to/cookies.json
# sealed:
export AGENT_COOKIE_PASSPHRASE="your passphrase"
python3 agent/inject-cookies.py --cookies /path/to/cookies.enc.json
```

Then copy `inject.meta.json` back to the user's sync folder as `agent-health.json` so the settings page can show the health of the loop.

### On-demand sync

Need a fresher session than the 15-minute alarm?

1. Run `Request-Sync.ps1` on Windows, or `request-sync.sh` on macOS/Linux.
2. Within about a minute the extension exports and clears `sync-request.flag`.
3. Your agent pulls the folder and runs `inject-cookies.py` again.

You can also click the extension icon anytime for an immediate export.

## Tests

```bash
pip install -r agent/requirements.txt pytest
python -m pytest tests/ -q
node tests/test_lib.mjs
node tests/interop.mjs python3   # JS<->Python sealed-export interop, both directions
```

## FAQ

**Does this send my cookies anywhere?** Not from here. The extension and the host are local only. The sync to your agent is a separate job it runs at your say so. With a passphrase set, what leaves your machine is ciphertext.

**Does it work with anything other than one specific agent?** Any agent that browses from a machine that is not yours and can sync a folder.

**Do I need this for an agent on my own PC?** No. It already has your browser.

**Why is my agent still on a login page after sync?** Syncing the folder is not enough. The agent has to inject the file into its Chrome (see `agent/inject-cookies.py`). Then reload the site. Check the **Agent health** panel in the settings: if the inject reported failures, those sites never landed.

**Can my agent use it to log into Gmail, my ad account or Facebook?** Do not let it. Google, Meta and X treat a cloud browser arriving on your account as the thing their risk systems exist to catch, and the cost is a security warning, a locked account or a disabled ad account. Use their own MCP servers, plugins or official APIs for those, and keep the cookie bridge for everything else.

**Can I sync only a few sites?** Yes. Options, then **Only the sites I pick**, tick them, done. The next export carries nothing else.

**Can it sync only the sites I actually use?** Pick a window under **Only sites used recently**. It works from your browsing history and from cookie changes, because Chrome keeps no creation date on a cookie.

**How fast does a new login reach my agent?** With instant sync on, the export runs within about a minute of the sign-in. Your agent has it on its next pull.

**What happens when I sign out of a site?** The next export carries no session for it and your agent loses access at the next sync.

**What if I lose the sealing passphrase?** The sealed files cannot be opened. Clear the passphrase in the settings and export again to go back to plain exports.

**Can I use it for clients?** Yes, it is MIT.

## License

MIT. Copyright (c) 2026 Mark Fulton (original agent-cookie-sync); modifications copyright (c) 2026 the Cookie Sync Plus contributors. [LICENSE](LICENSE).
