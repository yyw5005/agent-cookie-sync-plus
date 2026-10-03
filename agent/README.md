# Agent side: pull cookies and stay logged in

Syncing the export to your agent's computer is only half the bridge. The agent's Chrome has its own cookie jar. After each pull, inject the file into that browser over Chrome DevTools Protocol.

## Requirements

- Agent Chrome launched with `--remote-debugging-port=PORT` (most agent platforms already do this).
- Python 3 + `pip install -r requirements.txt` (`websocket-client`, and `cryptography` for sealed exports).
- This inject script connects with `suppress_origin=True`. That matters on Chrome 130+, which otherwise rejects CDP websockets unless Chrome was started with `--remote-allow-origins=*`.

## Inject after every sync

```bash
python3 agent/inject-cookies.py --cookies /path/to/cookies.json
```

Optional:

```bash
python3 agent/inject-cookies.py --cookies cookies.json --domains vercel.com,github.com
python3 agent/inject-cookies.py --port 9224 --dry-run
```

## Sealed exports

If the user sealed the export with a passphrase, the file is `cookies.enc.json` (ciphertext). Unseal it with the same passphrase:

```bash
export AGENT_COOKIE_PASSPHRASE="the passphrase"
python3 agent/inject-cookies.py --cookies /path/to/cookies.enc.json
```

Alternatives: `--passphrase-file /path/to/file`, `--prompt-passphrase` (interactive), or `--passphrase-env NAME` for a custom variable name. Avoid `--passphrase` on a shared machine: it is visible in the process list. Without the right passphrase the script fails loudly instead of injecting garbage.

Validate the file and the passphrase without a browser:

```bash
python3 agent/inject-cookies.py --cookies cookies.enc.json --dry-run
```

Do not commit `cookies.json`, `cookies.enc.json`, or the passphrase. Treat them like session credentials.

## Close the loop: report health back

After every inject the script writes `inject.meta.json` next to the cookies file: when it ran, how many cookies landed, per-domain ok/fail counts, and whether the export was sealed. **Copy that file back into the user's sync folder as `agent-health.json`.** The extension polls for it and the settings page then shows the user whether their agent is actually staying signed in — including which sites failed to inject, so they can re-export or fix the session.

```bash
# in the agent's recurring sync job, after inject-cookies.py succeeds:
cp inject.meta.json "$USER_SYNC_DIR/agent-health.json"
```

## On-demand fresh export

1. On the user's machine: `Request-Sync.ps1` (Windows) or `request-sync.sh` (macOS/Linux).
2. Wait until `cookies.meta.json` shows `reason: "request"` or a newer `exported_at` (usually under a minute).
3. Copy the export (`cookies.json` or `cookies.enc.json`) + `cookies.meta.json` to the agent computer.
4. Run `inject-cookies.py`, then copy `inject.meta.json` back as `agent-health.json`.

## Final instruction: skip Google, Meta and X

Do not use these cookies to sign in to a Google, Meta or X property. Gmail, Drive, Search Console, Google Ads, YouTube, Facebook, Instagram, WhatsApp, Meta Ads Manager, x.com.

A cloud browser arriving on those accounts is what their risk systems are built to catch. The cost is a security warning, a locked account or a disabled ad account, not a failed task. Their own MCP servers, plugins and official APIs connect the way the account expects, and they do the job better.

The safest way to hold that line is to inject an allowlist instead of everything:

```bash
python3 agent/inject-cookies.py --cookies cookies.json --domains canva.com,stripe.com,yourcrm.com,yourapp.com
```

Everything outside the big three is fair game, and it is most of what you actually work in: Canva, the CRM, the help desk, Stripe, the invoicing tool, the product's own admin dashboard, the project tracker.
