# ca-bee

Minimal CyberArk SSH with MFA helper for WSL.

## What It Does

1. `ca-login` authenticates to CyberArk with RADIUS and refreshes the MFA caching SSH key.
2. `ca <hostname>` connects through the CyberArk PSMP hop using that cached key.
3. `ca-update` caches the hosts your `CARK_PLATFORM_ACCOUNT` can access.
4. `cai` opens an interactive picker over that cached list: type to filter, use Up/Down to select, Enter to connect.

## GitHub Setup

Clone the repository and install the commands in your WSL user environment:

```bash
git clone git@github.com:tomdrm/ca-bee.git
cd ca-bee
python3 -m pip install --user .
```


If `pip install` fails because build tooling is missing, run this once and retry:

```bash
python3 -m ensurepip --upgrade
python3 -m pip install --user --upgrade pip setuptools wheel
```

Make sure `~/.local/bin` is on your `PATH`:

```bash
echo $PATH
```

## Configuration

Create this file:

```bash
~/.config/ca-bee/config.env
```

Example:

```bash
CARK_USERNAME=<username>
CARK_AUTH_TYPE=RADIUS
CARK_PLATFORM_ACCOUNT=<platform-account>
CARK_PROXY_HOST=<proxy-host>
CARK_DEFAULT_DOMAIN=<domain>
CARK_BASE_URL=https://<cyberark-url>/PasswordVault/API
CARK_MFA_CACHE_KEY_PATH=~/.ssh/psm_mfa_cache.key
CARK_MFA_CACHE_KEY_FORMAT=OpenSSH
CARK_DISPLAY_TZ=Europe/Vilnius
CARK_SERVERS_CACHE_PATH=~/.cache/ca-bee/servers.json
CARK_ACCOUNTS_PAGE_SIZE=250
# CARK_MAX_ACCOUNT_PAGES=10000
# CARK_SERVER_SIDE_FILTER=true
# CARK_ACCOUNTS_SEARCH=<optional override; defaults to CARK_PLATFORM_ACCOUNT>
CARK_VERIFY_TLS=true
# CARK_VERIFY_TLS=/path/to/custom-ca-bundle.pem
# CARK_DEBUG=true
# CARK_DEBUG_MAX_BYTES=1048576
```

Notes:

- `CARK_BASE_URL` is required.
- `CARK_PLATFORM_ACCOUNT`, `CARK_PROXY_HOST`, and `CARK_DEFAULT_DOMAIN` are required.
- Do not store your password in the config file.
- `ca-login` prompts for the password and RADIUS challenge responses.
- `CARK_DEFAULT_DOMAIN` is used for short target hostnames and also for a short `CARK_PROXY_HOST`.
- `ca-login` prints key expiration in `CARK_DISPLAY_TZ` (defaults to `Europe/Vilnius`, EEST/EET as applicable).
- `cai` reads the host list cached by `ca-update` at `CARK_SERVERS_CACHE_PATH` (defaults to `~/.cache/ca-bee/servers.json`).
- `ca-update` only caches accounts whose `userName` matches `CARK_PLATFORM_ACCOUNT`, and stores just the host addresses.
- `ca-update` pages through accounts by following CyberArk's `nextLink`, so it handles more than 1000 accounts. Tune page size with `CARK_ACCOUNTS_PAGE_SIZE` (default `250`, max `1000`).
- By default, `ca-update` tries server-side search (`CARK_SERVER_SIDE_FILTER=true`) using `CARK_PLATFORM_ACCOUNT` as the search term. Set `CARK_ACCOUNTS_SEARCH` only if you want a different search term. If the Vault does not support this, it automatically falls back to full scan.
- If your environment has unstable pagination links or very large datasets, cap traversal with `CARK_MAX_ACCOUNT_PAGES` (default `10000`).
- TLS certificate verification is enabled by default. Keep `CARK_VERIFY_TLS=true` for normal operation. Only set `CARK_VERIFY_TLS=false` for temporary troubleshooting, or set it to a CA bundle path if your environment uses a custom trust chain.
- Debug logging is disabled by default. Enable with `CARK_DEBUG=true`; logs are written to `~/.cache/ca-bee/ca_bee_debug.log` with restricted permissions and simple size rotation.
- If your Vault rejects concurrent RADIUS sessions, add `CARK_CONCURRENT_SESSIONS=false`.

## Daily Usage

Refresh the MFA caching SSH key:

```bash
ca-login
```

Connect with a short hostname:

```bash
ca srv-example
```

That is expanded to:

```text
srv-example.domain.lt
```

If `CARK_PROXY_HOST=psmp-vip`, the proxy side is also expanded to:

```text
psmp-vip.domain.lt
```

You can also pass the full target hostname directly:

```bash
ca srv-example.domain.lt
```

The final SSH target format is:

```text
username@<platform-account>@<server-fqdn>@<proxy-fqdn>
```

If the cached key is missing, run `ca-login` first.

## Interactive Host Picker

First, cache the hosts your account can reach (prompts for password and RADIUS challenge):

```bash
ca-update
```

Then open the interactive picker:

```bash
cai
```

Start typing part of a hostname, for example `appl`, and matching hosts appear below.
Use the Up/Down arrows to highlight one and press Enter to connect. Press Esc to cancel.

You can also pre-fill the search:

```bash
cai appl
```

If you prefer to type `ca.` instead of `cai`, add a shell alias:

```bash
echo "alias ca.='cai'" >> ~/.bashrc
source ~/.bashrc
```

Re-run `ca-update` whenever new servers are added in CyberArk.

## Help

```bash
ca --help
cai --help
ca-update --help
ca-login --help
ca --version
```
