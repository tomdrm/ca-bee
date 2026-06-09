# ca-bee

Minimal CyberArk SSH with MFA helper for WSL.

## What It Does

1. `ca-login` authenticates to CyberArk with RADIUS and refreshes the MFA caching SSH key.
2. `ca <hostname>` connects through the CyberArk PSMP hop using that cached key.

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
```

Notes:

- `CARK_BASE_URL` is required.
- `CARK_PLATFORM_ACCOUNT`, `CARK_PROXY_HOST`, and `CARK_DEFAULT_DOMAIN` are required.
- Do not store your password in the config file.
- `ca-login` prompts for the password and RADIUS challenge responses.
- `CARK_DEFAULT_DOMAIN` is used for short target hostnames and also for a short `CARK_PROXY_HOST`.
- `ca-login` prints key expiration in `CARK_DISPLAY_TZ` (defaults to `Europe/Vilnius`, EEST/EET as applicable).
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

## Help

```bash
ca --help
ca-login --help
```
