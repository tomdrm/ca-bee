#!/usr/bin/env python3
import getpass
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote_plus, urljoin, urlparse
from zoneinfo import ZoneInfo

import requests

__version__ = "2.1.0"

DEFAULT_KEY_PATH = Path.home() / ".ssh" / "psm_mfa_cache.key"
CONFIG_ENV_PATH = Path.home() / ".config" / "ca-bee" / "config.env"
CACHE_DIR = Path.home() / ".cache" / "ca-bee"
DEFAULT_SERVERS_CACHE_PATH = CACHE_DIR / "servers.json"
DEFAULT_KEY_META_PATH = CACHE_DIR / "key_meta.json"
DEBUG_LOG_PATH = CACHE_DIR / "ca_bee_debug.log"


def is_debug_enabled():
  return (os.environ.get("CARK_DEBUG") or "").strip().lower() in {"1", "true", "yes", "on"}


def get_tls_verify():
  """Return the value to pass to requests' verify=.

  Defaults to True (verification on). Set CARK_VERIFY_TLS to a CA bundle path to
  use a custom bundle, or to false/0/no to disable verification (not recommended).
  """
  raw = (os.environ.get("CARK_VERIFY_TLS") or "").strip()
  if not raw:
    return True
  if raw.lower() in {"0", "false", "no", "off"}:
    import urllib3
    urllib3.disable_warnings()
    return False
  if raw.lower() in {"1", "true", "yes", "on"}:
    return True
  return raw


def tls_help_text():
  return (
    "TLS certificate verification failed. "
    "Set CARK_VERIFY_TLS to your CA bundle path (recommended), "
    "or set CARK_VERIFY_TLS=false temporarily for troubleshooting."
  )


def debug_log(message: str, level: str = "DEBUG"):
  if not is_debug_enabled():
    return
  try:
    DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
      max_log_bytes = int((os.environ.get("CARK_DEBUG_MAX_BYTES") or "1048576").strip() or "1048576")
    except ValueError:
      max_log_bytes = 1048576
    if DEBUG_LOG_PATH.exists() and DEBUG_LOG_PATH.stat().st_size > max_log_bytes:
      rotated_path = DEBUG_LOG_PATH.with_suffix(".log.1")
      if rotated_path.exists():
        rotated_path.unlink()
      DEBUG_LOG_PATH.rename(rotated_path)
    fd = os.open(str(DEBUG_LOG_PATH), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
      os.write(fd, f"[{level}] {message}\n".encode("utf-8"))
    finally:
      os.close(fd)
  except OSError:
    pass


def maybe_print_version():
  if len(sys.argv) > 1 and sys.argv[1] in {"--version", "-V"}:
    print(f"ca-bee {__version__}")
    sys.exit(0)


def save_key_metadata(expiration_time):
  if expiration_time in (None, ""):
    return
  payload = {"expirationTime": str(expiration_time)}
  try:
    DEFAULT_KEY_META_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(DEFAULT_KEY_META_PATH), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
      os.write(fd, json.dumps(payload).encode("utf-8"))
    finally:
      os.close(fd)
  except OSError:
    pass


def load_key_expiration_time():
  try:
    payload = json.loads(DEFAULT_KEY_META_PATH.read_text(encoding="utf-8"))
  except (OSError, ValueError):
    return None
  return payload.get("expirationTime")



def load_config_file():
  if not CONFIG_ENV_PATH.exists():
    return

  for raw_line in CONFIG_ENV_PATH.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in line:
      continue
    key, value = line.split("=", 1)
    key = key.strip()
    value = value.strip().strip('"').strip("'")
    if key and key not in os.environ:
      os.environ[key] = value


def require_env(name: str):
  value = (os.environ.get(name) or "").strip()
  if not value:
    raise RuntimeError(f"Missing {name} in {CONFIG_ENV_PATH} or environment.")
  return value


def parse_response_json(response: requests.Response):
  try:
    return response.json()
  except (ValueError, UnicodeDecodeError):
    decoded_body = response.content.decode("utf-8", errors="replace")
    return json.loads(decoded_body)


def get_response_text(response: requests.Response):
  return response.content.decode("utf-8", errors="replace")


load_config_file()


def get_username():
  return (os.environ.get("CARK_USERNAME") or os.environ.get("USER") or "").strip()


def format_expiration_time(expiration_time):
  if expiration_time in (None, ""):
    return None

  try:
    unix_seconds = int(str(expiration_time).strip())
  except (TypeError, ValueError):
    return str(expiration_time)

  display_tz = (os.environ.get("CARK_DISPLAY_TZ") or "Europe/Vilnius").strip() or "Europe/Vilnius"
  local_time = datetime.fromtimestamp(unix_seconds, tz=ZoneInfo(display_tz))
  return f"{local_time.strftime('%Y-%m-%d %H:%M:%S %Z')} ({display_tz}, unix: {unix_seconds})"


def get_pvwa_base_url():
  base_url = (os.environ.get("CARK_BASE_URL") or "").strip().rstrip("/")
  if not base_url:
    raise RuntimeError(f"Missing CARK_BASE_URL in {CONFIG_ENV_PATH} or environment.")
  return base_url


def get_auth_config():
  auth_type = os.environ.get("CARK_AUTH_TYPE", "RADIUS").strip().upper() or "RADIUS"
  auth_endpoint = os.environ.get("CARK_AUTH_ENDPOINT")
  concurrent_sessions = os.environ.get("CARK_CONCURRENT_SESSIONS", "true").strip().lower()
  enable_concurrent_sessions = concurrent_sessions not in {"0", "false", "no"}
  login_url = auth_endpoint if auth_endpoint else f"/auth/{auth_type}/Logon"
  payload = {"concurrentSessions": "true" if enable_concurrent_sessions else "false"} if auth_type == "RADIUS" else {}
  return auth_type, login_url, payload


def get_cache_key_config():
  key_path = Path(os.environ.get("CARK_MFA_CACHE_KEY_PATH", str(DEFAULT_KEY_PATH))).expanduser()
  key_format = os.environ.get("CARK_MFA_CACHE_KEY_FORMAT", "OpenSSH").strip() or "OpenSSH"
  key_password = os.environ.get("CARK_MFA_CACHE_KEY_PASSWORD", "")
  return key_path, key_format, key_password


def get_connection_config():
  platform_account = require_env("CARK_PLATFORM_ACCOUNT")
  login_user = (os.environ.get("CARK_LOGIN_USER") or os.environ.get("CARK_USERNAME") or os.environ.get("USER") or "").strip()
  proxy_host = require_env("CARK_PROXY_HOST")
  default_domain = require_env("CARK_DEFAULT_DOMAIN").strip(".")
  return platform_account, login_user, proxy_host, default_domain


def normalize_host(hostname: str, default_domain: str):
  normalized = hostname.strip().rstrip(".")
  if "." not in normalized:
    normalized = f"{normalized}.{default_domain}"
  return normalized


def build_ssh_target(hostname: str):
  platform_account, login_user, proxy_host, default_domain = get_connection_config()
  resolved_host = normalize_host(hostname, default_domain)
  resolved_proxy_host = normalize_host(proxy_host, default_domain)
  ssh_target = "@".join(part for part in [login_user, platform_account, resolved_host, resolved_proxy_host] if part)
  return resolved_host, platform_account, ssh_target


def prompt_for_password():
  return getpass.getpass("CyberArk(AD) password: ")


def prompt_for_challenge(challenge_message: str):
  print(challenge_message)
  if "Enter an authentication method number" in challenge_message:
    return input("Select RADIUS method number(OTP works only now): ").strip()
  return getpass.getpass("Enter OTP/token code: ").strip()


def cyberark_logon(username: str, password: str):
  auth_type, login_url, payload = get_auth_config()
  api_url = f"{get_pvwa_base_url()}{login_url}"
  headers = {"Content-Type": "application/json"}
  current_secret = password
  session = requests.Session()

  verify_config = get_tls_verify()

  try:
    for attempt in range(5):
      payload["Username"] = username
      payload["Password"] = current_secret
      try:
        response = session.post(api_url, headers=headers, json=payload, verify=verify_config, timeout=60)
      except requests.exceptions.SSLError as exc:
        raise RuntimeError(f"{tls_help_text()} Details: {exc}") from exc

      if response.ok:
        return parse_response_json(response)

      try:
        error_data = parse_response_json(response)
      except ValueError:
        error_data = {"ErrorMessage": get_response_text(response)}

      error_code = error_data.get("ErrorCode", "")
      error_message = error_data.get("ErrorMessage", get_response_text(response))
      debug_log(
        f"Authentication attempt {attempt + 1} failed: HTTP {response.status_code} code={error_code} message={error_message} cookies=<redacted:{len(session.cookies)}>",
        level="ERROR",
      )

      if error_code != "ITATS542I":
        raise RuntimeError(f"CyberArk {auth_type} authentication failed: HTTP {response.status_code} {error_message}")

      current_secret = prompt_for_challenge(error_message)
      if not current_secret:
        raise RuntimeError("No RADIUS challenge response provided.")

    raise RuntimeError("CyberArk RADIUS authentication did not complete after multiple challenge responses.")
  finally:
    session.close()


def generate_mfa_cache_ssh_key(token: str):
  key_path, key_format, key_password = get_cache_key_config()
  api_url = f"{get_pvwa_base_url()}/Users/Secret/SSHKeys/Cache/"
  headers = {"Content-Type": "application/json", "Authorization": token}
  payload = {"formats": [key_format]}
  if key_password:
    payload["keyPassword"] = key_password

  response = requests.post(api_url, headers=headers, json=payload, verify=get_tls_verify(), timeout=60)
  if not response.ok:
    try:
      error_data = parse_response_json(response)
      detail = error_data.get("ErrorMessage") or error_data.get("Details") or get_response_text(response)
    except ValueError:
      detail = get_response_text(response)
    raise RuntimeError(f"Failed to generate MFA cache SSH key: HTTP {response.status_code} {detail}")
  response_data = parse_response_json(response)

  private_key = None
  for entry in response_data.get("value", []):
    if entry.get("format") == key_format and entry.get("privateKey"):
      private_key = entry["privateKey"]
      break
  if not private_key:
    for entry in response_data.get("value", []):
      if entry.get("privateKey"):
        private_key = entry["privateKey"]
        break
  if not private_key:
    raise RuntimeError("CyberArk did not return a private key in the MFA cache response.")

  key_path.parent.mkdir(parents=True, exist_ok=True)
  private_key_text = private_key + ("\n" if not private_key.endswith("\n") else "")
  key_fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
  try:
    os.write(key_fd, private_key_text.encode("utf-8"))
  finally:
    os.close(key_fd)
  os.chmod(key_path, 0o600)

  public_key = response_data.get("publicKey")
  if not public_key:
    for entry in response_data.get("value", []):
      candidate_public_key = entry.get("publicKey")
      if candidate_public_key:
        public_key = candidate_public_key
        break
  if public_key:
    public_key_path = key_path.with_suffix(key_path.suffix + ".pub")
    public_key_path.write_text(public_key + ("\n" if not public_key.endswith("\n") else ""), encoding="utf-8")
    os.chmod(public_key_path, 0o644)

  return key_path, response_data.get("expirationTime")


def get_servers_cache_path():
  return Path(os.environ.get("CARK_SERVERS_CACHE_PATH", str(DEFAULT_SERVERS_CACHE_PATH))).expanduser()


def save_cached_servers(servers):
  cache_path = get_servers_cache_path()
  cache_path.parent.mkdir(parents=True, exist_ok=True)
  payload = {"generated_at": int(time.time()), "servers": servers}
  cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
  os.chmod(cache_path, 0o600)
  return cache_path


def load_cached_servers():
  cache_path = get_servers_cache_path()
  if not cache_path.exists():
    return None, []
  try:
    data = json.loads(cache_path.read_text(encoding="utf-8"))
  except (ValueError, OSError):
    return None, []
  return data.get("generated_at"), data.get("servers", [])


def resolve_accounts_next_url(base_url: str, next_link: str):
  link = (next_link or "").strip()
  if not link:
    return None

  if link.startswith("http://") or link.startswith("https://"):
    return link

  parsed = urlparse(base_url)
  origin = f"{parsed.scheme}://{parsed.netloc}"
  path_lower = parsed.path.lower()
  passwordvault_root = urljoin(origin + "/", "/PasswordVault/")

  if "/passwordvault/api" in path_lower:
    api_path = parsed.path[:path_lower.index("/passwordvault/api") + len("/PasswordVault/API")]
    api_root = f"{origin}{api_path.rstrip('/')}/"
  else:
    api_root = urljoin(passwordvault_root, "API/")

  if link.startswith("/"):
    return urljoin(origin + "/", link.lstrip("/"))

  if link.lower().startswith("passwordvault/"):
    return urljoin(origin + "/", link)

  if link.lower().startswith("api/"):
    return urljoin(passwordvault_root, link)

  return urljoin(api_root, link)


def fetch_all_accounts(token: str, show_progress: bool = False):
  base_url = get_pvwa_base_url()
  headers = {"Authorization": token}
  platform_account = require_env("CARK_PLATFORM_ACCOUNT").lower()
  addresses = []
  seen = set()

  try:
    page_size = int(os.environ.get("CARK_ACCOUNTS_PAGE_SIZE", "250").strip() or "250")
  except ValueError:
    page_size = 250
  page_size = max(1, min(page_size, 1000))

  max_pages = max(1, int((os.environ.get("CARK_MAX_ACCOUNT_PAGES") or "10000").strip() or "10000"))
  search_enabled = (os.environ.get("CARK_SERVER_SIDE_FILTER") or "true").strip().lower() not in {"0", "false", "no", "off"}
  search_query = (os.environ.get("CARK_ACCOUNTS_SEARCH") or require_env("CARK_PLATFORM_ACCOUNT")).strip()

  def first_page_url(with_search: bool):
    if with_search and search_query:
      return f"{base_url}/Accounts?limit={page_size}&offset=0&search={quote_plus(search_query)}"
    return f"{base_url}/Accounts?limit={page_size}&offset=0"

  visited_urls = set()
  pages_processed = 0
  spinner_frames = "|/-\\"
  next_url = first_page_url(search_enabled)

  while next_url:
    if next_url in visited_urls:
      raise RuntimeError("Account paging loop detected: CyberArk returned the same nextLink repeatedly.")
    if len(visited_urls) >= max_pages:
      raise RuntimeError(f"Account paging exceeded {max_pages} pages. Check nextLink responses.")
    visited_urls.add(next_url)
    pages_processed += 1

    response = requests.get(next_url, headers=headers, verify=get_tls_verify(), timeout=60)
    # Some PVWA versions reject the search parameter. Fall back to full scan.
    if (
      not response.ok
      and search_enabled
      and pages_processed == 1
      and "search=" in next_url.lower()
      and response.status_code in {400, 404}
    ):
      if show_progress:
        print("Server-side search unsupported; falling back to full account scan...", flush=True)
      search_enabled = False
      visited_urls.clear()
      pages_processed = 0
      next_url = first_page_url(False)
      continue

    if not response.ok:
      try:
        error_data = parse_response_json(response)
        detail = error_data.get("ErrorMessage") or error_data.get("Details") or get_response_text(response)
      except ValueError:
        detail = get_response_text(response)
      raise RuntimeError(f"Failed to list accounts at {next_url}: HTTP {response.status_code} {detail}")

    data = parse_response_json(response)

    items = data.get("value", [])
    for item in items:
      if (item.get("userName") or "").strip().lower() != platform_account:
        continue
      address = (item.get("address") or "").strip()
      if not address or address.lower() in seen:
        continue
      seen.add(address.lower())
      addresses.append(address)

    if show_progress:
      spinner = spinner_frames[(pages_processed - 1) % len(spinner_frames)]
      print(
        f"  {spinner} matching hosts: {len(addresses)}...",
        end="\r",
        flush=True,
      )

    next_link = (data.get("nextLink") or "").strip()
    if next_link:
      next_url = resolve_accounts_next_url(base_url, next_link)
    else:
      next_url = None

  if show_progress:
    print(" " * 80, end="\r", flush=True)
  addresses.sort(key=str.lower)
  return addresses


def connect_host(hostname: str):
  key_path, _, _ = get_cache_key_config()
  if not key_path.exists():
    print(f"Missing MFA cache key at {key_path}. Run ca-login first.")
    sys.exit(1)

  expiration_time = load_key_expiration_time()
  if expiration_time:
    try:
      expires_unix = int(str(expiration_time).strip())
      if expires_unix <= int(time.time()):
        print(f"Warning: MFA cache key expired ({format_expiration_time(expiration_time)}). Run ca-login.")
    except (TypeError, ValueError):
      pass

  resolved_host, platform_account, ssh_target = build_ssh_target(hostname)
  print(f"Connecting to {resolved_host} via CyberArk ({platform_account})...")
  subprocess.run([
    "ssh",
    "-i",
    str(key_path),
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "UpdateHostKeys=yes",
    ssh_target,
  ], check=False)


def _fallback_pick(addresses, initial_query=""):
  query = initial_query
  while True:
    matches = [a for a in addresses if query.lower() in a.lower()]
    if matches:
      for index, address in enumerate(matches[:20], start=1):
        print(f"  {index}. {address}")
      if len(matches) > 20:
        print(f"  ... {len(matches) - 20} more, refine your search")
    else:
      print("  (no matches)")

    raw = input("Filter text, number to connect, or 'q' to quit: ").strip()
    if raw.lower() == "q":
      return None
    if raw.isdigit():
      choice_index = int(raw) - 1
      if 0 <= choice_index < len(matches):
        return matches[choice_index]
      continue
    query = raw


def _run_picker(stdscr, addresses, initial_query):
  import curses

  curses.curs_set(1)
  stdscr.keypad(True)

  query = initial_query
  selected = 0
  top = 0

  while True:
    filtered = [a for a in addresses if query.lower() in a.lower()]
    if selected >= len(filtered):
      selected = max(0, len(filtered) - 1)

    height, width = stdscr.getmaxyx()
    max_visible = max(1, height - 3)

    if selected < top:
      top = selected
    elif selected >= top + max_visible:
      top = selected - max_visible + 1

    stdscr.erase()
    prompt = f"Search: {query}"
    info = "(type to filter, Up/Down select, Enter connect, Esc cancel)"
    try:
      stdscr.addstr(0, 0, prompt[:width - 1])
      stdscr.addstr(1, 0, info[:width - 1], curses.A_DIM)
    except curses.error:
      pass

    visible = filtered[top:top + max_visible]
    for row, address in enumerate(visible):
      actual_index = top + row
      attr = curses.A_REVERSE if actual_index == selected else curses.A_NORMAL
      try:
        stdscr.addstr(2 + row, 0, address[:width - 1], attr)
      except curses.error:
        pass

    try:
      stdscr.move(0, min(len(prompt), width - 1))
    except curses.error:
      pass
    stdscr.refresh()

    key = stdscr.get_wch()
    if isinstance(key, str):
      if key in ("\n", "\r"):
        return filtered[selected] if filtered else None
      if key == "\x1b":
        return None
      if key in ("\x7f", "\b"):
        query = query[:-1]
        selected = 0
      elif key.isprintable():
        query += key
        selected = 0
    else:
      if key == curses.KEY_UP:
        selected = max(0, selected - 1)
      elif key == curses.KEY_DOWN:
        selected = min(max(0, len(filtered) - 1), selected + 1)
      elif key in (curses.KEY_BACKSPACE, 127, 8):
        query = query[:-1]
        selected = 0
      elif key == curses.KEY_ENTER:
        return filtered[selected] if filtered else None


def interactive_pick(servers, initial_query=""):
  addresses = sorted(
    {
      (entry if isinstance(entry, str) else entry.get("address", "")).strip()
      for entry in servers
      if (entry if isinstance(entry, str) else entry.get("address"))
    }
  )
  if not addresses:
    return None

  try:
    import curses
  except ImportError:
    return _fallback_pick(addresses, initial_query)

  if not sys.stdin.isatty() or not sys.stdout.isatty():
    return _fallback_pick(addresses, initial_query)

  try:
    return curses.wrapper(_run_picker, addresses, initial_query)
  except curses.error:
    return _fallback_pick(addresses, initial_query)


def print_ca_help():
  print("Usage: ca <hostname>")
  print("Connect to a CyberArk target using the cached MFA SSH key.")
  print("")
  print("Behavior:")
  print("- Uses the private key from ~/.ssh/psm_mfa_cache.key by default")
  print("- Uses the configured CyberArk account")
  print("- Appends CARK_DEFAULT_DOMAIN to short target and proxy hostnames")
  print("")
  print("Examples:")
  print("  ca srv-example")
  print("  ca srv-example.domain.lt")
  print("")
  print("Configuration file:")
  print(f"  {CONFIG_ENV_PATH}")


def ca_main():
  maybe_print_version()
  if len(sys.argv) == 1:
    print("Missing hostname. Try: ca <hostname>")
    sys.exit(1)
  if len(sys.argv) == 2 and sys.argv[1] in {"-h", "--help"}:
    print_ca_help()
    sys.exit(0)
  if len(sys.argv) != 2:
    print_ca_help()
    sys.exit(1)

  connect_host(sys.argv[1])


def cai_main():
  maybe_print_version()
  if len(sys.argv) > 1 and sys.argv[1] in {"-h", "--help"}:
    print("Usage: cai [initial-search]")
    print("Interactively pick a CyberArk host from the cached list and connect.")
    print("Type to filter, use Up/Down to select, Enter to connect, Esc to cancel.")
    print("Run ca-update first to build or refresh the cached host list.")
    sys.exit(0)

  generated_at, servers = load_cached_servers()
  if not servers:
    print(f"No cached hosts found at {get_servers_cache_path()}.")
    print("Run ca-update first.")
    sys.exit(1)

  if generated_at:
    age_days = (time.time() - generated_at) / 86400
    if age_days > 7:
      print(f"Note: host list is {int(age_days)} day(s) old. Run ca-update to refresh.")

  initial_query = sys.argv[1] if len(sys.argv) > 1 else ""
  choice = interactive_pick(servers, initial_query)
  if not choice:
    sys.exit(0)

  connect_host(choice)


def ca_update_main():
  maybe_print_version()
  if len(sys.argv) > 1 and sys.argv[1] in {"-h", "--help"}:
    print("Usage: ca-update")
    print("Authenticate to CyberArk and cache the list of hosts your account can access.")
    print("The cached list is used by the 'cai' interactive picker.")
    sys.exit(0)

  username = get_username() or input("CyberArk username: ").strip()
  if not username:
    print("Error: CyberArk username is required.")
    sys.exit(1)

  password = prompt_for_password()
  if not password:
    print("Error: CyberArk password is required.")
    sys.exit(1)

  try:
    token = cyberark_logon(username, password)
    print("Fetching hosts from CyberArk, please wait...")
    servers = fetch_all_accounts(token, show_progress=True)
  except Exception as e:
    print(f"ca-update failed: {e}")
    sys.exit(1)

  cache_path = save_cached_servers(servers)
  print(f"Cached {len(servers)} host(s) to {cache_path}")


def ca_login_main():
  maybe_print_version()
  if len(sys.argv) > 1 and sys.argv[1] in {"-h", "--help"}:
    print("Usage: ca-login")
    print("Log in to CyberArk, answer any RADIUS challenges, and save the MFA caching SSH key locally.")
    sys.exit(0)

  username = get_username() or input("CyberArk username: ").strip()
  if not username:
    print("Error: CyberArk username is required.")
    sys.exit(1)

  password = prompt_for_password()
  if not password:
    print("Error: CyberArk password is required.")
    sys.exit(1)

  try:
    token = cyberark_logon(username, password)
    key_path, expiration_time = generate_mfa_cache_ssh_key(token)
  except Exception as e:
    print(f"ca-login failed: {e}")
    sys.exit(1)

  save_key_metadata(expiration_time)
  print(f"Saved MFA caching SSH key to {key_path}")
  if expiration_time:
    print(f"Key expiration time: {format_expiration_time(expiration_time)}")


def main():
  print("This package provides 'ca', 'cai', 'ca-update', and 'ca-login'. Use 'ca --help' for usage.")
  sys.exit(1)


if __name__ == "__main__":
  main()
