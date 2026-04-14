#!/usr/bin/env python3
import getpass
import json
import os
import subprocess
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()

DEFAULT_KEY_PATH = Path.home() / ".ssh" / "psm_mfa_cache.key"
CONFIG_ENV_PATH = Path.home() / ".config" / "ca-bee" / "config.env"
LEGACY_CONFIG_ENV_PATH = Path.home() / ".config" / "climan" / "config.env"


def debug_log(message: str, level: str = "DEBUG"):
  debug_log_file = Path(__file__).with_name("ca_bee_debug.log")
  with debug_log_file.open("a", encoding="utf-8") as handle:
    handle.write(f"[{level}] {message}\n")


def load_config_file():
  config_path = CONFIG_ENV_PATH if CONFIG_ENV_PATH.exists() else LEGACY_CONFIG_ENV_PATH
  if not config_path.exists():
    return

  for raw_line in config_path.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in line:
      continue
    key, value = line.split("=", 1)
    key = key.strip()
    value = value.strip().strip('"').strip("'")
    if key and key not in os.environ:
      os.environ[key] = value


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
  platform_account = os.environ.get("CARK_PLATFORM_ACCOUNT", "admin3").strip() or "admin3"
  login_user = (os.environ.get("CARK_LOGIN_USER") or os.environ.get("CARK_USERNAME") or os.environ.get("USER") or "").strip()
  proxy_host = os.environ.get("CARK_PROXY_HOST", "srpsmp").strip() or "srpsmp"
  default_domain = os.environ.get("CARK_DEFAULT_DOMAIN", "in.telecom.lt").strip().strip(".")
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

  try:
    for attempt in range(5):
      payload["Username"] = username
      payload["Password"] = current_secret
      response = session.post(api_url, headers=headers, json=payload, verify=False, timeout=60)

      if response.ok:
        return parse_response_json(response)

      try:
        error_data = parse_response_json(response)
      except ValueError:
        error_data = {"ErrorMessage": get_response_text(response)}

      error_code = error_data.get("ErrorCode", "")
      error_message = error_data.get("ErrorMessage", get_response_text(response))
      debug_log(
        f"Authentication attempt {attempt + 1} failed: HTTP {response.status_code} code={error_code} message={error_message} cookies={session.cookies.get_dict()}",
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

  response = requests.post(api_url, headers=headers, json=payload, verify=False, timeout=60)
  response.raise_for_status()
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
  key_path.write_text(private_key + ("\n" if not private_key.endswith("\n") else ""), encoding="utf-8")
  os.chmod(key_path, 0o600)

  public_key = response_data.get("publicKey")
  if public_key:
    public_key_path = key_path.with_suffix(key_path.suffix + ".pub")
    public_key_path.write_text(public_key + ("\n" if not public_key.endswith("\n") else ""), encoding="utf-8")
    os.chmod(public_key_path, 0o644)

  return key_path, response_data.get("expirationTime")


def print_ca_help():
  print("Usage: ca <hostname>")
  print("Connect to a CyberArk target using the cached MFA SSH key.")
  print("")
  print("Behavior:")
  print("- Uses the private key from ~/.ssh/psm_mfa_cache.key by default")
  print("- Uses the configured CyberArk account, such as admin3")
  print("- Appends CARK_DEFAULT_DOMAIN to short target and proxy hostnames")
  print("")
  print("Examples:")
  print("  ca srv-example")
  print("  ca srv-example.domain.lt")
  print("")
  print("Configuration file:")
  print(f"  {CONFIG_ENV_PATH}")


def ca_main():
  if len(sys.argv) != 2 or sys.argv[1] in {"-h", "--help"}:
    print_ca_help()
    sys.exit(0 if len(sys.argv) == 2 else 1)

  username = get_username()
  if not username:
    print(f"Missing CARK_USERNAME in {CONFIG_ENV_PATH} or environment.")
    sys.exit(1)

  key_path, _, _ = get_cache_key_config()
  if not key_path.exists():
    print(f"Missing MFA cache key at {key_path}. Run ca-login first.")
    sys.exit(1)

  resolved_host, platform_account, ssh_target = build_ssh_target(sys.argv[1])
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


def ca_login_main():
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

  print(f"Saved MFA caching SSH key to {key_path}")
  if expiration_time:
    print(f"Key expiration time: {expiration_time}")


def main():
  print("This package provides 'ca' and 'ca-login'. Use 'ca --help' for usage.")
  sys.exit(1)


if __name__ == "__main__":
  main()