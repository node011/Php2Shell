#!/usr/bin/env bash
# lab_setup.sh — php2shell lab creator v2: mount-free proof design
#   1) virgin-stub docker  : stock image, stub page + perms created via docker exec
#   2) wordpress docker    : php:8.4.26-apache + WordPress 6.7.2 source mount
#
# Only the calibration-required config files are mounted (php.ini, apache.conf).
# NO /out proof mount: the exploit writes the proof to /tmp (session save_path,
# always www-data-writable) and the tool reads it back via `docker exec cat`.
#
# Authorized labs only. Usage: bash lab_setup.sh [STUB_PORT] [WP_PORT]
set -euo pipefail

STUB_PORT="${1:-8089}"
WP_PORT="${2:-8088}"
IMAGE="php:8.4.26-apache"
LAB="${LAB_DIR:-$HOME/php2shell-lab}"

mkdir -p "$LAB"/{ini,www-wp}

# ---- config (mirrors the aslr-bypass repo's php.ini / apache.conf) --------
cat > "$LAB/ini/php.ini" <<'EOF'
; php2shell lab settings
display_errors = On
display_startup_errors = On
error_reporting = E_ALL

memory_limit = 8M
post_max_size = 64M
upload_max_filesize = 64M

session.save_path = "/tmp"
session.use_strict_mode = 0
session.use_cookies = 1
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
EOF

cat > "$LAB/ini/apache.conf" <<'EOF'
# php2shell: single-worker prefork, no keep-alive
KeepAlive Off

<IfModule mpm_prefork_module>
    StartServers           1
    MinSpareServers        1
    MaxSpareServers        1
    MaxRequestWorkers      1
    ServerLimit            1
    MaxConnectionsPerChild 0
</IfModule>
EOF

# ---- wordpress source ------------------------------------------------------
if [ ! -f "$LAB/www-wp/wp-settings.php" ]; then
    echo "[*] fetching WordPress 6.7.2 source..."
    curl -fsSL https://wordpress.org/wordpress-6.7.2.tar.gz -o "$LAB/wp.tar.gz"
    tar -xzf "$LAB/wp.tar.gz" -C "$LAB/www-wp" --strip-components=1
    rm -f "$LAB/wp.tar.gz"
fi

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE"

run_target() { # name port
    local name="$1" port="$2"
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" \
        -v "$LAB/ini/php.ini":/usr/local/etc/php/conf.d/zz-php2shell.ini:ro \
        -v "$LAB/ini/apache.conf":/etc/apache2/conf-enabled/zz-php2shell.conf:ro \
        $( [ "$name" = php2shell-wp ] && echo "-v $LAB/www-wp:/var/www/html" ) \
        -p 127.0.0.1:"$port":80 \
        "$IMAGE" >/dev/null
    sleep 3
    if [ "$name" = php2shell-stub ]; then
        # stub page + writable docroot, created in-container: no www mount
        docker exec "$name" sh -c 'echo "<?php echo \"OK\";" > /var/www/html/i.php && chmod 777 /var/www/html'
        code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$port/i.php" || echo 000)
    else
        docker exec "$name" sh -c 'mkdir -p /var/www/html/wp-content/uploads && chown -R www-data:www-data /var/www/html/wp-content/uploads'
        code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$port/wp-content/index.php" || echo 000)
    fi
    echo "[+] $name up on :$port (probe: HTTP $code)"
}

run_target php2shell-stub "$STUB_PORT"
run_target php2shell-wp   "$WP_PORT"

echo
echo "targets ready (no proof mounts; proof lives in /tmp, read back via docker exec):"
echo "  stub:  http://127.0.0.1:$STUB_PORT/i.php"
echo "  wp:    http://127.0.0.1:$WP_PORT/wp-content/index.php"
echo "run:"
echo "  python3 php_exploit_general.py -u http://127.0.0.1:$STUB_PORT/i.php --bootstrap php2shell-stub"
echo "  python3 wp_exploit.py --url http://127.0.0.1:$WP_PORT/index.php --docker-container php2shell-wp --cmd 'sh</tmp/c' --fetch /proof.txt"
