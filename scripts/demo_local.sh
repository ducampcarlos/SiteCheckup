#!/usr/bin/env bash
# Run the demo lab with a locally installed nginx instead of Docker.
#   scripts/demo_local.sh start | stop
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$root/.demo"
nginx_bin="${NGINX:-nginx}"

start() {
  command -v "$nginx_bin" >/dev/null || { echo "nginx not found; install it or use Docker." >&2; exit 1; }
  mkdir -p "$work/tmp" "$work/logs"
  for spec in "legacy:8080" "new:8081"; do
    name="${spec%%:*}"; port="${spec##*:}"
    sed -e "s|listen 80;|listen 127.0.0.1:${port};|" \
        -e "s|/usr/share/nginx/html|${root}/demo/${name}/html|" \
        "$root/demo/${name}/nginx.conf" > "$work/${name}.conf"
  done
  mime="/etc/nginx/mime.types"
  cat > "$work/nginx.conf" <<CONF
pid ${work}/nginx.pid;
error_log ${work}/logs/error.log;
events { worker_connections 64; }
http {
  include ${mime};
  access_log ${work}/logs/access.log;
  client_body_temp_path ${work}/tmp/body;
  proxy_temp_path ${work}/tmp/proxy;
  fastcgi_temp_path ${work}/tmp/fastcgi;
  uwsgi_temp_path ${work}/tmp/uwsgi;
  scgi_temp_path ${work}/tmp/scgi;
  include ${work}/legacy.conf;
  include ${work}/new.conf;
}
CONF
  "$nginx_bin" -p "$work" -c "$work/nginx.conf"
  echo "Demo lab: legacy http://localhost:8080  new http://localhost:8081"
}

stop() {
  if [ -f "$work/nginx.pid" ]; then
    kill "$(cat "$work/nginx.pid")" 2>/dev/null || true
    rm -f "$work/nginx.pid"
  fi
}

case "${1:-}" in
  start) stop; start ;;
  stop) stop ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
