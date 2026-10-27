#!/usr/bin/env bash
# php2shell-check.sh
#
# Memeriksa apakah PHP di host ini (dan di container Docker, dengan --docker)
# sudah memuat perbaikan PHP2Shell (CVE-2026-109618 / CVE-2026-109619), dan
# apakah proses yang berjalan sudah memakai binary yang baru.
#
# Cara pakai:
#   sudo ./php2shell-check.sh             # host (Debian/Ubuntu atau AlmaLinux/RHEL)
#   sudo ./php2shell-check.sh --docker    # host + semua container yang berjalan
#
# Sifat: hanya membaca. Efek samping yang mungkin:
#   - mengunduh .deb ke folder sementara bila changelog paket tidak terpasang
#   - mode --docker menjalankan 'apt-get update' di dalam container Debian
#     (hanya mengubah lapisan container yang sementara)
#
# Bukti yang dipakai:
#   1. versi >= rilis upstream yang diperbaiki (8.2.35, 8.3.36, 8.4.27, 8.5.12), atau
#   2. changelog paket menyebut CVE-2026-109618 (untuk backport: 5.6, 7.4, 8.0, 8.1,
#      atau paket distribusi yang tidak menaikkan nomor versi)
# Skrip ini TIDAK menguji exploit dan tidak membuktikan tidak ada celah lain.

set -u

CVE_ID="CVE-2026-109618"
CVE_NUM="109618"
FAIL=0; WARN=0; OKC=0

ok()   { echo "  [OK]    $*"; OKC=$((OKC+1)); }
bad()  { echo "  [GAGAL] $*"; FAIL=$((FAIL+1)); }
warn() { echo "  [CEK]   $*"; WARN=$((WARN+1)); }
info() { echo "  [INFO]  $*"; }

# cabang -> versi upstream pertama yang diperbaiki
fixed_for() {
  case "$1" in
    8.2) echo 8.2.35 ;;
    8.3) echo 8.3.36 ;;
    8.4) echo 8.4.27 ;;
    8.5) echo 8.5.12 ;;
    *)   echo "" ;;
  esac
}

# ver_ge A B  -> benar bila A >= B
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# judge LABEL VERSI_UPSTREAM HIT(1|0|?)
judge() {
  local label="$1" ver="$2" hit="$3" br fx
  br="${ver%.*}"
  fx="$(fixed_for "$br")"
  if [ "$hit" = "1" ]; then
    ok "$label ($ver): changelog paket memuat $CVE_ID"
  elif [ -n "$fx" ] && ver_ge "$ver" "$fx"; then
    ok "$label ($ver): versi >= $fx (rilis upstream yang diperbaiki)"
  elif [ -n "$fx" ]; then
    if [ "$hit" = "?" ]; then
      warn "$label ($ver): di bawah $fx dan changelog tidak bisa diperiksa; verifikasi manual"
    else
      bad "$label ($ver): di bawah $fx dan tidak ada bukti backport. UPGRADE."
    fi
  elif [ "$hit" = "0" ]; then
    bad "$label ($ver): cabang tanpa rilis resmi dan changelog TIDAK memuat $CVE_ID"
  else
    warn "$label ($ver): cabang tanpa rilis resmi dan changelog tidak bisa diperiksa; verifikasi manual"
  fi
}

# ---------- Debian / Ubuntu ----------

# deb_hit PAKET VERSI_LENGKAP -> 1 | 0 | ?
deb_hit() {
  local pkg="$1" full="$2" f t
  f="/usr/share/doc/$pkg/changelog.Debian.gz"
  if [ -r "$f" ]; then
    if zcat "$f" | grep -q "$CVE_NUM"; then echo 1; else echo 0; fi
    return
  fi
  t="$(mktemp -d)" || { echo '?'; return; }
  if ( cd "$t" && apt-get download "$pkg=$full" >/dev/null 2>&1 ); then
    if dpkg-deb --fsys-tarfile "$t"/*.deb 2>/dev/null \
       | tar -xO "./usr/share/doc/$pkg/changelog.Debian.gz" 2>/dev/null \
       | zcat 2>/dev/null | grep -q "$CVE_NUM"; then
      echo 1
    else
      echo 0
    fi
  else
    echo '?'
  fi
  rm -rf "$t"
}

scan_deb() {
  local pkg full up hit found=0
  while read -r pkg full; do
    [ -z "$pkg" ] && continue
    found=1
    up="${full#*:}"; up="${up%%-*}"
    hit="$(deb_hit "$pkg" "$full")"
    judge "$pkg" "$up" "$hit"
  done < <(dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null \
           | awk '$1 ~ /^php[0-9]+\.[0-9]+-common$/')
  [ "$found" -eq 0 ] && info "tidak ada paket phpX.Y-common di host ini"
}

# ---------- AlmaLinux / RHEL (termasuk Remi SCL) ----------

scan_rpm() {
  local name ver rel hit found=0
  while read -r name ver rel; do
    [ -z "$name" ] && continue
    found=1
    hit=0
    rpm -q --changelog "$name" 2>/dev/null | grep -q "$CVE_NUM" && hit=1
    judge "$name-$ver-$rel" "$ver" "$hit"
  done < <(rpm -qa --qf '%{NAME} %{VERSION} %{RELEASE}\n' 2>/dev/null \
           | awk '$1 ~ /^(ea-php[0-9]+-php|alt-php[0-9]+|php|php[0-9]+-php)-cli$/')
  [ "$found" -eq 0 ] && info "tidak ada paket php-cli, ea-php, atau alt-php di host ini"
}

# ---------- Proses yang berjalan: masih memakai binary lama? ----------

check_proc() {
  local label="$1" pid="$2" exe real et start mt
  exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
  if [ -z "$exe" ]; then
    warn "$label pid $pid: /proc tidak terbaca (jalankan dengan sudo)"
    return
  fi
  et="$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')"
  [ -z "$et" ] && return
  start=$(( $(date +%s) - et ))
  real="${exe% (deleted)}"
  mt="$(stat -c %Y "$real" 2>/dev/null || echo 0)"
  if [ "$exe" != "$real" ]; then
    bad "$label pid $pid: binary sudah diganti sejak proses start ((deleted)). RESTART service."
  elif [ "$start" -lt "$mt" ]; then
    bad "$label pid $pid: start $(date -d "@$start" '+%F %T') lebih lama dari binary $(date -d "@$mt" '+%F %T'). RESTART service."
  else
    ok "$label pid $pid: start $(date -d "@$start" '+%F %T'), binary $real"
  fi
}

scan_procs() {
  local pat pid n found=0
  # Ditambahkan 'lsphp' untuk mendeteksi LiteSpeed di cPanel
  for pat in 'php-fpm: master' 'nginx: master' 'lsphp'; do
    for pid in $(pgrep -f "$pat" 2>/dev/null); do
      # lewati proses milik container; diperiksa di mode --docker
      grep -qE 'docker|containerd|kubepods|lxc' "/proc/$pid/cgroup" 2>/dev/null && continue
      found=1
      check_proc "$pat" "$pid"
    done
  done
  for n in httpd apache2; do
    pid="$(pgrep -ox "$n" 2>/dev/null)" && { found=1; check_proc "$n" "$pid"; }
  done
  [ "$found" -eq 0 ] && info "tidak ada proses php-fpm, lsphp, nginx, atau Apache di host (di luar container)"
}

# CVE-2026 yang tercatat di changelog web server (untuk dibandingkan dengan advisory)
show_cves() {
  local p="$1" list=""
  if command -v rpm >/dev/null 2>&1 && rpm -q "$p" >/dev/null 2>&1; then
    list="$(rpm -q --changelog "$p" | grep -oE 'CVE-2026-[0-9]+' | sort -u | tr '\n' ' ')"
  elif [ -r "/usr/share/doc/$p/changelog.Debian.gz" ]; then
    list="$(zcat "/usr/share/doc/$p/changelog.Debian.gz" | grep -oE 'CVE-2026-[0-9]+' | sort -u | tr '\n' ' ')"
  else
    return
  fi
  info "$p: CVE-2026 di changelog: ${list:-(tidak ada)}"
}

# ---------- Docker ----------

scan_docker() {
  command -v docker >/dev/null 2>&1 || { warn "docker tidak ditemukan"; return; }
  local c ver img run_id cur_id out p v hit up br
  for c in $(docker ps --format '{{.Names}}'); do
    ver="$(docker exec "$c" php -r 'echo PHP_VERSION;' 2>/dev/null)" || continue
    [ -z "$ver" ] && continue
    echo
    echo "-- container $c (PHP $ver)"

    img="$(docker inspect -f '{{.Config.Image}}' "$c")"
    run_id="$(docker inspect -f '{{.Image}}' "$c")"
    cur_id="$(docker image inspect -f '{{.Id}}' "$img" 2>/dev/null || true)"
    if [ -n "$cur_id" ] && [ "$cur_id" != "$run_id" ]; then
      bad "$c: container memakai image lama (tag $img sudah menunjuk image lain). Jalankan: docker compose up -d --force-recreate"
    else
      ok "$c: container memakai image terbaru untuk tag $img"
    fi

    out="$(docker exec -i "$c" sh -s -- "$CVE_NUM" <<'EOS'
n="$1"
res=$(
  if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | awk '$1 ~ /^php[0-9]+\.[0-9]+-common$/' | while read -r p v; do
      hit=0
      f="/usr/share/doc/$p/changelog.Debian.gz"
      if [ -r "$f" ]; then
        zcat "$f" | grep -q "$n" && hit=1
      else
        d=$(mktemp -d) && cd "$d" && apt-get update -qq >/dev/null 2>&1
        if apt-get download "$p=$v" >/dev/null 2>&1; then
          dpkg-deb --fsys-tarfile ./*.deb | tar -xO "./usr/share/doc/$p/changelog.Debian.gz" 2>/dev/null | zcat 2>/dev/null | grep -q "$n" && hit=1
        else
          hit='?'
        fi
      fi
      echo "$p $v $hit"
    done
  elif command -v rpm >/dev/null 2>&1; then
    rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' | awk '$1 ~ /^(php|php[0-9]+-php)-common$/' | while read -r p v; do
      hit=0
      rpm -q --changelog "$p" 2>/dev/null | grep -q "$n" && hit=1
      echo "$p $v $hit"
    done
  fi
)
if [ -n "$res" ]; then echo "$res"; else echo OFFICIAL; fi
EOS
)"

    if [ "$out" = "OFFICIAL" ] || [ -z "$out" ]; then
      br="${ver%.*}"
      if [ -z "$(fixed_for "$br")" ]; then
        bad "$c: PHP $ver dari image resmi/cabang tanpa patch upstream. Pindah ke build yang terbukti memuat perbaikan."
      else
        judge "$c: php" "$ver" 0
      fi
    else
      while read -r p v hit; do
        [ -z "$p" ] && continue
        up="${v#*:}"; up="${up%%-*}"
        judge "$c: $p" "$up" "$hit"
      done <<< "$out"
    fi
  done
}

# ---------- Main ----------

echo "=== PHP2Shell ($CVE_ID / CVE-2026-109619) - $(hostname) - $(date '+%F %T') ==="
[ "$(id -u)" -ne 0 ] && warn "Bukan root: sebagian proses dan changelog mungkin tidak terbaca. Jalankan dengan sudo."

echo
echo "== Paket PHP di host"
if [ -f "/etc/redhat-release" ] || command -v rpm >/dev/null 2>&1; then
  scan_rpm
elif command -v dpkg-query >/dev/null 2>&1; then
  scan_deb
else
  warn "pengelola paket tidak dikenali"
fi

echo
echo "== Proses yang berjalan (sudah memakai binary baru?)"
scan_procs

echo
echo "== Web server (info; bandingkan dengan advisory nginx/Apache)"
for p in nginx httpd apache2; do show_cves "$p"; done

if [ "${1:-}" = "--docker" ]; then
  echo
  echo "== Container Docker"
  scan_docker
fi

echo
echo "=== Ringkasan: OK=$OKC  CEK=$WARN  GAGAL=$FAIL ==="
[ "$FAIL" -eq 0 ] || exit 1
exit 0
