#!/usr/bin/env bash
# Standalone clean uninstaller for Secure Desktop Stream (macOS & Linux).
# Delegates to `sds-installer uninstall` if present, or removes strictly allowlisted SDS artifacts.
set -euo pipefail
umask 077

component="all"
instance="sds-host"
purge_config=0
keep_firewall=0
execute_sudo=0
user_only=${SDS_UNINSTALL_USER_ONLY:-0}
dry_run=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --component)
      [ "$#" -ge 2 ] || { printf '%s\n' '--component requires all|client|host|installer' >&2; exit 2; }
      component=$2; shift 2 ;;
    --component=*)
      component=${1#--component=}; shift ;;
    --instance)
      [ "$#" -ge 2 ] || { printf '%s\n' '--instance requires a slug' >&2; exit 2; }
      instance=$2; shift 2 ;;
    --instance=*)
      instance=${1#--instance=}; shift ;;
    --purge-config) purge_config=1; shift ;;
    --keep-firewall) keep_firewall=1; shift ;;
    --execute-sudo) execute_sudo=1; shift ;;
    --user-only) user_only=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    --help|-h)
      printf '%s\n' \
        'Usage: bash uninstall.sh [--component all|client|host|installer] [--instance SLUG] [--purge-config] [--keep-firewall] [--execute-sudo] [--user-only] [--dry-run]' \
        'Removes Secure Desktop Stream client, host, and/or installer artifacts cleanly.' \
        'Configs, certificates, and Keychain keys are preserved unless --purge-config is explicitly passed.'
      exit 0 ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      exit 2 ;;
  esac
done

case "$component" in
  all|client|host|installer) ;;
  *) printf 'Invalid --component: %s\n' "$component" >&2; exit 2 ;;
esac

case "$instance" in
  *[!a-z0-9-]*|''|-*) printf 'Invalid --instance slug: %s\n' "$instance" >&2; exit 2 ;;
esac

# Prefer user-local sds-installer inside $HOME before PATH or system /Applications
# (so isolated HOME runs never touch host binaries and only delegate when appropriate).
sds_bin=""
if [ -x "$HOME/.local/bin/sds-installer" ]; then
  sds_bin="$HOME/.local/bin/sds-installer"
elif [ -x "$HOME/Applications/Secure Desktop Stream Installer.app/Contents/MacOS/sds-installer" ]; then
  sds_bin="$HOME/Applications/Secure Desktop Stream Installer.app/Contents/MacOS/sds-installer"
elif [ "$user_only" != 1 ]; then
  if command -v sds-installer >/dev/null 2>&1; then
    sds_bin=$(command -v sds-installer)
  elif [ -x "/Applications/Secure Desktop Stream Installer.app/Contents/MacOS/sds-installer" ]; then
    sds_bin="/Applications/Secure Desktop Stream Installer.app/Contents/MacOS/sds-installer"
  fi
fi

if [ -n "$sds_bin" ]; then
  args=(uninstall --component "$component" --instance "$instance")
  [ "$purge_config" = 1 ] && args+=(--purge-config)
  [ "$keep_firewall" = 1 ] && args+=(--keep-firewall)
  [ "$execute_sudo" = 1 ] && args+=(--execute-sudo)
  [ "$user_only" = 1 ] && args+=(--user-only)
  if [ "$dry_run" = 1 ]; then
    args+=(--dry-run)
  else
    args+=(--yes)
  fi
  exec "$sds_bin" "${args[@]}"
fi

run_rm() {
  local target=$1
  if [ ! -e "$target" ] && [ ! -L "$target" ]; then
    return 0
  fi
  if [ "$dry_run" = 1 ]; then
    printf '[dry-run] remove %s\n' "$target"
    return 0
  fi
  if [ -d "$target" ] && [ ! -L "$target" ]; then
    rm -rf -- "$target"
  else
    rm -f -- "$target"
  fi
  printf 'Removed: %s\n' "$target"
}

os=$(uname -s)

if [ "$component" = "all" ] || [ "$component" = "client" ]; then
  if [ "$os" = "Darwin" ]; then
    if [ "$dry_run" = 0 ] && command -v pkill >/dev/null 2>&1; then
      pkill -x Moonlight 2>/dev/null || true
    fi
    run_rm "$HOME/Applications/Moonlight Secure Desktop.app"
    if [ "$user_only" != 1 ]; then
      if [ -w "/Applications" ]; then
        run_rm "/Applications/Moonlight Secure Desktop.app"
      elif [ -e "/Applications/Moonlight Secure Desktop.app" ]; then
        printf 'Run with sudo to remove: /Applications/Moonlight Secure Desktop.app\n'
      fi
    fi
    if [ "$purge_config" = 1 ]; then
      run_rm "$HOME/Library/Application Support/SecureDesktopStream/client-receipt.json"
      run_rm "$HOME/Library/Preferences/local.secure-desktop-stream.Moonlight.plist"
    fi
  elif [ "$os" = "Linux" ]; then
    if [ "$dry_run" = 0 ] && command -v pkill >/dev/null 2>&1; then
      pkill -x moonlight 2>/dev/null || true
    fi
    run_rm "$HOME/.local/share/sds-client"
    run_rm "$HOME/.local/bin/moonlight-sds"
    run_rm "$HOME/.local/share/applications/sds-moonlight.desktop"
  fi
fi

if [ "$component" = "all" ] || [ "$component" = "host" ]; then
  if [ "$os" = "Linux" ]; then
    if command -v systemctl >/dev/null 2>&1; then
      for u in "${instance}-sunshine.service" "${instance}-display.service" "${instance}-audio.service"; do
        if [ "$dry_run" = 1 ]; then
          printf '[dry-run] systemctl --user disable --now %s\n' "$u"
        else
          systemctl --user disable --now "$u" >/dev/null 2>&1 || true
        fi
        run_rm "$HOME/.config/systemd/user/$u"
      done
      run_rm "$HOME/.config/systemd/user/${instance}-display.service.d"
      run_rm "$HOME/.config/systemd/user/${instance}-sunshine.service.d"
      [ "$dry_run" = 0 ] && systemctl --user daemon-reload >/dev/null 2>&1 || true
    fi
    run_rm "$HOME/.local/share/sds-installer-stage/$instance"
    if [ "$user_only" != 1 ]; then
      if [ -e "/opt/secure-desktop-stream-$instance" ]; then
        printf 'Run with sudo to remove root-owned host install: sudo rm -rf -- %q\n' "/opt/secure-desktop-stream-$instance"
      fi
      if [ -e "/etc/udev/rules.d/60-sds-uinput.rules" ]; then
        printf 'Run with sudo to remove udev rule: sudo rm -f /etc/udev/rules.d/60-sds-uinput.rules && sudo udevadm control --reload-rules\n'
      fi
    fi
    if [ "$keep_firewall" = 0 ]; then
      printf 'To remove SDS firewall rules manually (if active): sudo nft delete table inet sds_filter (or delete ufw/firewalld sds rules).\n'
    fi
    if [ "$purge_config" = 1 ]; then
      run_rm "$HOME/.config/${instance}-sunshine"
      run_rm "$HOME/.config/${instance}-desktop"
      run_rm "$HOME/.local/share/${instance}-sunshine"
      run_rm "$HOME/.local/share/${instance}-desktop"
      run_rm "$HOME/.local/state/${instance}-sunshine"
      run_rm "$HOME/.local/state/${instance}-audio"
      run_rm "$HOME/.cache/${instance}-sunshine"
      run_rm "$HOME/.cache/${instance}-desktop"
    fi
  fi
fi

if [ "$component" = "all" ] || [ "$component" = "installer" ]; then
  if [ "$os" = "Darwin" ]; then
    run_rm "$HOME/Applications/Secure Desktop Stream Installer.app"
    if [ "$user_only" != 1 ] && [ -w "/Applications" ]; then
      run_rm "/Applications/Secure Desktop Stream Installer.app"
    fi
    run_rm "$HOME/.local/bin/sds-installer"
    if [ "$purge_config" = 1 ]; then
      run_rm "$HOME/Library/Application Support/SecureDesktopStream"
    fi
  elif [ "$os" = "Linux" ]; then
    run_rm "$HOME/.local/share/sds-installer"
    run_rm "$HOME/.local/bin/sds-installer"
    run_rm "$HOME/.local/share/applications/sds-installer.desktop"
    if [ "$purge_config" = 1 ]; then
      run_rm "$HOME/.local/state/secure-desktop-stream"
    fi
  fi
fi

printf 'Standalone uninstall (%s, dry_run=%s, purge_config=%s) completed.\n' "$component" "$dry_run" "$purge_config"
