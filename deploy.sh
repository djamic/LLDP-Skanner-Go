#!/bin/bash
# ============================================================
# deploy.sh — puts a branch of this repository live on this machine
#
#   ./deploy.sh BRANCH     build BRANCH, fast-forward the live tree to it,
#                          swap the binary, restart the monitor (and the bot
#                          when bot/ changed)
#   ./deploy.sh --restart  restart the monitor only
#
# The live tree is the one the monitor runs from, and its static/ is served
# as it is on disk: the merge shows the new pages at once. BRANCH is built
# in a temporary worktree first, so a failed build changes nothing. The
# running binary is kept as lldp_scanner.bakN (the next free N). The
# monitor is not restarted while the new binary has a web login and no
# web user exists (the UI would answer 503): add one with
#   sudo ./lldp_scanner --user-add NAME
# and run ./deploy.sh --restart. The restarts run as root without a
# password through /etc/sudoers.d/lldp-deploy.
#
# Rollback: cp lldp_scanner.bakN lldp_scanner && ./deploy.sh --restart
# ============================================================

DIR="/home/qosim/Desktop/lldp_go"
SELF=$(readlink -f "$0")
MONITOR="$DIR/lldp_scanner --mode"

say() { printf '%s\n' "$*"; }
die() {
    printf '❌ %s\n' "$*" >&2
    exit 1
}

# web_users counts the web users of the new binary; -1 when it has no web
# login (an older binary does not know --user-list)
web_users() {
    local out
    if ! out=$(sudo -n "$DIR/lldp_scanner" --user-list 2>/dev/null); then
        echo -1
        return
    fi
    grep -c '^user: ' <<<"$out" || true
}

restart_monitor() {
    local before now code
    before=$(pgrep -f "^$MONITOR" | head -1 || true)
    say "▶ Restarting the monitor"
    sudo -n /usr/bin/setsid "$DIR/start_monitor.sh" || die "sudo refused the restart (see /etc/sudoers.d/lldp-deploy)"
    for _ in $(seq 1 30); do
        now=$(pgrep -f "^$MONITOR" | head -1 || true)
        [ -n "$now" ] && [ "$now" != "$before" ] && break
        sleep 1
    done
    [ -n "$now" ] && [ "$now" != "$before" ] || die "the monitor did not start: see results/cron_monitor.log"
    for _ in $(seq 1 30); do
        code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8088/ || true)
        [ "$code" != "000" ] && break
        sleep 1
    done
    say "✅ Monitor running: PID $now, the web server answers HTTP $code"
}

main() {
    set -euo pipefail
    cd "$DIR"

    # Run as root (sudo ./deploy.sh), git leaves the sources it writes
    # owned by root, and the next git command of the owner fails
    if [ "$(id -u)" = 0 ]; then
        die "run ./deploy.sh without sudo: it asks sudo itself for the restart. If an earlier run did, give the files back first:
   sudo chown -R qosim:qosim $DIR/.git && git -C $DIR ls-files -z | (cd $DIR && sudo xargs -0 chown qosim:qosim)"
    fi

    case "${1:-}" in
    --restart)
        restart_monitor
        return
        ;;
    "" | -h | --help)
        sed -n '3,9p' "$SELF"
        return 2
        ;;
    esac

    local branch=$1 old tmp n users
    git rev-parse --verify --quiet "$branch^{commit}" >/dev/null || die "no branch $branch"
    git merge-base --is-ancestor HEAD "$branch" || die "$branch does not fast-forward the live tree ($(git rev-parse --abbrev-ref HEAD))"
    old=$(git rev-parse HEAD)

    say "▶ Building $branch ($(git rev-parse --short "$branch"))"
    tmp=$(mktemp -d)
    git worktree add --quiet --detach "$tmp/src" "$branch"
    if ! (cd "$tmp/src" && go build -o "$DIR/lldp_scanner.new" .); then
        git worktree remove --force "$tmp/src"
        die "the build failed: nothing changed"
    fi
    git worktree remove --force "$tmp/src"
    rmdir "$tmp"

    say "▶ Fast-forwarding $(git rev-parse --abbrev-ref HEAD) to $branch"
    git merge --ff-only --quiet "$branch"

    n=2
    while [ -e "lldp_scanner.bak$n" ]; do n=$((n + 1)); done
    cp -p lldp_scanner "lldp_scanner.bak$n"
    mv lldp_scanner.new lldp_scanner
    say "▶ Binary swapped; the old one is lldp_scanner.bak$n"

    users=$(web_users)
    if [ "$users" = 0 ]; then
        say "⚠️  The new binary has a web login and no web user yet: the monitor was NOT restarted."
        say "   Run:  sudo ./lldp_scanner --user-add NAME   then   ./deploy.sh --restart"
        return 3
    fi

    restart_monitor
    if ! git diff --quiet "$old" HEAD -- bot/; then
        say "▶ bot/ changed: restarting the Telegram bot"
        sudo -n /usr/bin/systemctl restart analyserbot || die "sudo refused the bot restart"
    fi
    say "✅ Deployed $branch ($(git rev-parse --short HEAD))"
}

# main is read whole before it runs: the merge may replace this file
main "$@"
exit $?
