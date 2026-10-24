# Shared POSIX shell helpers. Source through a category script; do not execute.
# Reports are private. Audit commands must project safe fields before capture.
LC_ALL=C
export LC_ALL
umask 077
APPLY=0
DEFER_RESTARTS=0
ACTION_FAILURE=0
LAST_CAPTURE_RC=0
ROOT_FS=/

have() { command -v "$1" >/dev/null 2>&1; }
die() { printf '%s\n' "Error: $*" >&2; exit 2; }
clean_text() {
    # Defence in depth; never pass secret-bearing files or command lines here.
    sed -E 's#(//)[^[:space:]"<>]*@#\1[redacted]@#g; s#([?&])[^[:space:]"<>]*#\1[query-redacted]#g; s#((password|passwd|secret|token|authorization|credential)[[:space:]]*[:=][[:space:]]*)[^[:space:];]+#\1[redacted]#Ig' |
        tr -d '\000-\010\013\014\016-\037\177'
}
finding() {
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" | clean_text >> "$REPORT_DIR/findings.tsv"
    printf '%s: %s — %s\n' "$1" "$2" "$3" | clean_text
}
fact() { printf '%s\t%s\n' "$1" "$2" | clean_text >> "$REPORT_DIR/facts.tsv"; }
arg() {
    arg_value=$(awk -F '\t' -v key="$1" '$1 == key {print substr($0,length($1)+2); exit}' "$REPORT_DIR/.arguments")
    if [ -n "$arg_value" ]; then printf '%s\n' "$arg_value"; else printf '%s\n' "${2-}"; fi
}
os_value() {
    awk -v key="$1" 'index($0,key "=")==1 {v=substr($0,length(key)+2); gsub(/^"|"$/, "",v); gsub(/^\047|\047$/, "",v); print v; exit}' "$2"
}
detect_os() {
    os_file=${1-/etc/os-release}
    OS_ID=unknown; OS_VERSION=unknown; OS_FAMILY=unknown
    if [ -r "$os_file" ]; then
        OS_ID=$(os_value ID "$os_file"); OS_VERSION=$(os_value VERSION_ID "$os_file")
        os_like=$(os_value ID_LIKE "$os_file")
        case "$OS_ID" in
            debian|ubuntu|linuxmint|pop|raspbian|kali) OS_FAMILY=debian ;;
            rhel|rocky|almalinux|ol|centos) OS_FAMILY=rhel ;;
            fedora) OS_FAMILY=fedora ;;
            amzn) OS_FAMILY=amazon ;;
            sles|sled|opensuse*|suse) OS_FAMILY=suse ;;
            arch|manjaro|endeavouros) OS_FAMILY=arch ;;
            alpine) OS_FAMILY=alpine ;;
            *) case " $os_like " in *' debian '*|*' ubuntu '*) OS_FAMILY=debian ;; *' rhel '*) OS_FAMILY=rhel ;; *' suse '*|*' opensuse '*) OS_FAMILY=suse ;; *' arch '*) OS_FAMILY=arch ;; esac ;;
        esac
    fi
    INIT_SYSTEM=unknown
    if [ -d /run/systemd/system ] && have systemctl; then INIT_SYSTEM=systemd
    elif [ -d /run/openrc ] && have rc-service; then INIT_SYSTEM=openrc
    fi
}
usage() {
    printf '%s\n\n' "$SCRIPT_NAME — $DESCRIPTION"
    printf '%s\n' 'Standard flags: --help, --output-dir DIRECTORY'
    if [ "$MUTATING" = true ]; then printf '%s\n' 'Changes: --apply (default is plan), --dry-run, --defer-restarts'; fi
    printf '%s\n' "Script flags: $FLAGS" 'Exit: 0 completed, 1 failed finding/action, 2 invalid usage, 3 incomplete/unknown.'
}
script_init() {
    for init_token in "$@"; do [ "$init_token" != --help ] || { usage; exit 0; }; done
    [ "$(uname -s 2>/dev/null)" = Linux ] || die 'Run on Linux. This shell is not a Linux kernel.'
    init_out=$LIBRARY_ROOT/Reports
    # Validate in a first pass; create no reports for malformed flags.
    init_apply_seen=0; init_dry_seen=0
    init_remaining=$#
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --apply) [ "$MUTATING" = true ] || die 'This is an audit; --apply is unavailable.'; init_apply_seen=1; shift ;;
            --dry-run) [ "$MUTATING" = true ] || die '--dry-run is available on setup scripts.'; init_dry_seen=1; shift ;;
            --defer-restarts) [ "$MUTATING" = true ] || die 'This is an audit.'; DEFER_RESTARTS=1; shift ;;
            --output-dir) [ "$#" -ge 2 ] && [ -n "$2" ] || die '--output-dir needs a directory.'; init_out=$2; shift 2 ;;
            --*) init_key=${1#--}; case " $OPTIONS " in *" $init_key "*) ;; *) die "Unknown flag: $1" ;; esac
                [ "$#" -ge 2 ] && [ -n "$2" ] || die "$1 needs a value."
                case "$2" in --*) die "$1 needs a value before the next flag." ;; esac
                shift 2 ;;
            *) die "Unexpected argument: $1" ;;
        esac
    done
    [ "$init_apply_seen$init_dry_seen" != 11 ] || die '--apply and --dry-run conflict.'
    APPLY=$init_apply_seen
    # All controls/newlines are rejected in values to keep TSV reports unambiguous.
    case "$init_out" in '') die 'Output directory is empty.' ;; esac
    if printf '%s' "$init_out" | LC_ALL=C grep '[[:cntrl:]]' >/dev/null; then die 'Control characters in output path.'; fi
    mkdir -p "$init_out" || die 'Cannot create output directory.'
    init_out=$(CDPATH= cd -P "$init_out" && pwd) || die 'Cannot resolve output directory.'
    REPORT_DIR=$(mktemp -d "$init_out/$SCRIPT_NAME.XXXXXXXX") || die 'Cannot create private report folder.'
    chmod 700 "$REPORT_DIR" || die 'Cannot protect report folder.'
    printf 'status\tcheck\tdetail\n' > "$REPORT_DIR/findings.tsv"
    printf 'key\tvalue\n' > "$REPORT_DIR/facts.tsv"
    : > "$REPORT_DIR/.arguments"
    trap 'rm -f "$REPORT_DIR/.arguments"' 0
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    detect_os
    fact script "$SCRIPT_NAME"; fact distro "$OS_ID"; fact version "$OS_VERSION"
    fact family "$OS_FAMILY"; fact init "$INIT_SYSTEM"; fact mode "$([ "$APPLY" = 1 ] && printf apply || printf audit-or-plan)"
    fact architecture "$(uname -m 2>/dev/null)"
    printf 'Report: %s\n' "$REPORT_DIR"
}
store_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in --apply|--dry-run|--defer-restarts) shift ;; --output-dir) shift 2 ;;
            --*) store_key=${1#--}; store_value=$2
                if printf '%s' "$store_value" | LC_ALL=C grep '[[:cntrl:]]' >/dev/null; then die 'Control characters in argument.'; fi
                if awk -F '\t' -v key="$store_key" '$1==key {found=1} END {exit !found}' "$REPORT_DIR/.arguments"; then die "Duplicate flag: --$store_key"; fi
                printf '%s\t%s\n' "$store_key" "$store_value" >> "$REPORT_DIR/.arguments"; shift 2 ;;
        esac
    done
}
capture() {
    cap_label=$1; shift
    case "$cap_label" in ''|*[!a-zA-Z0-9_.-]*) die 'Invalid internal capture label.' ;; esac
    if ! have "$1"; then finding Unknown "$cap_label" "Required command is unavailable: $1"; LAST_CAPTURE_RC=127; return 0; fi
    # Stream through a sanitizer and consume all output; do not create a raw spool file.
    cap_status=$(mktemp "$REPORT_DIR/.status.XXXXXXXX") || die 'Cannot create status marker.'
    ( "$@" 2>/dev/null; printf '%s\n' "$?" > "$cap_status" ) | clean_text | awk 'NR<=500 {print} NR==501 {print "[Output limited to 500 lines]"}' > "$REPORT_DIR/$cap_label.txt"
    LAST_CAPTURE_RC=$(cat "$cap_status"); rm -f "$cap_status"
    case "$LAST_CAPTURE_RC" in 0) finding Info "$cap_label" 'Evidence captured; review the report. Successful collection does not establish health.' ;;
        *) finding Unknown "$cap_label" "Collection failed or is partial (exit $LAST_CAPTURE_RC). Standard error excluded to avoid secret leakage." ;;
    esac
    [ -s "$REPORT_DIR/$cap_label.txt" ] || finding Info "$cap_label-empty" 'No output returned. Interpret using the command semantics and exit code; this alone does not establish health.'
    return 0
}
run_read() { capture "$@"; }
require_root() { [ "$(id -u)" = 0 ] || die 'Apply requires root; review the plan first.'; }
change() {
    change_label=$1; shift
    if [ "$ACTION_FAILURE" != 0 ]; then finding Warn "$change_label" 'Action skipped because an earlier action failed.'; return 1; fi
    if [ "$APPLY" != 1 ]; then finding Info "$change_label" 'Planned action; no system change performed.'; return 0; fi
    require_root
    if "$@" > /dev/null 2>&1; then finding Pass "$change_label" 'Action completed; inspect any documented verification.'
    else change_rc=$?; ACTION_FAILURE=1; finding Fail "$change_label" "Action failed (exit $change_rc); review system state before retrying."; return "$change_rc"; fi
}
confirm_disruption() {
    [ "$APPLY" = 1 ] || return 1
    if [ "$DEFER_RESTARTS" = 1 ]; then finding Warn restart-deferred "$1 deferred by --defer-restarts."; return 1; fi
    if ! ( : < /dev/tty ) 2>/dev/null; then finding Warn confirmation-required "$1 deferred: an interactive terminal is required."; return 1; fi
    printf '%s [y/N]: ' "$1" > /dev/tty
    IFS= read -r confirm_answer < /dev/tty || confirm_answer=n
    case "$confirm_answer" in y|Y|yes|YES) return 0 ;; *) finding Warn restart-deferred "$1 declined; configuration may await activation."; return 1 ;; esac
}
restart_service() {
    case "$1" in ''|-*|*[!a-zA-Z0-9_.@-]*) die 'Invalid service name.' ;; esac
    [ "$APPLY" = 1 ] || { finding Info service-restart "Plan: separately confirm restart of $1."; return 0; }
    [ "$ACTION_FAILURE" = 0 ] || { finding Warn service-restart 'Restart skipped because an earlier action failed.'; return 1; }
    confirm_disruption "Restart service $1 now?" || return 0
    case "$INIT_SYSTEM" in systemd) change service-restart systemctl restart "$1" ;;
        openrc) change service-restart rc-service "$1" restart ;;
        *) finding Unknown service-restart 'No supported active init system.' ;;
    esac
}
backup_file() {
    [ "$APPLY" = 1 ] || return 0
    [ ! -L "$1" ] || die "Refusing symlink configuration target: $1"
    if [ -e "$1" ]; then
        [ -f "$1" ] || die 'Backup target is not a regular file.'
        mkdir -p "$REPORT_DIR/backups" || die 'Cannot create backup folder.'
        backup_name=$(printf '%s' "$1" | sed 's#/#_#g')
        cp -p "$1" "$REPORT_DIR/backups/$backup_name" || die 'Configuration backup failed.'
        chmod 600 "$REPORT_DIR/backups/$backup_name" || die 'Cannot protect backup.'
        finding Info backup 'Original configuration copied to the private backups folder. It may contain secrets; do not share backups.'
    fi
}
write_config_file() {
    config_target=$1; config_source=$2
    case "$config_target" in /etc/*) ;; *) die 'Configuration target must be under /etc.' ;; esac
    case "$config_target" in */../*|*/./*|*/..|*/.) die 'Dot segments in configuration paths are refused.' ;; esac
    [ -f "$config_source" ] && [ -r "$config_source" ] || die 'Unreadable generated configuration.'
    [ "$APPLY" = 1 ] || { finding Info configuration "Plan: replace dedicated configuration file $config_target."; return 0; }
    [ "$ACTION_FAILURE" = 0 ] || return 1
    require_root
    config_parent=$(dirname "$config_target")
    [ -d "$config_parent" ] && [ ! -L "$config_parent" ] && [ ! -L "$config_target" ] || die 'Configuration directory must exist without symlink targets.'
    config_resolved=$(CDPATH= cd -P "$config_parent" && pwd) || die 'Cannot resolve configuration parent.'
    [ "$config_resolved" = "$config_parent" ] || die 'Symlinked configuration ancestry refused.'
    backup_file "$config_target"
    config_tmp=$(mktemp "$config_parent/.scriptlibrary.XXXXXXXX") || die 'Cannot stage configuration beside target.'
    if cat "$config_source" > "$config_tmp" && chmod 644 "$config_tmp" && mv -f "$config_tmp" "$config_target"; then
        finding Pass configuration "Dedicated configuration written atomically: $config_target"
    else
        rm -f "$config_tmp"; ACTION_FAILURE=1; finding Fail configuration 'Configuration write failed; original target was preserved where possible.'; return 1
    fi
}
install_packages() {
    install_profile=$1; install_manifest=$2
    [ -r "$install_manifest" ] && [ -f "$install_manifest" ] || die 'Package manifest must be a readable regular TSV file.'
    install_list=$REPORT_DIR/approved-packages.txt
    awk -F '\t' -v family="$OS_FAMILY" '
      /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
      NF!=2 {bad=1; next}
      $1==family || $1=="all" {if ($2 !~ /^[a-zA-Z0-9][a-zA-Z0-9+_.:-]*$/) bad=1; else print $2}
      END {if(bad) exit 2}' "$install_manifest" | sort -u > "$install_list"
    # Pipeline status cannot validate awk on POSIX shells; do a separate validation pass.
    awk -F '\t' '/^[[:space:]]*#/ || /^[[:space:]]*$/ {next} NF!=2 || $1 !~ /^(all|debian|rhel|fedora|amazon|suse|arch|alpine)$/ || $2 !~ /^[a-zA-Z0-9][a-zA-Z0-9+_.:-]*$/ {bad=1} END {exit bad}' "$install_manifest" || die 'Invalid package manifest; expected family TAB package.'
    [ -s "$install_list" ] || die "No approved packages for $OS_FAMILY."
    fact package-profile "$install_profile"
    finding Info package-plan "Approved package names saved to $install_list; existing repository trust/configuration is used."
    case "$OS_FAMILY" in
        debian) install_manager=apt-get ;;
        rhel|fedora) install_manager=dnf ;;
        amazon) case "$OS_VERSION" in 2023*) install_manager=dnf ;; 2) install_manager=yum ;; *) finding Unknown package-install 'Unsupported Amazon Linux release.'; return ;; esac ;;
        suse) install_manager=zypper ;;
        alpine) install_manager=apk ;;
        arch) finding Unknown package-install 'Arch installation is intentionally deferred: review a full system upgrade to avoid partial upgrades; run native package maintenance separately.'; return ;;
        *) finding Unknown package-install 'No supported package family.'; return ;;
    esac
    have "$install_manager" || { finding Unknown package-install "$install_manager unavailable."; return; }
    if have rpm-ostree || [ -e /run/ostree-booted ] || have transactional-update; then finding Unknown package-install 'Immutable/transactional system requires its native deployment workflow.'; return; fi
    [ "$APPLY" = 1 ] || return 0
    require_root
    confirm_disruption 'Install approved packages? Maintainer scripts may start or restart services.' || return 0
    set --
    while IFS= read -r install_package; do set -- "$@" "$install_package"; done < "$install_list"
    case "$install_manager" in
        apt-get) change package-install apt-get --assume-yes --no-remove install "$@" ;;
        dnf|yum) change package-install "$install_manager" --assumeyes install "$@" ;;
        zypper) change package-install zypper --non-interactive --no-refresh install "$@" ;;
        apk) change package-install apk add "$@" ;;
    esac
}
finish() {
    rm -f "$REPORT_DIR/.arguments"
    printf '\nReport: %s\n' "$REPORT_DIR"
    [ "$ACTION_FAILURE" = 0 ] || exit 1
    if awk -F '\t' '$1=="Fail" {found=1} END {exit !found}' "$REPORT_DIR/findings.tsv"; then exit 1; fi
    if awk -F '\t' '$1=="Unknown" {found=1} END {exit !found}' "$REPORT_DIR/findings.tsv"; then exit 3; fi
    exit 0
}
