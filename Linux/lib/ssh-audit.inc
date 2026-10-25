# What it does
# Shares read-only SSH policy collection while retaining legacy remote/access report profiles.
# Available flags
# No public flags; entrypoints select the internal remote or access profile.
# How it works
# Preserves default/Match contexts and safe projections, with selected network or public-key evidence.

sl_ssh_find_server() {
    sl_ssh_binary=''
    if have sshd; then sl_ssh_binary=$(command -v sshd)
    elif [ -x /usr/sbin/sshd ]; then sl_ssh_binary=/usr/sbin/sshd
    fi
}

sl_ssh_project_policy() {
    sl_ssh_effective=$("$sl_ssh_binary" "$@" 2>/dev/null) || return $?
    printf '%s\n' "$sl_ssh_effective" | awk -v view="$sl_ssh_profile" '
      $1~/^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|authenticationmethods|maxauthtries|usepam)$/ {print; next}
      view=="remote" && $1=="allowtcpforwarding" {print; next}
      view=="access" && $1~/^(kbdinteractiveauthentication|allowusers|allowgroups|denyusers|denygroups|authorizedkeysfile|strictmodes)$/ {print}
    '
}

sl_ssh_collect_policy() {
    sl_ssh_find_server
    if [ -z "$sl_ssh_binary" ]; then
        finding Unknown sshd 'OpenSSH server is unavailable.'
        return
    fi
    if [ "$sl_ssh_profile" = remote ]; then
        if "$sl_ssh_binary" -t >/dev/null 2>&1; then
            finding Pass sshd-syntax 'SSHD configuration syntax passed.'
        else
            finding Unknown sshd-syntax 'Syntax check failed or host keys/configuration are unreadable; rerun with appropriate access.'
        fi
    else
        capture ssh-config-test "$sl_ssh_binary" -t
    fi
    if [ -n "$sl_ssh_context" ]; then
        capture "$sl_ssh_policy_label" sl_ssh_project_policy -T -C "$sl_ssh_context"
    else
        capture "$sl_ssh_policy_label" sl_ssh_project_policy -T
    fi
    if [ "$sl_ssh_profile" = remote ]; then
        finding Info sshd-context 'Effective rules are for the selected user and address context only.'
    elif [ -z "$sl_ssh_context" ]; then
        finding Info match-rules 'Default policy only. Supply user, client-address and client-host together to evaluate applicable Match rules.'
    fi
}

sl_ssh_collect_network() {
    if have ss; then capture listening-sockets ss -lnt; else finding Unknown listeners 'ss is unavailable.'; fi
    if have ip; then capture routes ip route show; fi
    if [ -n "$sl_ssh_target" ]; then
        case "$sl_ssh_target" in *'/'*|*'@'*) die 'Use a hostname or address without credentials.' ;; esac
        if have python3; then
            capture ssh-tcp python3 -c 'import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),3); s.close(); print("TCP connection established; authentication not attempted")' "$sl_ssh_target" "$sl_ssh_port"
            if [ "$LAST_CAPTURE_RC" = 0 ]; then
                finding Pass ssh-tcp 'TCP endpoint reachable; SSH authentication was not attempted.'
            else
                finding Fail ssh-tcp 'TCP endpoint unavailable.'
            fi
        else
            finding Unknown ssh-tcp 'Python 3 is needed for the optional bounded TCP test.'
        fi
    fi
    finding Info firewall 'Use audit-firewall-rules.sh to correlate local policy; this script never alters access.'
}

sl_ssh_public_key_fingerprints() {
    sl_ssh_key_result=$(ssh-keygen -l -f "$1" 2>/dev/null) || return $?
    printf '%s\n' "$sl_ssh_key_result" | awk '{print $1 " " $2 " " $NF}'
}

sl_ssh_collect_local_keys() {
    if [ -n "$sl_ssh_user" ]; then
        sl_ssh_home=$(awk -F: -v u="$sl_ssh_user" '$1==u {print $6}' /etc/passwd)
        case "$sl_ssh_home" in /*) ;; *) die 'Selected local user has no valid absolute home directory.' ;; esac
        [ "$sl_ssh_home" != / ] || die 'Root-home filesystem scan is refused.'
        for sl_ssh_file in "$sl_ssh_home" "$sl_ssh_home/.ssh" "$sl_ssh_home/.ssh/authorized_keys"; do
            [ ! -e "$sl_ssh_file" ] || capture ssh-file-metadata ls -ld "$sl_ssh_file"
        done
        if [ -f "$sl_ssh_home/.ssh/authorized_keys" ] && [ -r "$sl_ssh_home/.ssh/authorized_keys" ]; then
            if have ssh-keygen; then
                capture public-key-fingerprints sl_ssh_public_key_fingerprints "$sl_ssh_home/.ssh/authorized_keys"
            else
                finding Unknown keys 'ssh-keygen is unavailable.'
            fi
        else
            finding Unknown keys 'No readable standard authorized_keys file. Custom AuthorizedKeysCommand or paths require separate review.'
        fi
    fi
    finding Info scope 'Private keys, key comments, and authorized-key contents are excluded.'
}

collect_ssh_audit() {
    sl_ssh_profile=$1
    sl_ssh_context=''
    case "$sl_ssh_profile" in
        remote)
            sl_ssh_target=$(arg target '')
            sl_ssh_port=$(arg port 22)
            sl_ssh_user=$(arg user root)
            sl_ssh_client=$(arg client-address 127.0.0.1)
            sl_ssh_local=$(arg local-address 127.0.0.1)
            case "$sl_ssh_port" in ''|*[!0-9]*) die 'Port must be numeric.' ;; esac
            [ "$sl_ssh_port" -ge 1 ] && [ "$sl_ssh_port" -le 65535 ] || die 'Port must be 1-65535.'
            for sl_ssh_value in "$sl_ssh_target" "$sl_ssh_user" "$sl_ssh_client" "$sl_ssh_local"; do
                case "$sl_ssh_value" in -*|*','*|*'='*|*' '*|*'
'*) die 'Invalid SSH test context.' ;; esac
            done
            sl_ssh_context="user=$sl_ssh_user,host=localhost,addr=$sl_ssh_client,laddr=$sl_ssh_local,lport=$sl_ssh_port"
            sl_ssh_policy_label=sshd-effective
            ;;
        access)
            sl_ssh_user=$(arg user '')
            sl_ssh_client=$(arg client-address '')
            sl_ssh_host=$(arg client-host '')
            case "$sl_ssh_user" in *[!A-Za-z0-9_.-]*) die 'Invalid user.' ;; esac
            case "$sl_ssh_client$sl_ssh_host" in *[!A-Za-z0-9_.:%-]*) die 'Invalid client context.' ;; esac
            sl_ssh_policy_label=default-ssh-policy
            if [ -n "$sl_ssh_user" ] && [ -n "$sl_ssh_client" ] && [ -n "$sl_ssh_host" ]; then
                sl_ssh_context="user=$sl_ssh_user,host=$sl_ssh_host,addr=$sl_ssh_client"
                sl_ssh_policy_label=effective-ssh-policy
            fi
            ;;
        *) die 'Invalid internal SSH report profile.' ;;
    esac
    sl_ssh_collect_policy
    if [ "$sl_ssh_profile" = remote ]; then sl_ssh_collect_network; else sl_ssh_collect_local_keys; fi
}
