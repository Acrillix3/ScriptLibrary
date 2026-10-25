# What it does
# Shares read-only CUPS collection while retaining legacy inventory/export sections and filenames.
# Available flags
# No public flags; entrypoints select the internal inventory or export profile.
# How it works
# Collects queue, endpoint and selected configuration metadata through the common private reporter.

sl_cups_device_endpoints() {
    if [ -n "$sl_cups_queue" ]; then
        sl_cups_devices=$(lpstat -v "$sl_cups_queue" 2>/dev/null) || return $?
    else
        sl_cups_devices=$(lpstat -v 2>/dev/null) || return $?
    fi
    printf '%s\n' "$sl_cups_devices" | sed -E 's#(://)[^ ]*@#\1[redacted]@#g; s#[?][^ ]*#?[omitted]#g'
}

sl_cups_printer_metadata() {
    awk -v view="$sl_cups_profile" '
      /^<Printer / || /^<DefaultPrinter / || /^Shared / {print; next}
      view=="export" && /^(State|Accepting|ErrorPolicy|OpPolicy) / {print}
    ' /etc/cups/printers.conf
}

sl_cups_scheduler_metadata() {
    awk '$1~/^(Listen|Port|Browsing|BrowseLocalProtocols|WebInterface|DefaultAuthType|DefaultEncryption)$/ {print}' /etc/cups/cupsd.conf
}

sl_cups_ppd_inventory() {
    find /etc/cups/ppd -maxdepth 1 -type f -name '*.ppd' -print 2>/dev/null
}

collect_cups_audit() {
    sl_cups_profile=$1
    case "$sl_cups_profile" in
        inventory)
            sl_cups_queue=$(arg queue '')
            sl_cups_state_label=queues
            sl_cups_accepting_label=accepting
            sl_cups_devices_label=device-endpoints
            sl_cups_metadata_label=sharing
            ;;
        export)
            sl_cups_queue=''
            sl_cups_state_label=queue-state
            sl_cups_accepting_label=queue-accepting
            sl_cups_devices_label=sanitized-devices
            sl_cups_metadata_label=queue-metadata
            ;;
        *) die 'Invalid internal CUPS report profile.' ;;
    esac
    case "$sl_cups_queue" in -*|*[!A-Za-z0-9_.-]*) die 'Queue name must contain letters, digits, dot, underscore, or hyphen.' ;; esac

    if have lpstat; then
        [ "$sl_cups_profile" != inventory ] || capture cups-scheduler lpstat -r
        capture default-printer lpstat -d
        if [ -n "$sl_cups_queue" ]; then
            capture "$sl_cups_state_label" lpstat -p "$sl_cups_queue"
            capture "$sl_cups_accepting_label" lpstat -a "$sl_cups_queue"
        else
            capture "$sl_cups_state_label" lpstat -p
            capture "$sl_cups_accepting_label" lpstat -a
        fi
        capture "$sl_cups_devices_label" sl_cups_device_endpoints
    else
        finding Unknown cups 'CUPS client tools are unavailable.'
    fi

    if [ "$sl_cups_profile" = inventory ]; then
        if have lpinfo; then capture installed-drivers lpinfo -m; else finding Unknown drivers 'lpinfo is unavailable.'; fi
    fi
    if [ -r /etc/cups/printers.conf ]; then
        capture "$sl_cups_metadata_label" sl_cups_printer_metadata
    elif [ "$sl_cups_profile" = inventory ]; then
        finding Unknown sharing 'CUPS sharing metadata is unavailable or unreadable.'
    else
        finding Unknown printer-metadata 'printers.conf is unavailable or unreadable.'
    fi

    if [ "$sl_cups_profile" = export ]; then
        if [ -r /etc/cups/cupsd.conf ]; then
            capture scheduler-metadata sl_cups_scheduler_metadata
        else
            finding Unknown scheduler-metadata 'cupsd.conf is unavailable or unreadable.'
        fi
        [ ! -d /etc/cups/ppd ] || capture ppd-file-names sl_cups_ppd_inventory
        finding Info export "Metadata is stored in this run's private report. Raw configuration, certificates, private keys, credentials, and spool documents are excluded."
        finding Info restore 'Use this report to review queue definitions; it cannot restore a complete CUPS server.'
    else
        finding Info privacy 'No job contents, document names, authentication data, or raw CUPS configuration is collected.'
    fi
}
