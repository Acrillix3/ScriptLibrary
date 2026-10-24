# AMD GPU cache and driver restart

[Reset-AmdGpuCache.ps1](Troubleshooting/Reset-AmdGpuCache.ps1) clears known shader-cache files for the executing Windows user and then offers to restart the selected AMD display device. Run it in native 64-bit Windows PowerShell 5.1 on Windows 11 or Windows Server 2022/2025. Close games, renderers and other GPU applications first; save open work before accepting the restart.

From the ScriptLibrary root:

```powershell
# Preview files and detected AMD adapters. No cleanup or restart.
.\Windows\Troubleshooting\Reset-AmdGpuCache.ps1

# Preview an apply run, retaining the report.
.\Windows\Troubleshooting\Reset-AmdGpuCache.ps1 -Apply -WhatIf

# Run elevated: clear caches, then answer the separate driver-restart question.
.\Windows\Troubleshooting\Reset-AmdGpuCache.ps1 -Apply

# Clear caches while leaving the driver restart pending.
.\Windows\Troubleshooting\Reset-AmdGpuCache.ps1 -Apply -SkipRestartPrompt

# Optionally include this user's shared Windows DirectX shader cache.
.\Windows\Troubleshooting\Reset-AmdGpuCache.ps1 -Apply -IncludeDirectXCache
```

The default allowlist contains these existing folders under the executing user's Local AppData:

- `AMD\DxCache`
- `AMD\DxcCache`
- `AMD\GLCache`
- `AMD\VkCache`
- `AMD\DX9Cache`

`-IncludeDirectXCache` adds `D3DSCache`, which can include shaders from other GPU vendors. The locations follow [Unity's official Windows GPU troubleshooting guidance](https://docs.unity.com/en-us/engine/6000.0/manual/platform-specific/windows/develop/troubleshoot-gpu-crash). Driver builds can use different locations; absent folders are reported. Caches may rebuild when applications next use the GPU, including extra compilation work on first use.

Only regular files in the selected known folders are eligible. The tool preserves directories, rejects reparse-point ancestry, and rechecks file size and creation/modification timestamps before literal deletion. Locked, changing or inaccessible files are skipped. It does not force-close applications or change shader-cache policy. Driver packages, AMD profiles, installation folders, game shader caches and other user data are outside the cleanup scope. Limits default to 5,000 inspected entries and depth eight; increase `-MaxEntries` or `-MaxDepth` explicitly after reviewing an incomplete plan.

## Selecting the GPU

Discovery uses currently present Display devices with AMD PCI vendor ID `1002`. A single AMD GPU is selected automatically. If multiple AMD display adapters are present, select exact `InstanceId` values from `adapters.csv`, or explicitly request all of them:

```powershell
.\Windows\Troubleshooting\Reset-AmdGpuCache.ps1 -Apply -AllAmdAdapters
```

Device selection controls the restart. The user's AMD shader-cache files are shared across that user's AMD adapters and are not separated by GPU. If elevation uses another administrator account, the cache scope is that account's Local AppData.

## Restart and reports

After cache handling, the script saves its report, then asks a separate restart question. `-Confirm:$false` does not bypass this question. `-SkipRestartPrompt` defers the restart. An unavailable confirmation host also defers it. Graphics-device restart may briefly blank displays, interrupt GPU applications or disconnect remote sessions.

The restart uses the exact selected device instance with [Windows PnPUtil `/restart-device`](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax#restart-device). No `/reboot` switch is supplied. A native reboot-required result is recorded for a later separately authorized Windows restart. No disable/enable fallback or driver removal is attempted. Failed or unverified restarts stop additional selected GPUs from being restarted.

Reports go into a unique `Windows\Reports\Reset-AmdGpuCache-*` folder. `-OutputDirectory` changes the destination; it must be outside the cache folders. The report contains `adapters.csv`, `cache-files.csv`, `cache-scopes.csv`, `driver-actions.csv`, `summary.json` and any native PnPUtil output. Reports are written during `-WhatIf` too. Look at per-file and per-device results; a completed pass can include skipped files or a deferred restart.

Verification checks device presence and PnP status for up to ten seconds (`-VerifyTimeoutSeconds`). It does not prove successful 3D rendering or that all in-memory shader state was purged. No live AMD cache or device was changed during development; [validation](TECHNICIAN-TOOLS-VALIDATION.md) uses isolated mocks and private cache fixtures.
