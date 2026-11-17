# Company baseline (Automattic Field Guide: Computer Security Best Practices)

Everyone-else mode only. The Field Guide page is mostly about accounts and habits, so only part of it is observable on the device. The agent checks what it can, asks about what it cannot, and never pretends the rest was verified. Anything suspicious goes to sysops@automattic.com.

| Field Guide requirement | Device-checkable? | How to verify it (read-only) |
| --- | --- | --- |
| Encrypt your hard drive (FileVault / BitLocker / LUKS) | Yes | `fdesetup status` / `manage-bde -status` / `lsblk -o NAME,TYPE,FSTYPE` |
| Password required to wake from sleep / screen saver; screen saver in 15 minutes or less | Yes | `sysadminctl -screenLock status`; `defaults -currentHost read com.apple.screensaver idleTime` (900 or less) |
| Turn on your firewall | Yes | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` / `netsh advfirewall show allprofiles` / `ufw status` |
| Always use the A8C proxy (AutoProxxy) | Yes | AutoProxxy present as a login item and PAC set to `pac.autoproxxy.com` in `scutil --proxy` |
| Turn on Find My Mac | Yes | `FindMyMacd` running; confirm in System Settings, Apple Account, iCloud |
| Backups encrypted (Time Machine) | Partly | `tmutil destinationinfo` shows destinations; encryption state needs a look at the Time Machine pane |
| Advanced Data Protection on | No | Ask: System Settings, Apple Account, iCloud, Advanced Data Protection |
| Windows Recall turned off | Yes (Windows) | `Get-WindowsOptionalFeature -Online -FeatureName Recall` |
| Use a password manager (1Password or Bitwarden; not LastPass) | Partly | App present in `/Applications` or login items; flag LastPass if found |
| No passwords in plain text (Word docs, spreadsheets, TextExpander, paper) | No | Ask. Never grep documents for passwords |
| SSH private key has a strong passphrase; key and passphrase never stored together | No | Ask. Reading the key file to test for encryption violates the secret-safety rule; the person runs `ssh-keygen -y -f ~/.ssh/<key>` themselves and confirms it prompts |
| 2FA on WP.com, Google Workspace, Slack, GitHub (no SMS; prefer WebAuthn or a hardware key) | No | Ask. Account-side, not device-side |
| Recovery codes printed, not stored online | No | Ask |
| Home router firmware current, default password changed, port forwards reviewed | No | Ask |
| VPN on public Wi-Fi; privacy screen in public; no a8c devices in Mainland China | No | Out of scope for a device check |
| Anti-virus (VIP team only; Apple devices exempt since Oct 2025) | Yes, where applicable | XProtect/MRT versions on macOS; Defender status on Windows |

The *Yes* rows become the baseline table in the report. The *No* rows become the short self-attestation list at the end (yes/no questions, not checks).
