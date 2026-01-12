# PWSH Alert Manager (Notification Tool)

Email alert handler for PowerShell automations that prevents inbox spam by applying **cooldowns**, **business-hours rules**, and **digest notifications** off-hours/weekends. It’s designed to be easy to integrate into existing scripts (often just a few lines).

## What it does

For each automation/script that uses this tool, it maintains a small registration folder containing:

- **Registration** (who to notify, subject prefix, email profile)
- **Policy** (working hours/off-hours/weekends behavior, throttling)
- **State** (last run, per-alert last sent, pending digests, history)
- A simple **flag file** to represent “alert is active”

With this, you can get behavior like:

- Send the **first alert immediately** (even off-hours/weekends).
- While the alert stays active, **repeat** only every *N* minutes during business hours.
- Off-hours / weekends: switch to **digest mode** (send one summary every *M* minutes) instead of repeated spam.
- When the alert clears, send a **resolved** notification (and update state/history).

## Repository layout (expected)

- `Alert-NotificationTool.ps1` – core engine (config, policy/state, email sending).
- `Config/config.conf` – global configuration (created automatically on first run if missing).
- `Registrations/` – per-script folders created automatically at runtime (state, policy, registration).

> Tip: The tool will create missing config and registration files on first run so you can start quickly and then edit the generated files.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Ability to send email via SMTP
- Optional: **MailKit + MimeKit** DLLs if you use the `mailkit` provider

## Quick start

1. **Clone / copy** this repository to a known location on the machine that runs your scheduled tasks.

2. Run your automation script and dot-source or import the tool, then call the notification cycle entrypoint.

   Example (pattern):
   ```powershell
   # In your automation script
   . "C:\Path\To\PWSH_AlertManager\Alert-NotificationTool.ps1"

   # Start the notification cycle (the function name/params may vary depending on your script version)
   Start-AlertNotificationCycle
   ```

3. On first run, the tool will generate:
   - `Config/config.conf`
   - `Registrations/<ScriptId>/Registration.json`
   - `Registrations/<ScriptId>/Policy.json`
   - `Registrations/<ScriptId>/State.json`

4. Edit `Config/config.conf` to configure SMTP and defaults.

## Global configuration (`Config/config.conf`)

This repo uses an INI-style config at:

- `Config/config.conf`

A default file is generated automatically if missing.

### Key settings

Top-level:
- `DefaultRecipients` – comma-separated email list used as defaults for new script registrations
- `SubjectPrefixFormat` – supports `{ScriptId}` replacement (default `[{ScriptId}]`)
- `DefaultEmailProfile` – profile name (default `default`)

Core email:
- `[Email] Provider` – set to `mailkit` to use MailKit, or leave blank for legacy/no-provider behavior
- `[Email] FromAddress`, `[Email] FromName`

SMTP:
- `[Smtp] Host`, `Port`, `UseStartTls`, `UseSsl`
- `[Smtp] AuthMode`:
  - `trusted` / `none` – no auth (relay/trusted)
  - `basic` – Username + Password or PasswordEnvVar
  - `defaultCredentials` – Windows integrated credentials
  - `credentialXml` – load PSCredential from `CredentialXmlPath`
- `[Smtp] TimeoutSeconds`

MailKit (only if `Provider=mailkit`):
- `[MailKit] MimeKitDllPath`
- `[MailKit] MailKitDllPath`

### Using `PasswordEnvVar` (recommended)

Instead of storing SMTP passwords in a file:
- Set `PasswordEnvVar=MY_SMTP_PASSWORD`
- Then set environment variable `MY_SMTP_PASSWORD` on the host.

### Using `credentialXml` auth mode

Create:
```powershell
Get-Credential | Export-Clixml -Path C:\Secure\smtp-credential.xml
```

Then configure:
- `AuthMode=credentialXml`
- `CredentialXmlPath=C:\Secure\smtp-credential.xml`

> Note: the credential can only be imported under the same Windows user context (DPAPI scope) that created it.

## Per-script registration and policy

The tool identifies the calling script and uses the file name (without extension) as the **ScriptId** by default.

Each script gets a folder under:
- `Registrations/<ScriptId>/`

Files:
- `Registration.json` – recipients, subject prefix, email profile, paths
- `Policy.json` – business rules
- `State.json` – last sent timestamps, per-alert throttling, history
- `ALERT_ACTIVE.flag` – indicates an active alert (exact semantics depend on your automation)

### Default policy behavior

The default policy is designed for “don’t spam people” while still notifying quickly:

- **First alert:** send immediately (even off-hours/weekends)
- **Working hours:** immediate mode, per-alert minimum repeat interval (default 120 minutes)
- **Off-hours:** digest mode (default 240 minutes)
- **Weekends:** digest mode (default 720 minutes)

Retention defaults:
- Keep resolved alerts for 14 days
- Cap stored history events (default 200)
- Cap stored body length (default 4000 chars)

## Diagnostics / troubleshooting

Two environment variables control diagnostics:

- `NOTIFICATION_TOOL_DIAGNOSTICS`
  - Default: enabled
  - Set to `0`, `false`, `off`, `no` to disable

- `NOTIFICATION_TOOL_DIAGNOSTICS_VERBOSE`
  - Default: disabled
  - Set to `1`, `true`, `on`, `yes` to enable verbose-only messages

Diagnostics are written via `Write-Host` (and `Write-Verbose`) and also appended into an in-memory `Notifier.Diagnostics` field when available.

## Overriding the tool root

By default, the tool uses `$PSScriptRoot` as its root (where config/registrations live).

You can override with:
- `NOTIFICATION_TOOL_ROOT`

This is useful for tests or nonstandard deployments.

## Security notes

- Prefer `PasswordEnvVar` or `credentialXml` rather than saving plain passwords in config.
- If you store credentials, restrict ACLs on `Config/` and `Registrations/` directories.
- Be mindful that alert history may include truncated copies of message bodies.

## Contributing

Issues and PRs are welcome. When contributing changes:
- Keep backward compatibility for existing `Registrations/*` state where feasible.
- Avoid hardcoding environment/org-specific defaults in code.
- Add diagnostics messages for behavior decisions (throttle/digest/windowing).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
