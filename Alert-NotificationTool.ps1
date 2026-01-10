
function Read-JsonFile {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Path,
		[Parameter(Mandatory = $true)]
		[object]$Default
	)

	try {
		if (-not (Test-Path -LiteralPath $Path)) {
			return $Default
		}
		$content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
		if ([string]::IsNullOrWhiteSpace($content)) {
			return $Default
		}
		return ($content | ConvertFrom-Json -ErrorAction Stop)
	}
	catch {
		return $Default
	}
}

function Read-ConfFile {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Path
	)

	if (-not (Test-Path -LiteralPath $Path)) {
		return $null
	}

	$section = ''
	$map = @{}
	$lines = Get-Content -LiteralPath $Path -ErrorAction Stop
	foreach ($raw in $lines) {
		$line = $raw.Trim()
		if ([string]::IsNullOrWhiteSpace($line)) { continue }
		if ($line.StartsWith('#') -or $line.StartsWith(';')) { continue }

		if ($line.StartsWith('[') -and $line.EndsWith(']')) {
			$section = $line.Substring(1, $line.Length - 2).Trim()
			continue
		}

		$eq = $line.IndexOf('=')
		if ($eq -lt 1) { continue }
		$key = $line.Substring(0, $eq).Trim()
		$value = $line.Substring($eq + 1).Trim()
		# Strip matching quotes
		if ($value.Length -ge 2) {
			if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
				$value = $value.Substring(1, $value.Length - 2)
			}
		}

		$fullKey = if ([string]::IsNullOrWhiteSpace($section)) { $key } else { "$section.$key" }
		$map[$fullKey] = $value
	}

	return $map
}

function Convert-ConfValueToBool {
	param([string]$Value)
	if ($null -eq $Value) { return $null }
	$v = $Value.Trim().ToLowerInvariant()
	if ($v -in @('1','true','yes','y','on')) { return $true }
	if ($v -in @('0','false','no','n','off')) { return $false }
	return $null
}

function Convert-ConfValueToInt {
	param([string]$Value)
	if ($null -eq $Value) { return $null }
	try { return [int]$Value } catch { return $null }
}

function Split-ConfCsv {
	param([string]$Value)
	if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
	return @($Value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Test-NotificationToolDiagnosticsEnabled {
	try {
		# Default: ON (write reasons every run).
		# Disable explicitly with: NOTIFICATION_TOOL_DIAGNOSTICS=0 (or false/off/no)
		$v = $env:NOTIFICATION_TOOL_DIAGNOSTICS
		if ([string]::IsNullOrWhiteSpace($v)) { return $true }
		$v = $v.Trim().ToLowerInvariant()
		if ($v -in @('0', 'false', 'no', 'n', 'off')) { return $false }
		if ($v -in @('1', 'true', 'yes', 'y', 'on')) { return $true }
		return $true
	}
	catch {
		return $true
	}
}

function Test-NotificationToolDiagnosticsVerboseEnabled {
	try {
		$v = $env:NOTIFICATION_TOOL_DIAGNOSTICS_VERBOSE
		if ([string]::IsNullOrWhiteSpace($v)) { return $false }
		$v = $v.Trim().ToLowerInvariant()
		return ($v -in @('1', 'true', 'yes', 'y', 'on'))
	}
	catch {
		return $false
	}
}

function Write-NotificationToolDiagnostic {
	param(
		[Parameter(Mandatory = $true)][object]$Notifier,
		[Parameter(Mandatory = $true)][string]$Message,
		[switch]$VerboseOnly
	)
	try {
		if ($VerboseOnly -and -not (Test-NotificationToolDiagnosticsVerboseEnabled)) {
			return
		}
		if (-not (Test-NotificationToolDiagnosticsEnabled)) {
			return
		}
		$ts = (Get-Date).ToString('o')
		$line = "[$ts] $Message"
		if ($Notifier -and $Notifier.PSObject.Properties.Match('Diagnostics').Count -gt 0) {
			$Notifier.Diagnostics = @($Notifier.Diagnostics + $line)
		}
		Write-Verbose $line
		Write-Host $line
	}
	catch { }
}

function Write-TextFileAtomic {
	param(
		[Parameter(Mandatory = $true)][string]$Path,
		[Parameter(Mandatory = $true)][string]$Content
	)

	$dir = Split-Path -Path $Path -Parent
	if ($dir -and -not (Test-Path -LiteralPath $dir)) {
		New-Item -ItemType Directory -Path $dir -Force | Out-Null
	}
	$tmp = "$Path.tmp"
	$Content | Set-Content -LiteralPath $tmp -Encoding UTF8
	Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function New-DefaultNotificationToolConfigConfText {
	return @'
# Notification Tool global configuration (INI-style)
#
# Notes:
# - Use comma-separated lists where applicable (example: DefaultRecipients=a@b.com,b@c.com).
# - Consider using PasswordEnvVar instead of Password for Task Scheduler.

DefaultRecipients=
SubjectPrefixFormat=[{ScriptId}]

# Default email profile name to use (see profile sections below)
DefaultEmailProfile=default

[Email]
Provider=
FromAddress=
FromName=

[Smtp]
Host=
Port=587
UseStartTls=true
UseSsl=false

# AuthMode:
# - trusted: do not authenticate (relay/trusted connection)
# - none: same as trusted
# - basic: authenticate with Username + Password/PasswordEnvVar
# - defaultCredentials: authenticate with the current user (Windows integrated auth)
# - credentialXml: authenticate using a PSCredential loaded from CredentialXmlPath
AuthMode=trusted
Username=
Password=
PasswordEnvVar=

# CredentialXmlPath notes:
# - Create with: Get-Credential | Export-Clixml -Path C:\Path\To\smtp-credential.xml
# - Import uses the Windows DPAPI scope of the user who created it.
CredentialXmlPath=
TimeoutSeconds=60

[MailKit]
MimeKitDllPath=
MailKitDllPath=

# Additional profiles (optional):
#
# [Email:secondary]
# Provider=mailkit
# FromAddress=
# FromName=
#
# [Smtp:secondary]
# Host=
# Port=587
# UseStartTls=true
# UseSsl=false
# AuthMode=trusted
# Username=
# Password=
# PasswordEnvVar=
# CredentialXmlPath=
# TimeoutSeconds=60
#
# [MailKit:secondary]
# MimeKitDllPath=
# MailKitDllPath=
'@
}

function Write-JsonFileAtomic {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Path,
		[Parameter(Mandatory = $true)]
		[object]$Object
	)

	$dir = Split-Path -Path $Path -Parent
	if ($dir -and -not (Test-Path -LiteralPath $dir)) {
		New-Item -ItemType Directory -Path $dir -Force | Out-Null
	}

	$tmp = "$Path.tmp"
	$Object | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $tmp -Encoding UTF8
	Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Convert-ToTimeSpan {
	param([Parameter(Mandatory = $true)][string]$Time)
	try {
		return [TimeSpan]::Parse($Time)
	}
	catch {
		throw "Invalid time format '$Time' (expected HH:mm or HH:mm:ss)."
	}
}

function Get-LocalNow {
	param([string]$TimeZoneId)
	$utc = (Get-Date).ToUniversalTime()
	if ([string]::IsNullOrWhiteSpace($TimeZoneId)) {
		return [pscustomobject]@{ Utc = $utc; Local = (Get-Date) }
	}

	try {
		$tz = [System.TimeZoneInfo]::FindSystemTimeZoneById($TimeZoneId)
		$local = [System.TimeZoneInfo]::ConvertTimeFromUtc($utc, $tz)
		return [pscustomobject]@{ Utc = $utc; Local = $local; TimeZone = $tz }
	}
	catch {
		return [pscustomobject]@{ Utc = $utc; Local = (Get-Date) }
	}
}

function Convert-ToUtcDateTime {
	param([Parameter(Mandatory = $true)][object]$Text)
	if ($null -eq $Text) { return $null }
	if ($Text -is [datetimeoffset]) { return $Text.UtcDateTime }
	if ($Text -is [datetime]) {
		try {
			# Our persisted fields are named *Utc and are intended to represent UTC clock time.
			# ConvertFrom-Json can yield DateTime values with Kind=Local but without shifting the clock.
			# To avoid double-converting and producing negative elapsed times, treat DateTime values as UTC clock.
			if ($Text.Kind -eq [DateTimeKind]::Utc) { return $Text }
			return [datetime]::SpecifyKind($Text, [DateTimeKind]::Utc)
		}
		catch { return $null }
	}
	$str = [string]$Text
	if ([string]::IsNullOrWhiteSpace($str)) { return $null }
	try {
		return ([datetimeoffset]::Parse($str)).UtcDateTime
	}
	catch {
		try {
			$styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
			return [datetime]::Parse($str, [Globalization.CultureInfo]::InvariantCulture, $styles)
		}
		catch {
			return $null
		}
	}
}

function Test-InWindow {
	param(
		[Parameter(Mandatory = $true)][datetime]$LocalNow,
		[Parameter(Mandatory = $true)][TimeSpan]$Start,
		[Parameter(Mandatory = $true)][TimeSpan]$End
	)

	$time = $LocalNow.TimeOfDay
	if ($Start -eq $End) { return $true }
	if ($Start -lt $End) {
		return ($time -ge $Start -and $time -lt $End)
	}
	return ($time -ge $Start -or $time -lt $End)
}

function Get-NotificationToolRoot {
	# Allow tests / nonstandard deployments to override.
	if ($env:NOTIFICATION_TOOL_ROOT -and -not [string]::IsNullOrWhiteSpace($env:NOTIFICATION_TOOL_ROOT)) {
		return $env:NOTIFICATION_TOOL_ROOT
	}
	return $PSScriptRoot
}

function Get-NotificationToolConfigPath {
	$root = Get-NotificationToolRoot
	Join-Path (Join-Path $root 'Config') 'config.conf'
}

function New-DefaultNotificationToolConfig {
	[pscustomobject]@{
		Version = 3
		DefaultRecipients = @()
		SubjectPrefixFormat = '[{ScriptId}]'
		DefaultEmailProfile = 'default'
		EmailProfiles = @{}
		Email = [pscustomobject]@{
			Provider = '' # 'mailkit' or '' (no built-in provider)
			FromAddress = ''
			FromName = ''
			Smtp = [pscustomobject]@{
				Host = ''
				Port = 587
				UseStartTls = $true
				UseSsl = $false
				AuthMode = '' # trusted|none|basic|defaultCredentials|credentialXml (blank => legacy behavior)
				Username = ''
				Password = ''
				PasswordEnvVar = ''
				CredentialXmlPath = ''
				TimeoutSeconds = 60
			}
			MailKit = [pscustomobject]@{
				MimeKitDllPath = ''
				MailKitDllPath = ''
			}
		}
	}
}

function Get-NotificationToolConfig {
	$path = Get-NotificationToolConfigPath
	$default = New-DefaultNotificationToolConfig

	# Back-compat: if old NotificationToolConfig.json exists, use it unless config.conf exists.
	$legacyPath = Join-Path (Get-NotificationToolRoot) 'NotificationToolConfig.json'
	$config = $null
	if (Test-Path -LiteralPath $path) {
		try {
			$conf = Read-ConfFile -Path $path
			if ($conf) {
				$config = $default
				$config.DefaultRecipients = Split-ConfCsv $conf['DefaultRecipients']
				if ($conf.ContainsKey('SubjectPrefixFormat')) { $config.SubjectPrefixFormat = $conf['SubjectPrefixFormat'] }
				if ($conf.ContainsKey('DefaultEmailProfile')) { $config.DefaultEmailProfile = $conf['DefaultEmailProfile'] }

				if ($conf.ContainsKey('Email.Provider')) { $config.Email.Provider = $conf['Email.Provider'] }
				if ($conf.ContainsKey('Email.FromAddress')) { $config.Email.FromAddress = $conf['Email.FromAddress'] }
				if ($conf.ContainsKey('Email.FromName')) { $config.Email.FromName = $conf['Email.FromName'] }

				if ($conf.ContainsKey('Smtp.Host')) { $config.Email.Smtp.Host = $conf['Smtp.Host'] }
				if ($conf.ContainsKey('Smtp.Port')) {
					$port = Convert-ConfValueToInt $conf['Smtp.Port']
					if ($port -ne $null) { $config.Email.Smtp.Port = $port }
				}
				if ($conf.ContainsKey('Smtp.UseStartTls')) {
					$val = Convert-ConfValueToBool $conf['Smtp.UseStartTls']
					if ($val -ne $null) { $config.Email.Smtp.UseStartTls = $val }
				}
				if ($conf.ContainsKey('Smtp.UseSsl')) {
					$val = Convert-ConfValueToBool $conf['Smtp.UseSsl']
					if ($val -ne $null) { $config.Email.Smtp.UseSsl = $val }
				}
				if ($conf.ContainsKey('Smtp.Username')) { $config.Email.Smtp.Username = $conf['Smtp.Username'] }
				if ($conf.ContainsKey('Smtp.Password')) { $config.Email.Smtp.Password = $conf['Smtp.Password'] }
				if ($conf.ContainsKey('Smtp.PasswordEnvVar')) { $config.Email.Smtp.PasswordEnvVar = $conf['Smtp.PasswordEnvVar'] }
				if ($conf.ContainsKey('Smtp.AuthMode')) { $config.Email.Smtp.AuthMode = $conf['Smtp.AuthMode'] }
				if ($conf.ContainsKey('Smtp.CredentialXmlPath')) { $config.Email.Smtp.CredentialXmlPath = $conf['Smtp.CredentialXmlPath'] }
				if ($conf.ContainsKey('Smtp.TimeoutSeconds')) {
					$to = Convert-ConfValueToInt $conf['Smtp.TimeoutSeconds']
					if ($to -ne $null) { $config.Email.Smtp.TimeoutSeconds = $to }
				}

				if ($conf.ContainsKey('MailKit.MimeKitDllPath')) { $config.Email.MailKit.MimeKitDllPath = $conf['MailKit.MimeKitDllPath'] }
				if ($conf.ContainsKey('MailKit.MailKitDllPath')) { $config.Email.MailKit.MailKitDllPath = $conf['MailKit.MailKitDllPath'] }

				# Profiles: allow any number of sections like [Email:profileName], [Smtp:profileName], [MailKit:profileName]
				$config.EmailProfiles = @{}
				$config.EmailProfiles['default'] = $config.Email
				$profileNames = New-Object System.Collections.Generic.HashSet[string]
				foreach ($k in @($conf.Keys)) {
					if ($k -match '^(Email|Smtp|MailKit):([^\.]+)\.') {
						[void]$profileNames.Add($Matches[2])
					}
				}
				foreach ($profileName in $profileNames) {
					try {
						$profile = ($config.Email | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
					}
					catch {
						$profile = (New-DefaultNotificationToolConfig).Email
					}

					$ek = "Email:$profileName"
					$sk = "Smtp:$profileName"
					$mk = "MailKit:$profileName"

					if ($conf.ContainsKey("$ek.Provider")) { $profile.Provider = $conf["$ek.Provider"] }
					if ($conf.ContainsKey("$ek.FromAddress")) { $profile.FromAddress = $conf["$ek.FromAddress"] }
					if ($conf.ContainsKey("$ek.FromName")) { $profile.FromName = $conf["$ek.FromName"] }

					if ($conf.ContainsKey("$sk.Host")) { $profile.Smtp.Host = $conf["$sk.Host"] }
					if ($conf.ContainsKey("$sk.Port")) {
						$port = Convert-ConfValueToInt $conf["$sk.Port"]
						if ($port -ne $null) { $profile.Smtp.Port = $port }
					}
					if ($conf.ContainsKey("$sk.UseStartTls")) {
						$val = Convert-ConfValueToBool $conf["$sk.UseStartTls"]
						if ($val -ne $null) { $profile.Smtp.UseStartTls = $val }
					}
					if ($conf.ContainsKey("$sk.UseSsl")) {
						$val = Convert-ConfValueToBool $conf["$sk.UseSsl"]
						if ($val -ne $null) { $profile.Smtp.UseSsl = $val }
					}
					if ($conf.ContainsKey("$sk.AuthMode")) { $profile.Smtp.AuthMode = $conf["$sk.AuthMode"] }
					if ($conf.ContainsKey("$sk.Username")) { $profile.Smtp.Username = $conf["$sk.Username"] }
					if ($conf.ContainsKey("$sk.Password")) { $profile.Smtp.Password = $conf["$sk.Password"] }
					if ($conf.ContainsKey("$sk.PasswordEnvVar")) { $profile.Smtp.PasswordEnvVar = $conf["$sk.PasswordEnvVar"] }
					if ($conf.ContainsKey("$sk.CredentialXmlPath")) { $profile.Smtp.CredentialXmlPath = $conf["$sk.CredentialXmlPath"] }
					if ($conf.ContainsKey("$sk.TimeoutSeconds")) {
						$to = Convert-ConfValueToInt $conf["$sk.TimeoutSeconds"]
						if ($to -ne $null) { $profile.Smtp.TimeoutSeconds = $to }
					}

					if ($conf.ContainsKey("$mk.MimeKitDllPath")) { $profile.MailKit.MimeKitDllPath = $conf["$mk.MimeKitDllPath"] }
					if ($conf.ContainsKey("$mk.MailKitDllPath")) { $profile.MailKit.MailKitDllPath = $conf["$mk.MailKitDllPath"] }

					$config.EmailProfiles[$profileName] = $profile
				}

				# Back-compat: set $config.Email to the configured default profile if it exists.
				$defProfile = $config.DefaultEmailProfile
				if (-not [string]::IsNullOrWhiteSpace($defProfile) -and $config.EmailProfiles.ContainsKey($defProfile)) {
					$config.Email = $config.EmailProfiles[$defProfile]
				}
			}
		}
		catch {
			$config = $null
		}
	}

	if (-not $config -and -not (Test-Path -LiteralPath $path) -and (Test-Path -LiteralPath $legacyPath)) {
		$config = Read-JsonFile -Path $legacyPath -Default $default
	}
	if (-not $config) {
		$config = $default
	}

	# Ensure config directory + file exist (in linux-style conf format)
	if (-not (Test-Path -LiteralPath $path)) {
		Write-TextFileAtomic -Path $path -Content (New-DefaultNotificationToolConfigConfText)
	}

	# Guarantee required fields (but do not hardcode org-specific values in code)
	if ($null -eq $config.DefaultRecipients) {
		$config.DefaultRecipients = @()
	}
	if (-not $config.SubjectPrefixFormat) {
		$config.SubjectPrefixFormat = '[{ScriptId}]'
	}
	if (-not $config.Version) { $config.Version = 3 }
	if (-not $config.DefaultEmailProfile) { $config | Add-Member -NotePropertyName DefaultEmailProfile -NotePropertyValue 'default' -Force }
	if (-not $config.EmailProfiles) { $config | Add-Member -NotePropertyName EmailProfiles -NotePropertyValue @{} -Force }
	if (-not $config.Email) {
		$config | Add-Member -NotePropertyName Email -NotePropertyValue (New-DefaultNotificationToolConfig).Email -Force
	}
	if (-not $config.Email.Smtp) {
		$config.Email | Add-Member -NotePropertyName Smtp -NotePropertyValue (New-DefaultNotificationToolConfig).Email.Smtp -Force
	}
	if (-not $config.Email.MailKit) {
		$config.Email | Add-Member -NotePropertyName MailKit -NotePropertyValue (New-DefaultNotificationToolConfig).Email.MailKit -Force
	}
	# Ensure the default profile exists in the in-memory map.
	try {
		if (-not $config.EmailProfiles.ContainsKey('default')) {
			$config.EmailProfiles['default'] = $config.Email
		}
	}
	catch { }

	return $config
}

function Get-NotificationToolSmtpPassword {
	param([Parameter(Mandatory = $true)][object]$Config)
	try {
		$pwd = $Config.Email.Smtp.Password
		if ($pwd -and -not [string]::IsNullOrWhiteSpace($pwd)) {
			return $pwd
		}
		$envName = $Config.Email.Smtp.PasswordEnvVar
		if ($envName -and -not [string]::IsNullOrWhiteSpace($envName)) {
			return [Environment]::GetEnvironmentVariable($envName)
		}
	}
	catch { }
	return $null
}

function Get-NotificationToolSmtpPasswordFromSmtp {
	param([Parameter(Mandatory = $true)][object]$Smtp)
	try {
		$pwd = $Smtp.Password
		if ($pwd -and -not [string]::IsNullOrWhiteSpace($pwd)) {
			return $pwd
		}
		$envName = $Smtp.PasswordEnvVar
		if ($envName -and -not [string]::IsNullOrWhiteSpace($envName)) {
			return [Environment]::GetEnvironmentVariable($envName)
		}
	}
	catch { }
	return $null
}

function Get-NotificationToolCredentialFromXml {
	param([string]$CredentialXmlPath)
	if ([string]::IsNullOrWhiteSpace($CredentialXmlPath)) { return $null }
	if (-not (Test-Path -LiteralPath $CredentialXmlPath)) {
		throw "CredentialXmlPath not found: $CredentialXmlPath"
	}
	$cred = Import-Clixml -LiteralPath $CredentialXmlPath
	if ($cred -is [pscredential]) { return $cred }
	return $null
}

function Import-MailKitAssemblies {
	param(
		[Parameter(Mandatory = $true)][object]$Config,
		[object]$EmailConfig
	)

	$cfgEmail = $EmailConfig
	if (-not $cfgEmail) { $cfgEmail = $Config.Email }
	$mk = $cfgEmail.MailKit
	if (-not $mk) {
		throw 'Email.MailKit settings are missing in Config/config.conf'
	}

	$mimePath = $mk.MimeKitDllPath
	$mailPath = $mk.MailKitDllPath

	if ([string]::IsNullOrWhiteSpace($mimePath) -or [string]::IsNullOrWhiteSpace($mailPath)) {
		throw 'MailKit DLL paths not configured. Set Email.MailKit.MimeKitDllPath and Email.MailKit.MailKitDllPath in Config/config.conf'
	}
	if (-not (Test-Path -LiteralPath $mimePath)) {
		throw "MimeKit DLL not found at: $mimePath"
	}
	if (-not (Test-Path -LiteralPath $mailPath)) {
		throw "MailKit DLL not found at: $mailPath"
	}

	# Only load once per session.
	if (-not ('MimeKit.MimeMessage' -as [type])) {
		Add-Type -LiteralPath $mimePath
	}
	if (-not ('MailKit.Net.Smtp.SmtpClient' -as [type])) {
		Add-Type -LiteralPath $mailPath
	}
}

function Send-EmailMailKit {
	param(
		[Parameter(Mandatory = $true)][object]$Config,
		[object]$EmailConfig,
		[Parameter(Mandatory = $true)][string[]]$Recipients,
		[Parameter(Mandatory = $true)][string]$Subject,
		[Parameter(Mandatory = $true)][string]$Body,
		[string]$Attachment
	)

	$cfgEmail = $EmailConfig
	if (-not $cfgEmail) { $cfgEmail = $Config.Email }

	Import-MailKitAssemblies -Config $Config -EmailConfig $cfgEmail

	$smtp = $cfgEmail.Smtp
	if (-not $smtp -or [string]::IsNullOrWhiteSpace($smtp.Host)) {
		throw 'SMTP Host not configured. Set Email.Smtp.Host in Config/config.conf'
	}

	$fromAddr = $cfgEmail.FromAddress
	if ([string]::IsNullOrWhiteSpace($fromAddr)) {
		throw 'FromAddress not configured. Set Email.FromAddress in Config/config.conf'
	}
	$fromName = $cfgEmail.FromName

	$msg = [MimeKit.MimeMessage]::new()
	if ([string]::IsNullOrWhiteSpace($fromName)) {
		$msg.From.Add([MimeKit.MailboxAddress]::new($fromAddr, $fromAddr))
	}
	else {
		$msg.From.Add([MimeKit.MailboxAddress]::new($fromName, $fromAddr))
	}

	foreach ($r in @($Recipients)) {
		if (-not [string]::IsNullOrWhiteSpace($r)) {
			$msg.To.Add([MimeKit.MailboxAddress]::new($r.Trim(), $r.Trim()))
		}
	}

	$msg.Subject = $Subject

	$builder = [MimeKit.BodyBuilder]::new()
	# Keep it simple: treat body as plain text.
	$builder.TextBody = $Body
	if ($Attachment -and (Test-Path -LiteralPath $Attachment)) {
		$null = $builder.Attachments.Add($Attachment)
	}
	$msg.Body = $builder.ToMessageBody()

	$client = [MailKit.Net.Smtp.SmtpClient]::new()
	try {
		$timeout = 60
		try { if ($smtp.TimeoutSeconds) { $timeout = [int]$smtp.TimeoutSeconds } } catch { }
		$client.Timeout = [int]($timeout * 1000)

		$port = 587
		try { if ($smtp.Port) { $port = [int]$smtp.Port } } catch { }

		$useSsl = $false
		$useStartTls = $true
		try { if ($null -ne $smtp.UseSsl) { $useSsl = [bool]$smtp.UseSsl } } catch { }
		try { if ($null -ne $smtp.UseStartTls) { $useStartTls = [bool]$smtp.UseStartTls } } catch { }

		# Connect
		if ($useSsl) {
			$client.Connect($smtp.Host, $port, $true)
		}
		elseif ($useStartTls) {
			$client.Connect($smtp.Host, $port, [MailKit.Security.SecureSocketOptions]::StartTlsWhenAvailable)
		}
		else {
			$client.Connect($smtp.Host, $port, [MailKit.Security.SecureSocketOptions]::None)
		}

		# Authenticate (optional)
		$authMode = $null
		try { $authMode = $smtp.AuthMode } catch { }
		if ([string]::IsNullOrWhiteSpace($authMode)) {
			# Legacy behavior: authenticate only if username + password are supplied.
			$user = $smtp.Username
			$pwd = Get-NotificationToolSmtpPasswordFromSmtp -Smtp $smtp
			if (-not [string]::IsNullOrWhiteSpace($user) -and -not [string]::IsNullOrWhiteSpace($pwd)) {
				$client.Authenticate($user, $pwd)
			}
		}
		else {
			$mode = $authMode.ToString().Trim().ToLowerInvariant()
			switch ($mode) {
				'trusted' { }
				'none' { }
				'basic' {
					$user = $smtp.Username
					$pwd = Get-NotificationToolSmtpPasswordFromSmtp -Smtp $smtp
					if (-not [string]::IsNullOrWhiteSpace($user) -and -not [string]::IsNullOrWhiteSpace($pwd)) {
						$client.Authenticate($user, $pwd)
					}
				}
				'defaultcredentials' {
					$client.Authenticate([System.Net.CredentialCache]::DefaultNetworkCredentials)
				}
				'credentialxml' {
					$cred = Get-NotificationToolCredentialFromXml -CredentialXmlPath $smtp.CredentialXmlPath
					if (-not $cred) { throw 'CredentialXmlPath did not load a PSCredential' }
					$net = $cred.GetNetworkCredential()
					$client.Authenticate($net.UserName, $net.Password)
				}
				default { }
			}
		}

		$client.Send($msg)
	}
	finally {
		try { $client.Disconnect($true) } catch { }
		$client.Dispose()
	}
}

function Get-CallsiteScriptPath {
	# Attempt to resolve the calling automation script path with minimal/no parameters.
	try {
		$stack = @(Get-PSCallStack)
		foreach ($frame in $stack) {
			if (-not $frame.ScriptName) { continue }
			# First script in stack that is NOT this tool.
			if ($frame.ScriptName -ne $PSCommandPath) {
				return $frame.ScriptName
			}
		}
	}
	catch { }

	# Fallback: try MyInvocation (works when called from a script).
	try {
		if ($MyInvocation -and $MyInvocation.PSCommandPath -and ($MyInvocation.PSCommandPath -ne $PSCommandPath)) {
			return $MyInvocation.PSCommandPath
		}
	}
	catch { }

	return $null
}

function Get-ScriptKeyFromPath {
	param([Parameter(Mandatory = $true)][string]$ScriptPath)

	$norm = $ScriptPath.ToLowerInvariant()
	$bytes = [System.Text.Encoding]::UTF8.GetBytes($norm)
	$sha1 = [System.Security.Cryptography.SHA1]::Create()
	try {
		$hash = $sha1.ComputeHash($bytes)
		return (-join ($hash | ForEach-Object { $_.ToString('x2') })).Substring(0, 8)
	}
	finally {
		$sha1.Dispose()
	}
}

function New-DefaultAlertPolicy {
	# Business policy defaults:
	# - Send first alert immediately (even off-hours/weekends)
	# - Then repeat per-alert every 2 hours during business hours
	# - Then digest every 4 hours off-hours
	# - Then digest every 12 hours on weekends
	[pscustomobject]@{
		Version = 2
		TimeZoneId = ''
		WorkingHours = [pscustomobject]@{
			Enabled = $true
			DaysOfWeek = @('Monday','Tuesday','Wednesday','Thursday','Friday')
			Start = '07:00'
			End = '18:00'
		}
		OffHours = [pscustomobject]@{
			Mode = 'digest' # digest|none
			DigestMinMinutes = 240
		}
		Weekends = [pscustomobject]@{
			Mode = 'digest' # digest|none
			DigestMinMinutes = 720
		}
		Throttle = [pscustomobject]@{
			PerAlertMinMinutes = 120
			AlwaysSendFirstImmediately = $true
		}
		Retention = [pscustomobject]@{
			ResolvedKeepDays = 14
			MaxHistoryEvents = 200
			MaxStoredBodyChars = 4000
		}
	}
}

function Limit-NotificationToolStoredText {
	param(
		[string]$Text,
		[int]$MaxChars,
		[string]$Label
	)
	if ($null -eq $Text) { return $null }
	if ($MaxChars -le 0) { return '' }
	try {
		if ($Text.Length -le $MaxChars) { return $Text }
		$prefixLen = [math]::Max(0, $MaxChars - 64)
		$prefix = if ($prefixLen -gt 0) { $Text.Substring(0, $prefixLen) } else { '' }
		$suffix = "`r`n...[truncated $Label; originalLength=$($Text.Length) chars]"
		return ($prefix + $suffix)
	}
	catch {
		return $Text
	}
}

function New-DefaultAlertState {
	[pscustomobject]@{
		Version = 2
		LastRunUtc = $null
		LastDigestSentUtc = $null
		PendingDigestSinceUtc = $null
		FlagWasPresentLastRun = $false
		Alerts = @{} # key -> object
		History = @() # capped
	}
}

function Get-NotificationMode {
	param(
		[Parameter(Mandatory = $true)][object]$Policy,
		[Parameter(Mandatory = $true)][datetime]$LocalNow
	)

	$day = $LocalNow.DayOfWeek.ToString()
	$isWeekend = ($day -eq 'Saturday' -or $day -eq 'Sunday')

	if ($Policy.WorkingHours -and $Policy.WorkingHours.Enabled) {
		$days = @($Policy.WorkingHours.DaysOfWeek)
		$start = Convert-ToTimeSpan -Time $Policy.WorkingHours.Start
		$end = Convert-ToTimeSpan -Time $Policy.WorkingHours.End
		$inDay = ($days -contains $day)
		if ($inDay -and (Test-InWindow -LocalNow $LocalNow -Start $start -End $end)) {
			return [pscustomobject]@{ Mode = 'immediate' }
		}
	}

	if ($isWeekend -and $Policy.Weekends) {
		return [pscustomobject]@{ Mode = $Policy.Weekends.Mode; DigestMinMinutes = $Policy.Weekends.DigestMinMinutes }
	}
	if ($Policy.OffHours) {
		return [pscustomobject]@{ Mode = $Policy.OffHours.Mode; DigestMinMinutes = $Policy.OffHours.DigestMinMinutes }
	}
	return [pscustomobject]@{ Mode = 'digest'; DigestMinMinutes = 240 }
}

function Add-AlertHistoryEvent {
	param(
		[Parameter(Mandatory = $true)][object]$State,
		[Parameter(Mandatory = $true)][object]$Policy,
		[Parameter(Mandatory = $true)][string]$Key,
		[Parameter(Mandatory = $true)][string]$EventType,
		[Parameter(Mandatory = $true)][datetime]$UtcNow,
		[string]$Subject,
		[string]$Body
	)

	$maxBody = 4000
	try { if ($Policy.Retention.MaxStoredBodyChars) { $maxBody = [int]$Policy.Retention.MaxStoredBodyChars } } catch { }
	$safeBody = Limit-NotificationToolStoredText -Text $Body -MaxChars $maxBody -Label 'body'

	$evt = [pscustomobject]@{
		Utc = $UtcNow.ToString('o')
		Key = $Key
		Type = $EventType # Triggered|Resolved|Reset
		Subject = $Subject
		Body = $safeBody
	}

	$State.History = @($State.History + $evt)
	$max = $Policy.Retention.MaxHistoryEvents
	if (-not $max) { $max = 200 }
	if ($State.History.Count -gt $max) {
		$State.History = @($State.History | Select-Object -Last $max)
	}
}

function Get-OrCreateScriptFolder {
	param(
		[Parameter(Mandatory = $true)][string]$ScriptPath,
		[Parameter(Mandatory = $true)][string]$ScriptId
	)

	$root = Get-NotificationToolRoot
	$registrationsRoot = Join-Path $root 'Registrations'
	if (-not (Test-Path -LiteralPath $registrationsRoot)) {
		New-Item -ItemType Directory -Path $registrationsRoot -Force | Out-Null
	}

	$folder = Join-Path $registrationsRoot $ScriptId
	if (-not (Test-Path -LiteralPath $folder)) {
		New-Item -ItemType Directory -Path $folder -Force | Out-Null
		return $folder
	}

	# If the folder exists but belongs to a different script path, use a suffix folder to avoid collisions.
	$regPath = Join-Path $folder 'Registration.json'
	if (Test-Path -LiteralPath $regPath) {
		try {
			$existing = Get-Content -LiteralPath $regPath -Raw | ConvertFrom-Json
			if ($existing.ScriptPath -and ($existing.ScriptPath -ne $ScriptPath)) {
				$suffix = Get-ScriptKeyFromPath -ScriptPath $ScriptPath
					$folder2 = Join-Path $registrationsRoot ("{0}-{1}" -f $ScriptId, $suffix)
				if (-not (Test-Path -LiteralPath $folder2)) {
					New-Item -ItemType Directory -Path $folder2 -Force | Out-Null
				}
				return $folder2
			}
		}
		catch { }
	}

	return $folder
}

function Get-AlertNotificationPolicy {
	param([Parameter(Mandatory = $true)][string]$PolicyPath)
	$default = New-DefaultAlertPolicy
	$policy = Read-JsonFile -Path $PolicyPath -Default $default
	if (-not (Test-Path -LiteralPath $PolicyPath)) {
		Write-JsonFileAtomic -Path $PolicyPath -Object $policy
	}
	return $policy
}

function Get-AlertNotificationState {
	param([Parameter(Mandatory = $true)][string]$StatePath)
	$default = New-DefaultAlertState
	$state = Read-JsonFile -Path $StatePath -Default $default
	if (-not $state.Alerts) { $state | Add-Member -NotePropertyName Alerts -NotePropertyValue @{} -Force }
	# Convert JSON "{}" PSCustomObject into a hashtable so callers can use .ContainsKey/.Keys.
	if ($state.Alerts -and -not ($state.Alerts -is [hashtable])) {
		try {
			$ht = @{}
			foreach ($prop in @($state.Alerts.PSObject.Properties)) {
				$ht[$prop.Name] = $prop.Value
			}
			$state.Alerts = $ht
		}
		catch {
			$state.Alerts = @{}
		}
	}
	if (-not $state.History) { $state | Add-Member -NotePropertyName History -NotePropertyValue @() -Force }
	if ($null -eq $state.FlagWasPresentLastRun) { $state | Add-Member -NotePropertyName FlagWasPresentLastRun -NotePropertyValue $false -Force }
	if (-not (Test-Path -LiteralPath $StatePath)) {
		Write-JsonFileAtomic -Path $StatePath -Object $state
	}
	return $state
}

function Get-OrCreateRegistration {
	param(
		[Parameter(Mandatory = $true)][string]$ScriptPath
	)

	$cfg = Get-NotificationToolConfig
	$scriptId = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)
	$folder = Get-OrCreateScriptFolder -ScriptPath $ScriptPath -ScriptId $scriptId

	$registrationPath = Join-Path $folder 'Registration.json'
	$policyPath = Join-Path $folder 'Policy.json'
	$statePath = Join-Path $folder 'State.json'
	$flagPath = Join-Path $folder 'ALERT_ACTIVE.flag'

	$defaultRecipients = @($cfg.DefaultRecipients)
	$subjectPrefix = $cfg.SubjectPrefixFormat -replace '\{ScriptId\}', $scriptId

	$default = [pscustomobject]@{
		Version = 2
		ScriptId = $scriptId
		ScriptPath = $ScriptPath
		EmailProfile = $cfg.DefaultEmailProfile
		Recipients = @($defaultRecipients)
		SubjectPrefix = $subjectPrefix
		PolicyPath = $policyPath
		StatePath = $statePath
		AlertFlagPath = $flagPath
	}

	$reg = Read-JsonFile -Path $registrationPath -Default $default

	# Ensure critical fields.
	if (-not $reg.ScriptId) { $reg | Add-Member -NotePropertyName ScriptId -NotePropertyValue $scriptId -Force }
	if (-not $reg.ScriptPath) { $reg | Add-Member -NotePropertyName ScriptPath -NotePropertyValue $ScriptPath -Force }
	if ($null -eq $reg.EmailProfile) { $reg | Add-Member -NotePropertyName EmailProfile -NotePropertyValue $cfg.DefaultEmailProfile -Force }
	if (-not $reg.PolicyPath) { $reg | Add-Member -NotePropertyName PolicyPath -NotePropertyValue $policyPath -Force }
	if (-not $reg.StatePath) { $reg | Add-Member -NotePropertyName StatePath -NotePropertyValue $statePath -Force }
	if (-not $reg.AlertFlagPath) { $reg | Add-Member -NotePropertyName AlertFlagPath -NotePropertyValue $flagPath -Force }
	if (-not $reg.SubjectPrefix) { $reg | Add-Member -NotePropertyName SubjectPrefix -NotePropertyValue $subjectPrefix -Force }
	if ($null -eq $reg.Recipients) { $reg | Add-Member -NotePropertyName Recipients -NotePropertyValue @($defaultRecipients) -Force }

	if (-not (Test-Path -LiteralPath $registrationPath)) {
		Write-JsonFileAtomic -Path $registrationPath -Object $reg
	}

	return $reg
}

function Start-AlertNotificationCycle {
	[CmdletBinding()]
	param(
		[scriptblock]$EmailSender,
		[switch]$AutoCompleteOnExit,
		[switch]$DisableAutoCompleteOnExit
	)

	$scriptPath = Get-CallsiteScriptPath
	if (-not $scriptPath) {
		$scriptPath = 'Interactive'
	}

	# If the caller is a script (Task Scheduler, automation, etc), default to auto-completing on exit so the
	# flag/state lifecycle is always maintained even when no alerts are added.
	# Opt out with -DisableAutoCompleteOnExit.
	$shouldAutoCompleteOnExit = $false
	if (-not $DisableAutoCompleteOnExit) {
		if ($AutoCompleteOnExit) {
			$shouldAutoCompleteOnExit = $true
		}
		elseif ($scriptPath -ne 'Interactive') {
			$shouldAutoCompleteOnExit = $true
		}
	}

	$reg = Get-OrCreateRegistration -ScriptPath $scriptPath
	$policy = Get-AlertNotificationPolicy -PolicyPath $reg.PolicyPath
	$state = Get-AlertNotificationState -StatePath $reg.StatePath
	$times = Get-LocalNow -TimeZoneId $policy.TimeZoneId

	$notifier = [pscustomobject]@{
		Registration = $reg
		Policy = $policy
		StatePath = $reg.StatePath
		State = $state
		UtcNow = $times.Utc
		LocalNow = $times.Local
		ObservedKeys = @{}
		RunAlerts = @{}
		EmailSender = $EmailSender
		Diagnostics = @()
		AutoCompleteOnExit = [bool]$shouldAutoCompleteOnExit
		__Completed = $false
		Abort = $false
	}

		if ($shouldAutoCompleteOnExit) {
			try {
				# Register an exit handler so scripts can omit calling Complete-AlertNotificationCycle.
			Register-EngineEvent -SourceIdentifier PowerShell.Exiting -MessageData $notifier -SupportEvent -Action {
					try {
						$n = $event.MessageData
						if ($null -eq $n) { return }
						if ($n.Abort) { return }
						if ($n.__Completed) { return }
						Complete-AlertNotificationCycle -Notifier $n
					}
					catch { }
			} | Out-Null
			}
			catch { }
		}

		return $notifier
}

function Add-AlertNotification {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)][object]$Notifier,
		[Parameter(Mandatory = $true)][string]$Key,
		[Parameter(Mandatory = $true)][string]$Subject,
		[Parameter(Mandatory = $true)][string]$Body,
		  [scriptblock]$AttachmentBuilder,
		  [switch]$ProcessNow
	)

	$utcNow = $Notifier.UtcNow
	$state = $Notifier.State
	$policy = $Notifier.Policy

	$Notifier.ObservedKeys[$Key] = $true
	$Notifier.RunAlerts[$Key] = [pscustomobject]@{
		Subject = $Subject
		Body = $Body
		AttachmentBuilder = $AttachmentBuilder
	}

	$maxBody = 4000
	try { if ($policy.Retention.MaxStoredBodyChars) { $maxBody = [int]$policy.Retention.MaxStoredBodyChars } } catch { }
	$storedBody = Limit-NotificationToolStoredText -Text $Body -MaxChars $maxBody -Label 'body'

	$existing = $null
	if ($state.Alerts.ContainsKey($Key)) {
		$existing = $state.Alerts[$Key]
	}

	if (-not $existing) {
		$existing = [pscustomobject]@{
			Key = $Key
			Status = 'Active'
			FirstSeenUtc = $utcNow.ToString('o')
			LastSeenUtc = $utcNow.ToString('o')
			Count = 1
			LastSentUtc = $null
			LastSubject = $Subject
			LastBody = $storedBody
			LastTransitionUtc = $utcNow.ToString('o')
		}
		$state.Alerts[$Key] = $existing
		Add-AlertHistoryEvent -State $state -Policy $policy -Key $Key -EventType 'Triggered' -UtcNow $utcNow -Subject $Subject -Body $Body
	}
	else {
		if ($existing.Status -ne 'Active') {
			$existing.Status = 'Active'
			$existing.FirstSeenUtc = $utcNow.ToString('o')
			$existing.Count = 0
			# Treat re-activation as a new incident: allow a new first-send.
			$existing.LastSentUtc = $null
			$existing.LastTransitionUtc = $utcNow.ToString('o')
			Add-AlertHistoryEvent -State $state -Policy $policy -Key $Key -EventType 'Triggered' -UtcNow $utcNow -Subject $Subject -Body $Body
		}
		$existing.LastSeenUtc = $utcNow.ToString('o')
		$existing.Count = [int]$existing.Count + 1
		$existing.LastSubject = $Subject
		$existing.LastBody = $storedBody
		$state.Alerts[$Key] = $existing
	}

	# Any off-hours/weekend activity should set pending digest.
	$mode = Get-NotificationMode -Policy $policy -LocalNow $Notifier.LocalNow
	# Note: Add-AlertNotification only queues alerts. Send/no-send reasons are evaluated in Complete-AlertNotificationCycle.
	Write-NotificationToolDiagnostic -Notifier $Notifier -Message "Queued alert '$Key' (mode=$($mode.Mode))" -VerboseOnly
	if ($mode.Mode -ne 'immediate') {
		if (-not $state.PendingDigestSinceUtc) {
			$state.PendingDigestSinceUtc = $utcNow.ToString('o')
		}
	}

	if ($ProcessNow) {
		Complete-AlertNotificationCycle -Notifier $Notifier
	}
}

function Resolve-UnobservedAlerts {
	param(
		[Parameter(Mandatory = $true)][object]$Notifier,
		[Parameter(Mandatory = $true)][string]$CurrentMode
	)

	$utcNow = $Notifier.UtcNow
	$state = $Notifier.State
	$policy = $Notifier.Policy

	foreach ($key in @($state.Alerts.Keys)) {
		$alert = $state.Alerts[$key]
		if ($alert.Status -eq 'Active' -and -not $Notifier.ObservedKeys.ContainsKey($key)) {
			$alert.Status = 'Resolved'
			$alert.LastTransitionUtc = $utcNow.ToString('o')
			$state.Alerts[$key] = $alert
			Add-AlertHistoryEvent -State $state -Policy $policy -Key $key -EventType 'Resolved' -UtcNow $utcNow -Subject $alert.LastSubject -Body $alert.LastBody

			# Only track pending digests for off-hours/weekends.
			# In working hours, we do not want a digest to auto-send just because something resolved.
			if ($CurrentMode -ne 'immediate') {
				if (-not $state.PendingDigestSinceUtc) {
					$state.PendingDigestSinceUtc = $utcNow.ToString('o')
				}
			}
		}
	}
}

function Build-DigestBody {
	param(
		[Parameter(Mandatory = $true)][object]$Notifier,
		[Parameter(Mandatory = $true)][datetime]$SinceUtc
	)

	$state = $Notifier.State
	$utcNow = $Notifier.UtcNow

	$lines = @()
	$lines += "Digest window: $($SinceUtc.ToString('o')) -> $($utcNow.ToString('o'))"
	$lines += ''

	$triggered = @($state.History | Where-Object { $_.Type -eq 'Triggered' -and ((Convert-ToUtcDateTime -Text $_.Utc) -ge $SinceUtc) })
	$resolved = @($state.History | Where-Object { $_.Type -eq 'Resolved' -and ((Convert-ToUtcDateTime -Text $_.Utc) -ge $SinceUtc) })
	$active = @($state.Alerts.Values | Where-Object { $_.Status -eq 'Active' })

	if ($triggered.Count -gt 0) {
		$lines += 'New/Reactived alerts:'
		foreach ($e in $triggered) {
			$lines += "- [$($e.Utc)] $($e.Key): $($e.Subject)"
		}
		$lines += ''
	}
	if ($resolved.Count -gt 0) {
		$lines += 'Resolved alerts:'
		foreach ($e in $resolved) {
			$lines += "- [$($e.Utc)] $($e.Key): $($e.Subject)"
		}
		$lines += ''
	}
	if ($active.Count -gt 0) {
		$lines += 'Currently active alerts:'
		foreach ($a in ($active | Sort-Object Key)) {
			$lines += "- $($a.Key) (first=$($a.FirstSeenUtc) last=$($a.LastSeenUtc) count=$($a.Count))"
		}
	}

	return ($lines -join "`r`n")
}

function Send-NotifierEmail {
	param(
		[Parameter(Mandatory = $true)][object]$Notifier,
		[Parameter(Mandatory = $true)][string]$Subject,
		[Parameter(Mandatory = $true)][string]$Body,
		[string]$Attachment
	)

	$recipients = @($Notifier.Registration.Recipients)
	if (-not $recipients -or $recipients.Count -eq 0) {
		throw 'No recipients configured. Set DefaultRecipients in Config\\config.conf or set Recipients in the per-script Registration.json.'
	}

	$emailSender = $Notifier.EmailSender
	if ($emailSender) {
		& $emailSender $recipients $Subject $Body $Attachment
		return
	}

	# Built-in provider via global config
	$cfg = $null
	try { $cfg = Get-NotificationToolConfig } catch { $cfg = $null }
	if ($cfg) {
		$profileName = $Notifier.Registration.EmailProfile
		if ([string]::IsNullOrWhiteSpace($profileName)) { $profileName = $cfg.DefaultEmailProfile }
		if ([string]::IsNullOrWhiteSpace($profileName)) { $profileName = 'default' }

		$emailCfg = $cfg.Email
		try {
			if ($cfg.EmailProfiles -and $cfg.EmailProfiles.ContainsKey($profileName)) {
				$emailCfg = $cfg.EmailProfiles[$profileName]
			}
		}
		catch { }

		if ($emailCfg -and $emailCfg.Provider -and ($emailCfg.Provider.ToString().ToLowerInvariant() -eq 'mailkit')) {
			Send-EmailMailKit -Config $cfg -EmailConfig $emailCfg -Recipients $recipients -Subject $Subject -Body $Body -Attachment $Attachment
			return
		}
	}

	throw 'No EmailSender provided and Email.Provider is not set to mailkit. Configure Config\config.conf (Email.Provider=mailkit + SMTP + MailKit DLL paths), or pass -EmailSender to Start-AlertNotificationCycle.'
}

function Resolve-NotificationToolAttachmentPath {
	param([object]$Value)
	if ($null -eq $Value) { return $null }
	try {
		if ($Value -is [string]) {
			$s = $Value
			# If something accidentally returned multi-line text, take the first non-empty line.
			if ($s -match "\r|\n") {
				$line = @($s -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) | Select-Object -First 1
				if ($line) { return $line }
			}
			return $s.Trim()
		}
		if ($Value -is [System.IO.FileInfo]) { return $Value.FullName }
		if ($Value -is [array]) {
			foreach ($v in @($Value)) {
				$p = Resolve-NotificationToolAttachmentPath -Value $v
				if ($p -and (Test-Path -LiteralPath $p)) { return $p }
			}
			return $null
		}
		return ($Value.ToString())
	}
	catch {
		return $null
	}
}

function Invoke-ManualResetIfFlagDeleted {
	param(
		[Parameter(Mandatory = $true)][object]$Notifier,
		[Parameter(Mandatory = $true)][int]$ActiveCount
	)

	$state = $Notifier.State
	$utcNow = $Notifier.UtcNow
	$flagPath = $Notifier.Registration.AlertFlagPath

	if ($ActiveCount -le 0) {
		return
	}

	$flagExists = (Test-Path -LiteralPath $flagPath)
	if ($state.FlagWasPresentLastRun -and -not $flagExists) {
		# Technician deleted the flag: treat as reset request.
		foreach ($key in @($state.Alerts.Keys)) {
			$alert = $state.Alerts[$key]
			if ($alert.Status -eq 'Active') {
				$alert.LastSentUtc = $null
				$state.Alerts[$key] = $alert
			}
		}
		$state.LastDigestSentUtc = $null
		$state.PendingDigestSinceUtc = $null
		Add-AlertHistoryEvent -State $state -Policy $Notifier.Policy -Key 'SYSTEM' -EventType 'Reset' -UtcNow $utcNow -Subject 'Manual reset via flag deletion' -Body "Flag deleted: $flagPath"
	}
}

function Ensure-AlertFlag {
	param(
		[Parameter(Mandatory = $true)][object]$Notifier,
		[Parameter(Mandatory = $true)][int]$ActiveCount
	)

	$state = $Notifier.State
	$flagPath = $Notifier.Registration.AlertFlagPath

	if ($ActiveCount -gt 0) {
		if (-not (Test-Path -LiteralPath $flagPath)) {
			New-Item -ItemType File -Path $flagPath -Force | Out-Null
		}
		$state.FlagWasPresentLastRun = $true
	}
	else {
		if (Test-Path -LiteralPath $flagPath) {
			Remove-Item -LiteralPath $flagPath -Force -ErrorAction SilentlyContinue
		}
		$state.FlagWasPresentLastRun = $false
	}
}

function Complete-AlertNotificationCycle {
	[CmdletBinding()]
	param([Parameter(Mandatory = $true)][object]$Notifier)

	if ($Notifier.Abort) {
		return
	}

	$policy = $Notifier.Policy
	$state = $Notifier.State
	$utcNow = $Notifier.UtcNow
	$mode = Get-NotificationMode -Policy $policy -LocalNow $Notifier.LocalNow
	$pendingDigestAtStart = $state.PendingDigestSinceUtc

	Resolve-UnobservedAlerts -Notifier $Notifier -CurrentMode $mode.Mode
	$state.LastRunUtc = $utcNow.ToString('o')

	$activeCount = @($state.Alerts.Values | Where-Object { $_.Status -eq 'Active' }).Count
	Invoke-ManualResetIfFlagDeleted -Notifier $Notifier -ActiveCount $activeCount
	Ensure-AlertFlag -Notifier $Notifier -ActiveCount $activeCount

	# Prune resolved alerts older than retention.
	$keepDays = $policy.Retention.ResolvedKeepDays
	if (-not $keepDays) { $keepDays = 14 }
	$cutoff = $utcNow.AddDays(-[double]$keepDays)
	foreach ($key in @($state.Alerts.Keys)) {
		$alert = $state.Alerts[$key]
		if ($alert.Status -eq 'Resolved') {
			try {
				$lt = Convert-ToUtcDateTime -Text $alert.LastTransitionUtc
				if ($lt -lt $cutoff) { $state.Alerts.Remove($key) }
			}
			catch { }
		}
	}

	$prefix = $Notifier.Registration.SubjectPrefix
	if ([string]::IsNullOrWhiteSpace($prefix)) { $prefix = "[$($Notifier.Registration.ScriptId)]" }

	# Always send the FIRST alert immediately, regardless of mode.
	$sendFirst = $true
	try {
		$sendFirst = [bool]$policy.Throttle.AlwaysSendFirstImmediately
	}
	catch { $sendFirst = $true }

	if ($sendFirst) {
		foreach ($key in @($Notifier.ObservedKeys.Keys)) {
			if (-not $state.Alerts.ContainsKey($key)) { continue }
			$alert = $state.Alerts[$key]
			if ($alert.Status -ne 'Active') { continue }
			if ($alert.LastSentUtc) {
				Write-NotificationToolDiagnostic -Notifier $Notifier -Message "Skip first-send for '$key': already sent at $($alert.LastSentUtc)."
				continue
			}

			$run = $Notifier.RunAlerts[$key]
			$subj = "$prefix $($run.Subject)"
			$attachment = $null
			try {
				if ($run.AttachmentBuilder) {
					$attachment = Resolve-NotificationToolAttachmentPath -Value (& $run.AttachmentBuilder)
					if ([string]::IsNullOrWhiteSpace($attachment)) {
						Write-NotificationToolDiagnostic -Notifier $Notifier -Message "AttachmentBuilder for '$key' returned nothing; sending without attachment."
					}
					elseif (-not (Test-Path -LiteralPath $attachment)) {
						Write-NotificationToolDiagnostic -Notifier $Notifier -Message "AttachmentBuilder for '$key' returned a path that does not exist: $attachment"
					}
					else {
						Write-NotificationToolDiagnostic -Notifier $Notifier -Message "Using attachment for '$key': $attachment" -VerboseOnly
					}
				}
				Send-NotifierEmail -Notifier $Notifier -Subject $subj -Body $run.Body -Attachment $attachment
				$alert.LastSentUtc = $utcNow.ToString('o')
				$state.Alerts[$key] = $alert
			}
			catch {
				Write-NotificationToolDiagnostic -Notifier $Notifier -Message "Send failed for '$key' (first-send): $($_.Exception.Message)"
				throw
			}
			finally {
				if ($attachment -and (Test-Path -LiteralPath $attachment)) {
					Remove-Item -LiteralPath $attachment -Force -ErrorAction SilentlyContinue
				}
			}
		}
	}

	# Decide follow-up sending.
	if ($mode.Mode -eq 'immediate') {
		$perAlertMin = $policy.Throttle.PerAlertMinMinutes
		if (-not $perAlertMin) { $perAlertMin = 120 }

		foreach ($key in @($Notifier.ObservedKeys.Keys)) {
			if (-not $state.Alerts.ContainsKey($key)) { continue }
			$alert = $state.Alerts[$key]
			if ($alert.Status -ne 'Active') { continue }

			$lastSent = $null
			if ($alert.LastSentUtc) { try { $lastSent = Convert-ToUtcDateTime -Text $alert.LastSentUtc } catch { $lastSent = $null } }
			if (-not $lastSent) {
				Write-NotificationToolDiagnostic -Notifier $Notifier -Message "Skip follow-up for '$key': no LastSentUtc recorded yet (should have been handled by first-send)."
				continue
			} # already handled by first-immediate

			$elapsed = ($utcNow - $lastSent).TotalMinutes
			if ($elapsed -lt [double]$perAlertMin) {
				$remain = [math]::Ceiling(([double]$perAlertMin - $elapsed))
				Write-NotificationToolDiagnostic -Notifier $Notifier -Message "Throttle: skip '$key'. LastSentUtc=$($alert.LastSentUtc); elapsedMin=$([math]::Round($elapsed,2)); needs $remain more minute(s)."
				continue
			}

			$run = $Notifier.RunAlerts[$key]
			$subj = "$prefix $($run.Subject)"
			$attachment = $null
			try {
				if ($run.AttachmentBuilder) {
					$attachment = Resolve-NotificationToolAttachmentPath -Value (& $run.AttachmentBuilder)
					if ([string]::IsNullOrWhiteSpace($attachment)) {
						Write-NotificationToolDiagnostic -Notifier $Notifier -Message "AttachmentBuilder for '$key' returned nothing; sending without attachment."
					}
					elseif (-not (Test-Path -LiteralPath $attachment)) {
						Write-NotificationToolDiagnostic -Notifier $Notifier -Message "AttachmentBuilder for '$key' returned a path that does not exist: $attachment"
					}
					else {
						Write-NotificationToolDiagnostic -Notifier $Notifier -Message "Using attachment for '$key': $attachment" -VerboseOnly
					}
				}
				Send-NotifierEmail -Notifier $Notifier -Subject $subj -Body $run.Body -Attachment $attachment
				$alert.LastSentUtc = $utcNow.ToString('o')
				$state.Alerts[$key] = $alert
			}
			catch {
				Write-NotificationToolDiagnostic -Notifier $Notifier -Message "Send failed for '$key' (follow-up): $($_.Exception.Message)"
				throw
			}
			finally {
				if ($attachment -and (Test-Path -LiteralPath $attachment)) {
					Remove-Item -LiteralPath $attachment -Force -ErrorAction SilentlyContinue
				}
			}
		}

		# If there was off-hours/weekend activity pending from a prior run, send one digest once back in hours.
		if ($pendingDigestAtStart) {
			try {
				$hadAttachmentAlerts = $false
				try {
					foreach ($rk in @($Notifier.RunAlerts.Keys)) {
						$ra = $Notifier.RunAlerts[$rk]
						if ($ra -and $ra.AttachmentBuilder) { $hadAttachmentAlerts = $true; break }
					}
				}
				catch { }
				if ($hadAttachmentAlerts) {
					Write-NotificationToolDiagnostic -Notifier $Notifier -Message 'Sending digest email. Note: digest emails do not include per-alert attachments.'
				}

				$sinceUtc = Convert-ToUtcDateTime -Text $pendingDigestAtStart
				$subj = "$prefix Alert digest (back in hours)"
				$body = Build-DigestBody -Notifier $Notifier -SinceUtc $sinceUtc
				Send-NotifierEmail -Notifier $Notifier -Subject $subj -Body $body -Attachment $null
				$state.LastDigestSentUtc = $utcNow.ToString('o')
				$state.PendingDigestSinceUtc = $null
			}
			catch {
				Write-NotificationToolDiagnostic -Notifier $Notifier -Message "Back-in-hours digest send failed: $($_.Exception.Message)"
			}
		}
		else {
			Write-NotificationToolDiagnostic -Notifier $Notifier -Message 'No pending digest to send when back in hours.' -VerboseOnly
		}
	}
	elseif ($mode.Mode -eq 'digest') {
		$digestMin = $mode.DigestMinMinutes
		if (-not $digestMin) { $digestMin = 240 }

		$lastDigest = $null
		if ($state.LastDigestSentUtc) { try { $lastDigest = Convert-ToUtcDateTime -Text $state.LastDigestSentUtc } catch { $lastDigest = $null } }

		$due = $false
		if (-not $lastDigest) {
			$due = $true
		}
		else {
			$elapsed = ($utcNow - $lastDigest).TotalMinutes
			$due = ($elapsed -ge [double]$digestMin)
		}

		if (-not $state.PendingDigestSinceUtc) {
			Write-NotificationToolDiagnostic -Notifier $Notifier -Message 'Digest mode: no PendingDigestSinceUtc; nothing to send.' -VerboseOnly
		}
		elseif (-not $due) {
			$nextIn = $null
			try {
				$elapsed2 = ($utcNow - $lastDigest).TotalMinutes
				$nextIn = [math]::Ceiling(([double]$digestMin - $elapsed2))
			}
			catch { }
			Write-NotificationToolDiagnostic -Notifier $Notifier -Message "Digest mode: not due yet (minMinutes=$digestMin). Next in ~$nextIn minute(s)." -VerboseOnly
		}
		elseif ($due -and $state.PendingDigestSinceUtc) {
			try {
				$hadAttachmentAlerts = $false
				try {
					foreach ($rk in @($Notifier.RunAlerts.Keys)) {
						$ra = $Notifier.RunAlerts[$rk]
						if ($ra -and $ra.AttachmentBuilder) { $hadAttachmentAlerts = $true; break }
					}
				}
				catch { }
				if ($hadAttachmentAlerts) {
					Write-NotificationToolDiagnostic -Notifier $Notifier -Message 'Sending digest email. Note: digest emails do not include per-alert attachments.'
				}

				$sinceUtc = Convert-ToUtcDateTime -Text $state.PendingDigestSinceUtc
				$activeCount2 = @($state.Alerts.Values | Where-Object { $_.Status -eq 'Active' }).Count
				$subj = "$prefix Alert digest (active=$activeCount2)"
				$body = Build-DigestBody -Notifier $Notifier -SinceUtc $sinceUtc
				Send-NotifierEmail -Notifier $Notifier -Subject $subj -Body $body -Attachment $null
				$state.LastDigestSentUtc = $utcNow.ToString('o')
				$state.PendingDigestSinceUtc = $null
			}
			catch {
				Write-NotificationToolDiagnostic -Notifier $Notifier -Message "Digest send failed: $($_.Exception.Message)"
			}
		}
	}

	Write-JsonFileAtomic -Path $Notifier.StatePath -Object $state
	# Mark completed so AutoCompleteOnExit doesn't double-process.
	try { $Notifier.__Completed = $true } catch { }
}

# Auto-registration (no emails): when a script dot-sources this file, create/update
# the per-script folder + Registration/Policy/State in NotificationTool\<ScriptName>.
# Opt-out by setting $env:NOTIFICATION_TOOL_DISABLE_AUTO_REGISTER = 1
if (-not $env:NOTIFICATION_TOOL_DISABLE_AUTO_REGISTER) {
	try {
		# Ensure global config exists/loads (no org-specific defaults hardcoded).
		$null = Get-NotificationToolConfig

		$callerPath = Get-CallsiteScriptPath
		if ($callerPath -and ($callerPath -ne $PSCommandPath)) {
			$scriptId = [System.IO.Path]::GetFileNameWithoutExtension($callerPath)
			$root = Get-NotificationToolRoot
			$regPath = Join-Path (Join-Path (Join-Path $root 'Registrations') $scriptId) 'Registration.json'

			# If already registered, do not touch disk beyond loading config.
			if (-not (Test-Path -LiteralPath $regPath)) {
				$reg0 = Get-OrCreateRegistration -ScriptPath $callerPath
				$null = Get-AlertNotificationPolicy -PolicyPath $reg0.PolicyPath
				$null = Get-AlertNotificationState -StatePath $reg0.StatePath
			}
		}
	}
	catch {
		# Never block the calling automation just because registration failed.
	}
}
