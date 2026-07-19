param(
  [Parameter(Mandatory = $true)][string]$Server,
  [Parameter(Mandatory = $true)][string]$Ticket
)

$ErrorActionPreference = "Stop"
$Server = $Server.TrimEnd("/")

function ConvertFrom-OpenCodeJsonC([string]$Text) {
  if ([string]::IsNullOrWhiteSpace($Text)) { return [pscustomobject]@{} }
  $clean = New-Object System.Text.StringBuilder
  $inString = $false
  $escaped = $false
  for ($i = 0; $i -lt $Text.Length; $i++) {
    $c = $Text[$i]
    $next = if ($i + 1 -lt $Text.Length) { $Text[$i + 1] } else { [char]0 }
    if ($inString) {
      [void]$clean.Append($c)
      if ($escaped) { $escaped = $false; continue }
      if ($c -eq '\') { $escaped = $true; continue }
      if ($c -eq '"') { $inString = $false }
      continue
    }
    if ($c -eq '"') { $inString = $true; [void]$clean.Append($c); continue }
    if ($c -eq '/' -and $next -eq '/') {
      $i += 2
      while ($i -lt $Text.Length -and $Text[$i] -ne "`n") { $i++ }
      [void]$clean.Append("`n")
      continue
    }
    if ($c -eq '/' -and $next -eq '*') {
      $i += 2
      while ($i + 1 -lt $Text.Length -and -not ($Text[$i] -eq '*' -and $Text[$i + 1] -eq '/')) { $i++ }
      $i++
      continue
    }
    [void]$clean.Append($c)
  }

  $withoutComments = $clean.ToString()
  $result = New-Object System.Text.StringBuilder
  $inString = $false
  $escaped = $false
  for ($i = 0; $i -lt $withoutComments.Length; $i++) {
    $c = $withoutComments[$i]
    if ($inString) {
      [void]$result.Append($c)
      if ($escaped) { $escaped = $false; continue }
      if ($c -eq '\') { $escaped = $true; continue }
      if ($c -eq '"') { $inString = $false }
      continue
    }
    if ($c -eq '"') { $inString = $true; [void]$result.Append($c); continue }
    if ($c -eq ',') {
      $j = $i + 1
      while ($j -lt $withoutComments.Length -and [char]::IsWhiteSpace($withoutComments[$j])) { $j++ }
      if ($j -lt $withoutComments.Length -and ($withoutComments[$j] -eq '}' -or $withoutComments[$j] -eq ']')) { continue }
    }
    [void]$result.Append($c)
  }
  return $result.ToString() | ConvertFrom-Json
}

$configDir = Join-Path $env:USERPROFILE ".config\opencode"
$jsonPath = Join-Path $configDir "opencode.json"
$jsoncPath = Join-Path $configDir "opencode.jsonc"
if ((Test-Path $jsonPath) -and (Test-Path $jsoncPath)) {
  throw "Both opencode.json and opencode.jsonc exist. Keep only the active global config, then run this command again."
}
$configPath = if (Test-Path $jsonPath) { $jsonPath } elseif (Test-Path $jsoncPath) { $jsoncPath } else { $jsonPath }
$config = if (Test-Path $configPath) { ConvertFrom-OpenCodeJsonC ([IO.File]::ReadAllText($configPath)) } else { [pscustomobject]@{} }
if ($null -eq $config -or $config -is [System.Array]) { throw "The OpenCode global config must be a JSON object." }
if ($null -ne $config.PSObject.Properties["provider"] -and $null -ne $config.provider -and $config.provider -isnot [pscustomobject]) {
  throw "The provider field in the OpenCode global config must be a JSON object."
}

$payload = @{ ticket = $Ticket; base_url = $Server } | ConvertTo-Json -Compress
$enrollment = Invoke-RestMethod -Uri "$Server/api/client/enroll" -Method Post -ContentType "application/json" -Body $payload

New-Item -ItemType Directory -Force $configDir | Out-Null
$tokenPath = Join-Path $configDir "opencodeproxy.token"
[IO.File]::WriteAllText($tokenPath, [string]$enrollment.proxy_token, (New-Object System.Text.UTF8Encoding($false)))
try {
  $account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  & icacls.exe $tokenPath /inheritance:r /grant:r "${account}:(R,W)" | Out-Null
} catch {
  Write-Warning "Could not restrict the token file ACL automatically: $($_.Exception.Message)"
}

if ($null -eq $config.PSObject.Properties["provider"] -or $null -eq $config.provider) {
  $config | Add-Member -Force -NotePropertyName provider -NotePropertyValue ([pscustomobject]@{})
}
foreach ($item in $enrollment.providers.PSObject.Properties) {
  $config.provider | Add-Member -Force -NotePropertyName $item.Name -NotePropertyValue $item.Value
}
if ($null -eq $config.PSObject.Properties["model"] -or [string]::IsNullOrWhiteSpace([string]$config.model)) {
  $config | Add-Member -Force -NotePropertyName model -NotePropertyValue ([string]$enrollment.default_model)
}

if (Test-Path $configPath) {
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  Copy-Item $configPath "$configPath.bak-$stamp"
}
$rendered = $config | ConvertTo-Json -Depth 100
$tempPath = "$configPath.tmp"
[IO.File]::WriteAllText($tempPath, $rendered, (New-Object System.Text.UTF8Encoding($false)))
Move-Item -Force $tempPath $configPath

Write-Host "OpencodeProxy configured successfully." -ForegroundColor Green
Write-Host "Config: $configPath"
Write-Host "Token:  $tokenPath"
Write-Host "Restart OpenCode, then run /models and select OpencodeProxy."
