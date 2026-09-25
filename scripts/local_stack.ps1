param(
    [ValidateSet("start", "stop", "status")]
    [string]$Action = "status"
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Compose = Join-Path $Root "infra\docker\compose.platform.yml"
$Secrets = Join-Path $Root "infra\docker\secrets"

function Find-Compose {
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        & docker compose version *> $null
        if ($LASTEXITCODE -eq 0) { return @("docker", "compose") }
    }
    if (Get-Command podman -ErrorAction SilentlyContinue) {
        & podman compose version *> $null
        if ($LASTEXITCODE -eq 0) { return @("podman", "compose") }
    }
    throw "FULL_STACK_RUNTIME_MISSING: Install Docker/Podman after enabling WSL, then rerun scripts/local_stack.ps1 start."
}

function Ensure-Secret([string]$Name, [int]$Bytes = 36) {
    New-Item -ItemType Directory -Force -Path $Secrets | Out-Null
    $Path = Join-Path $Secrets $Name
    if (-not (Test-Path -LiteralPath $Path)) {
        $Buffer = New-Object byte[] $Bytes
        [Security.Cryptography.RandomNumberGenerator]::Fill($Buffer)
        $Value = [Convert]::ToBase64String($Buffer).Replace("+", "A").Replace("/", "B").TrimEnd("=")
        [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
    }
}

$Runtime = Find-Compose
$Program = $Runtime[0]
$Prefix = @()
if ($Runtime.Count -gt 1) { $Prefix = $Runtime[1..($Runtime.Count - 1)] }
$Args = @($Prefix) + @("-f", $Compose)

if ($Action -eq "start") {
    Ensure-Secret "postgres_password.txt"
    Ensure-Secret "redis_password.txt"
    Ensure-Secret "minio_user.txt" 18
    Ensure-Secret "minio_password.txt"
    Ensure-Secret "clickhouse_password.txt"
    & $Program @Args up -d --wait
    if ($LASTEXITCODE -ne 0) { throw "LOCAL_STACK_START_FAILED" }
    & $Program @Args ps
} elseif ($Action -eq "stop") {
    & $Program @Args down
    if ($LASTEXITCODE -ne 0) { throw "LOCAL_STACK_STOP_FAILED" }
} else {
    & $Program @Args ps
    if ($LASTEXITCODE -ne 0) { throw "LOCAL_STACK_STATUS_FAILED" }
}
