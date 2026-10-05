# Установка Sysmon с конфигом лаборатории на Windows-агент.
# Запуск от администратора: powershell -ExecutionPolicy Bypass -File install-sysmon.ps1
$ErrorActionPreference = "Stop"

$config = Join-Path $PSScriptRoot "..\config\sysmon-config.xml"
$work = Join-Path $env:TEMP "sysmon"
New-Item -ItemType Directory -Force $work | Out-Null

# Официальный дистрибутив Sysinternals
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$work\Sysmon.zip"
Expand-Archive "$work\Sysmon.zip" -DestinationPath $work -Force

if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    # Уже установлен — только обновляем конфиг
    & "$work\Sysmon64.exe" -c $config
} else {
    & "$work\Sysmon64.exe" -accepteula -i $config
}

Restart-Service WazuhSvc -ErrorAction SilentlyContinue
Write-Host "Sysmon установлен, агент Wazuh перезапущен"
