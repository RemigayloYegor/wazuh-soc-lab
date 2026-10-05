# Безопасная симуляция техник на Windows-агенте ЛАБОРАТОРИИ.
# Ничего вредного не выполняет: каждое действие порождает телеметрию и сразу убирается.
# Запуск: powershell -ExecutionPolicy Bypass -File windows-sim.ps1
$ErrorActionPreference = "Continue"

Write-Host "[T1059.001] Закодированная команда PowerShell -> правило 100101"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "soclab test"'))
powershell.exe -NoProfile -EncodedCommand $encoded

Write-Host "[T1053.005] Запланированная задача -> правило 100105"
schtasks.exe /create /tn "SoclabTest" /tr "cmd.exe /c echo soclab" /sc once /st 23:59 /f | Out-Null
schtasks.exe /delete /tn "SoclabTest" /f | Out-Null

Write-Host "[T1547.001] Ключ автозапуска Run -> правило 100104"
$run = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $run -Name "SoclabTest" -Value "C:\Windows\System32\notepad.exe"
Remove-ItemProperty -Path $run -Name "SoclabTest"

Write-Host "[T1003.001] Строка в стиле Mimikatz (без самого Mimikatz) -> правило 100102"
cmd.exe /c "echo privilege::debug sekurlsa::logonpasswords > nul"

Write-Host "Готово. Проверьте Threat Hunting в Wazuh Dashboard: rule.groups: soclab"
