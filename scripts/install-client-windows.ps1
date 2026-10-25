param([string]$ControlUrl='https://frpc.hhse.top')
$ErrorActionPreference='Stop'
if(-not $ControlUrl.StartsWith('https://')){throw '平台地址必须以 https:// 开头'}
$source=Split-Path $PSScriptRoot -Parent
$target=Join-Path $env:LOCALAPPDATA 'FRPPortal\bin'
New-Item -ItemType Directory -Force -Path $target | Out-Null
if(Get-ScheduledTask -TaskName 'FRPPortal-Client' -ErrorAction SilentlyContinue){Stop-ScheduledTask -TaskName 'FRPPortal-Client' -ErrorAction SilentlyContinue}
foreach($name in @('portal.exe','frpc.exe')){
 $from=Join-Path $source $name
 if(-not (Test-Path -LiteralPath $from)){throw "客户端压缩包缺少 $name"}
 Copy-Item -LiteralPath $from -Destination (Join-Path $target $name) -Force
}
$portal=Join-Path $target 'portal.exe'
& $portal connect --control-url $ControlUrl --setup-only
if($LASTEXITCODE -ne 0){throw '设备绑定失败；请检查网络和五分钟绑定码'}
$config=Join-Path $env:APPDATA 'frp-portal\agent.json'
$log=Join-Path (Split-Path $target -Parent) 'agent.log'
$action=New-ScheduledTaskAction -Execute $portal -Argument ('agent --config "'+$config+'" --log-file "'+$log+'"')
$trigger=New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
$principal=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName 'FRPPortal-Client' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName 'FRPPortal-Client'
Write-Host '客户端已安装并开始运行；下次登录 Windows 会自动启动。'
Write-Host '状态：打开任务计划程序，查看 FRPPortal-Client。'
