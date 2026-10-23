param([ValidateSet('serve','node','agent')][string]$Mode='serve')
$ErrorActionPreference='Stop'
$name="FRPPortal-$Mode"
Stop-Service $name -ErrorAction SilentlyContinue
& sc.exe delete $name
if($LASTEXITCODE -ne 0){throw '删除服务失败，请确认管理员权限及服务名称'}
Write-Host '服务已移除，程序、配置、日志、状态和数据库保留。'
