param(
 [Parameter(Mandatory)][string]$Source,
 [Parameter(Mandatory)][string]$Verifier,
 [Parameter(Mandatory)][string]$PublicKey,
 [Parameter(Mandatory)][string]$Config,
 [ValidateSet('serve','node','agent')][string]$Mode='serve'
)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw '请在管理员 PowerShell 中运行'}
if($env:PROCESSOR_ARCHITECTURE -ne 'AMD64'){throw '当前仅提供 Windows amd64 安装'}
$sourcePath=(Resolve-Path -LiteralPath $Source).Path
$verifierPath=(Resolve-Path -LiteralPath $Verifier).Path
$keyPath=(Resolve-Path -LiteralPath $PublicKey).Path
$configPath=(Resolve-Path -LiteralPath $Config).Path
& $verifierPath verify --key $keyPath --manifest (Join-Path $sourcePath 'SHA256SUMS')
if($LASTEXITCODE -ne 0){throw '签名或文件校验失败'}
if(-not (Get-Content -LiteralPath (Join-Path $sourcePath 'SHA256SUMS') | Where-Object {$_ -match '^[a-fA-F0-9]{64}\s+portal\.exe$'})){throw 'portal.exe 未列入签名清单'}
$versionOutput=& (Join-Path $sourcePath 'portal.exe') version
if($LASTEXITCODE -ne 0 -or $versionOutput -notmatch '^portal 0\.2\.0; frp 0\.71\.1$'){throw '安装包与当前安装脚本版本不兼容；请使用该版本配套脚本'}
$root=Join-Path $env:ProgramData "FRPPortal-$Mode"
$release=Join-Path $root ('releases\'+(Get-Date -Format 'yyyyMMddHHmmssfff'))
$state=Join-Path $root 'state';$logs=Join-Path $root 'logs';$serviceName="FRPPortal-$Mode"
New-Item -ItemType Directory -Force $release,$state,$logs | Out-Null
$destConfig=Join-Path $root 'config.json'
if(-not (Test-Path -LiteralPath $destConfig)){Copy-Item -LiteralPath $configPath -Destination $destConfig}
# Protect secrets from other desktop users; the service can read config but write only state/logs.
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' | Out-Null
if($LASTEXITCODE -ne 0){throw '设置目录权限失败'}
& icacls.exe $state /grant '*S-1-5-19:(OI)(CI)M' | Out-Null
& icacls.exe $logs /grant '*S-1-5-19:(OI)(CI)M' | Out-Null
$prior=Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
if(-not $prior){
 $cfg=Get-Content -LiteralPath $destConfig -Raw | ConvertFrom-Json
 if($Mode -eq 'serve'){
  $listenHost,$listenPort=$cfg.listen -split ':(?=[^:]+$)'
  $probe=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($listenHost.Trim('[',']')),[int]$listenPort)
  try{$probe.Start()}finally{$probe.Stop()}
 }
}
Copy-Item -LiteralPath (Join-Path $sourcePath 'portal.exe') -Destination (Join-Path $release 'portal.exe')
Copy-Item -LiteralPath $destConfig -Destination (Join-Path $root ('config.backup-'+(Get-Date -Format 'yyyyMMddHHmmssfff')+'.json'))
$oldPath=if($prior){$prior.PathName}else{''}
$oldPath | Set-Content -LiteralPath (Join-Path $root 'previous-service-path.txt') -Encoding UTF8
$binary=Join-Path $release 'portal.exe';$log=Join-Path $logs "$Mode.log"
$binPath='"'+$binary+'" '+$Mode+' --config "'+$destConfig+'" --log-file "'+$log+'" --service'
if($prior){Stop-Service $serviceName -ErrorAction SilentlyContinue; & sc.exe config $serviceName binPath= $binPath start= auto | Out-Null}
else{& sc.exe create $serviceName binPath= $binPath start= auto obj= 'NT AUTHORITY\LocalService' | Out-Null}
if($LASTEXITCODE -ne 0){throw '注册服务失败'}
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
try{Start-Service $serviceName;Start-Sleep -Seconds 3;if((Get-Service $serviceName).Status -ne 'Running'){throw '服务未保持运行'}}
catch{
 Stop-Service $serviceName -ErrorAction SilentlyContinue
 if($oldPath){& sc.exe config $serviceName binPath= $oldPath | Out-Null;Start-Service $serviceName}
 throw "新版本启动失败，已尝试恢复旧服务路径。检查 $log。原错误：$_"
}
Write-Host "服务已安装；原配置保留在 $destConfig。还需确认 healthz 及真实隧道连通。"
