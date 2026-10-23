param([string]$Go='go',[string]$Out='dist')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Push-Location (Join-Path $root 'web')
try{& npm.cmd ci --ignore-scripts;if($LASTEXITCODE){throw 'npm ci failed'};& npm.cmd run build;if($LASTEXITCODE){throw 'web build failed'}}finally{Pop-Location}
Push-Location $root
try{
 & $Go mod verify;if($LASTEXITCODE){throw 'go mod verify failed'}
 & $Go test ./...;if($LASTEXITCODE){throw 'go test failed'}
 foreach($target in @(@('windows','amd64','portal.exe'),@('linux','amd64','portal'),@('linux','arm64','portal'))){
  $env:GOOS=$target[0];$env:GOARCH=$target[1];$env:CGO_ENABLED='0'
  $dir=Join-Path $Out ($target[0]+'-'+$target[1]);New-Item -ItemType Directory -Force $dir | Out-Null
  & $Go build -trimpath -ldflags='-s -w' -o (Join-Path $dir $target[2]) ./cmd/portal
  if($LASTEXITCODE){throw 'go build failed'}
 }
}finally{Remove-Item Env:GOOS,Env:GOARCH,Env:CGO_ENABLED -ErrorAction SilentlyContinue;Pop-Location}
