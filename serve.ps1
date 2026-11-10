param([int]$Port = 8080)
& (Join-Path $PSScriptRoot 'server.ps1') -Port $Port
