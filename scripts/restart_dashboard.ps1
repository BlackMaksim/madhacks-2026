[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8501
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
$dashboardPath = Join-Path $projectRoot 'app\dashboard.py'
$dashboardUrl = "http://localhost:$Port"
$healthUrl = "http://127.0.0.1:$Port/_stcore/health"

if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    throw 'Project Python was not found. Follow the Windows setup in README.md first.'
}

# The absolute script path and explicit port identify this checkout, even when
# Windows runs Streamlit in a child of the virtual environment's Python launcher.
$escapedPath = [regex]::Escape($dashboardPath)
$commandPattern = '(?i)\s-m\s+streamlit\s+run\s+"?' + $escapedPath +
    '"?\s+--server\.port=' + $Port + '(?:\s|$)'
$runningDashboard = @(
    Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" |
        Where-Object CommandLine -Match $commandPattern
)

# Stop the worker. The virtual environment's launcher exits with it.
foreach ($server in $runningDashboard) {
    if ($server.ProcessId -notin $runningDashboard.ParentProcessId) {
        Stop-Process -Id $server.ProcessId -ErrorAction SilentlyContinue
    }
}
foreach ($server in $runningDashboard) {
    Wait-Process -Id $server.ProcessId -Timeout 5 -ErrorAction SilentlyContinue
}

$portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
$portProbe.ExclusiveAddressUse = $true
try {
    $portProbe.Start()
}
catch {
    throw "Port $Port is unavailable. If you started Streamlit manually, stop it with Ctrl+C in its terminal and try again."
}
finally {
    $portProbe.Stop()
}

$logDirectory = Join-Path $projectRoot 'data\dashboard-runtime'
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$stdoutLog = Join-Path $logDirectory "streamlit-$Port.out.log"
$stderrLog = Join-Path $logDirectory "streamlit-$Port.err.log"
$streamlitArgs = @(
    '-m', 'streamlit', 'run', ('"{0}"' -f $dashboardPath),
    "--server.port=$Port", '--server.address=127.0.0.1',
    '--server.headless=true', '--browser.gatherUsageStats=false'
)
$dashboardProcess = Start-Process -FilePath $pythonPath -ArgumentList $streamlitArgs `
    -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog

for ($attempt = 0; $attempt -lt 20; $attempt++) {
    if ($dashboardProcess.HasExited) {
        throw "Streamlit exited during startup. See $stderrLog"
    }
    try {
        $health = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 1
        if ($health.StatusCode -eq 200 -and $health.Content.Trim() -eq 'ok') {
            Write-Output "EdgeSentinel dashboard is ready at $dashboardUrl"
            return
        }
    }
    catch {
        # The process may still be starting.
    }
    Start-Sleep -Milliseconds 300
}

throw "The dashboard did not respond at $dashboardUrl. See $stderrLog"
