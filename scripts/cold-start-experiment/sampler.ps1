# sampler.ps1 (rev2) -- cold-start experiment sampler (pwsh 7; never Windows PowerShell 5.1).
#
# Writes one JSON line per sample to -OutFile from raw WMI performance classes:
#   Win32_PerfRawData_PerfProc_Process   Name, IDProcess, CreatingProcessID, PercentProcessorTime, Timestamp_Sys100NS,
#                                        ElapsedTime, Timestamp_Object, Frequency_Object (creation identity: PERF_ELAPSED_TIME's raw
#                                        value is the start time in the object time base; elapsed = (Timestamp_Object - raw) / Frequency_Object)
#   Win32_PerfRawData_PerfOS_Processor   Name, PercentProcessorTime, Timestamp_Sys100NS
#   Win32_PerfRawData_PerfOS_System      ProcessorQueueLength
#   Win32_PerfRawData_PerfDisk_PhysicalDisk (_Total)  CurrentDiskQueueLength
# Raw classes are enumerated afresh on every sample, so processes that start after the sampler (the helper) are
# seen, and every process row carries its PID and creating PID, so identity never depends on an instance name.
# The first line records each counter's CounterType qualifier as read from the class, so the summarizer can
# refuse to derive a rate from a counter whose type is not the one its formula assumes.
#
# Wall-clock: t0/t1 are [DateTimeOffset]::UtcNow milliseconds immediately before and after the queries of one
# sample; the counters were read somewhere inside [t0, t1]. Timestamp_Sys100NS is used only for durations.
#
# Bounded: stops at -MaxSeconds or when -StopFile exists, whichever comes first. It starts no process, kills
# nothing and reads no command lines, user names or paths. Errors are recorded as exception TYPE names only.
param(
  [Parameter(Mandatory = $true)][string]$OutFile,
  [Parameter(Mandatory = $true)][string]$StopFile,
  [ValidateRange(60, 1800)][int]$MaxSeconds = 1500,
  [ValidateRange(500, 5000)][int]$IntervalMs = 1000
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$deadline = [DateTime]::UtcNow.AddSeconds($MaxSeconds)
$enc = [System.Text.UTF8Encoding]::new($false)
function Write-Line($obj) { [System.IO.File]::AppendAllText($OutFile, ($obj | ConvertTo-Json -Compress -Depth 5) + "`n", $enc) }

$types = [ordered]@{}
$wanted = @(
  @('Win32_PerfRawData_PerfProc_Process', 'PercentProcessorTime'),
  @('Win32_PerfRawData_PerfProc_Process', 'ElapsedTime'),
  @('Win32_PerfRawData_PerfOS_Processor', 'PercentProcessorTime'),
  @('Win32_PerfRawData_PerfOS_System', 'ProcessorQueueLength'),
  @('Win32_PerfRawData_PerfDisk_PhysicalDisk', 'CurrentDiskQueueLength')
)
foreach ($w in $wanted) {
  $key = $w[0] + '.' + $w[1]
  try {
    $q = (Get-CimClass -ClassName $w[0]).CimClassProperties[$w[1]].Qualifiers['CounterType']
    $types[$key] = if ($null -ne $q) { [int64]$q.Value } else { $null }
  } catch { $types[$key] = $null }
}
Write-Line ([ordered]@{ kind = 'meta'; version = 2; intervalMs = $IntervalMs; maxSeconds = $MaxSeconds; logicalProcessors = [Environment]::ProcessorCount; counterTypes = $types })

$seq = 0
$errors = 0
while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath $StopFile)) {
  $seq++
  $rec = [ordered]@{ kind = 'sample'; seq = $seq; t0 = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }
  try {
    $rec.procs = @(Get-CimInstance -ClassName Win32_PerfRawData_PerfProc_Process -Property Name, IDProcess, CreatingProcessID, PercentProcessorTime, Timestamp_Sys100NS, ElapsedTime, Timestamp_Object, Frequency_Object |
      Where-Object { $_.Name -ne '_Total' } |
      ForEach-Object { [ordered]@{ n = ($_.Name -replace '#\d+$', ''); pid = [int64]$_.IDProcess; ppid = [int64]$_.CreatingProcessID; cpu = [uint64]$_.PercentProcessorTime; ts = [uint64]$_.Timestamp_Sys100NS; et = [uint64]$_.ElapsedTime; to = [uint64]$_.Timestamp_Object; fo = [uint64]$_.Frequency_Object } })
  } catch { $rec.procsError = $_.Exception.GetType().Name; $errors++ }
  try {
    $rec.cores = @(Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Processor -Property Name, PercentProcessorTime, Timestamp_Sys100NS |
      ForEach-Object { [ordered]@{ n = [string]$_.Name; idle = [uint64]$_.PercentProcessorTime; ts = [uint64]$_.Timestamp_Sys100NS } })
  } catch { $rec.coresError = $_.Exception.GetType().Name; $errors++ }
  try {
    $rec.queue = [int64](Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_System -Property ProcessorQueueLength).ProcessorQueueLength
  } catch { $rec.queueError = $_.Exception.GetType().Name; $errors++ }
  try {
    $rec.diskQueue = [int64](Get-CimInstance -ClassName Win32_PerfRawData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -Property CurrentDiskQueueLength).CurrentDiskQueueLength
  } catch { $rec.diskQueueError = $_.Exception.GetType().Name; $errors++ }
  $rec.t1 = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  Write-Line $rec
  $sleep = $IntervalMs - ($rec.t1 - $rec.t0)
  if ($sleep -gt 0) { Start-Sleep -Milliseconds $sleep }
}
$reason = if (Test-Path -LiteralPath $StopFile) { 'stop-file' } else { 'deadline' }
Write-Line ([ordered]@{ kind = 'end'; reason = $reason; samples = $seq; errors = $errors; t = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() })
