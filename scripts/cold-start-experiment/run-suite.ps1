# run-suite.ps1 (rev2) -- runs the ordinary `npm test` under the step's own pwsh shell and stamps each output line with the
# UTC millisecond at which this script received it. Output is passed through to the job log; the stamped copy stays on the
# runner (it may contain paths and is never uploaded).
#
# Exit code. npm is invoked as the native `npm.cmd` (resolved to its absolute path), so $LASTEXITCODE is npm's own process
# exit code, not a value relayed through the npm.ps1 script wrapper that bare `npm` resolves to in pwsh. That code is written
# to -ExitFile unchanged and returned. As a SECONDARY safeguard only, if npm exits 0 while a "FAIL - " line was printed, this
# script exits 1 and says so; the native code is still recorded as it was.
#
# Decoding. pwsh decodes a native command's output with [Console]::OutputEncoding; it is set to UTF-8 (no BOM) for the
# duration of the call so the suite's UTF-8 output (e.g. "parent↔child") is decoded as written, then restored. This changes
# only how this wrapper reads the output, not the suite's environment. Its behaviour on the hosted runner is unobserved.
#
# Timing caveat. A line's arrival time is when this reader received it, after npm, the pipe and pwsh's asynchronous reader;
# that latency is not measured, so stamps are only an approximate cross-check for the experiment.
param(
  [Parameter(Mandatory = $true)][string]$StampFile,
  [Parameter(Mandatory = $true)][string]$ExitFile,
  [Parameter(Mandatory = $true)][string]$CheckFile
)
$ErrorActionPreference = 'Continue'
$utf8 = [System.Text.UTF8Encoding]::new($false)
$npmCmd = (Get-Command -Name 'npm.cmd' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
if ($null -eq $npmCmd) {
  [System.IO.File]::WriteAllText($ExitFile, 'unknown', $utf8)
  [System.IO.File]::WriteAllText($CheckFile, 'npm-cmd-not-found', $utf8)
  Write-Output 'EXPERIMENT: npm.cmd was not found; the suite did not run'
  exit 1
}
$writer = [System.IO.StreamWriter]::new($StampFile, $false, $utf8)
$writer.AutoFlush = $true
$previousEncoding = [Console]::OutputEncoding
$code = $null
$failLines = 0
try {
  try { [Console]::OutputEncoding = $utf8 } catch { Write-Output 'EXPERIMENT: could not set UTF-8 output decoding; continuing with the default' }
  & $npmCmd.Source test 2>&1 | ForEach-Object {
    $t = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $line = [string]$_
    if ($line -match '^\s*FAIL - ') { $failLines++ }
    $writer.WriteLine("$t`t$line")
    $line
  }
  $code = $LASTEXITCODE
} finally {
  try { [Console]::OutputEncoding = $previousEncoding } catch { }
  $writer.Dispose()
}
$exitText = if ($null -eq $code) { 'unknown' } else { [string]$code }
[System.IO.File]::WriteAllText($ExitFile, $exitText, $utf8)
$inconsistent = ($null -ne $code -and $code -eq 0 -and $failLines -gt 0)
[System.IO.File]::WriteAllText($CheckFile, ("fail-lines={0} inconsistent={1}" -f $failLines, $(if ($inconsistent) { 'yes' } else { 'no' })), $utf8)
if ($null -eq $code) { exit 1 }
if ($inconsistent) { Write-Output "EXPERIMENT GUARD: npm exited 0 but $failLines FAIL line(s) were printed; failing this step (native exit code recorded as 0)"; exit 1 }
exit $code
