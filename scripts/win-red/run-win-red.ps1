#Requires -Version 7.0
# run-win-red.ps1 (rev4) -- bounded RED validation of the Windows runtime marker test.
#
# TWO POWERSHELLS, STATED. This orchestrator runs in pwsh 7 (the workflow's `shell: pwsh` on windows-latest; the
# `#Requires` line refuses anything older). The PRODUCT's consent helper -- the thing under test -- is spawned by the
# isolated test and by measure-markers.js as Windows PowerShell 5.1 (System32\WindowsPowerShell\v1.0\powershell.exe),
# exactly as the product does. Nothing here changes which PowerShell the product uses.
#
#   -HeadSha        the REVIEWED head (github.event.pull_request.head.sha). Binding target. Never github.sha.
#   -MergeSha       the checked-out commit (github.sha; on pull_request a synthetic merge). Reported, not bound.
#   -RepoPath       a local checkout containing HeadSha (after `git fetch --depth=1 origin <HeadSha>`)
#   -Work           fresh directory; raw outputs live here and are NEVER printed or uploaded wholesale
#   -Harness        directory with bound.json, predictions.json, quote-vectors.json, WinRed.cs and the *.js
#   -JobTimeoutMin  the workflow job's timeout-minutes; the time budget must fit inside it with headroom (budget.js)
#
# CONTAINMENT (R1, rev3). Every process this script launches -- git, tar, node, npm via cmd.exe, the isolated test, the
# measurement, the summarizer -- is started by WinRed.ContainedProcess (harness/WinRed.cs, compiled here with Add-Type):
# a fresh Job Object with kill-on-close, process created suspended, assigned, confirmed in the job, then resumed;
# breakaway not permitted. Cleanup is PROVEN by job accounting (ActiveProcesses reaching 0), never by sampling. CIM
# sampling of descendants is kept as a DIAGNOSTIC number only. Nothing outside a job this script created is ever
# signalled. Any launch, assignment or accounting failure halts the run without a RESULT line.
#
# NATIVE LAUNCH (R2, rev3). Executables are resolved to .exe files and given MSVCRT-quoted command lines. npm is
# resolved to npm.cmd explicitly and run through cmd.exe /d /s /c with a RESTRICTED command line.
#
# TIME (R3, rev3). budget.js is the single source of the arithmetic; this script runs it first and refuses to start
# unless the modelled worst case plus workflow overhead fits in -JobTimeoutMin with the required headroom.
#
# ORCHESTRATION (rev4 corrections of rev3 defects):
#   * variables: PowerShell names are case-insensitive, so rev3's $TAR (tar.exe) and $tar (archive path) were ONE
#     variable and tar would have been launched as the archive. Executables are now $nodeExe/$gitExe/$tarExe/$npmCmdPath
#     and the archive is $archivePath; every other name was audited against automatic variables (static check).
#   * logging vs return values: rev3's Say() wrote to the success stream, so Run-Case returned its log lines together
#     with its code and the final gate compared strings to 0. Say() now writes with Write-Host (information stream)
#     and to summary.txt; functions return exactly one typed object; the gate requires five [int] results.
#   * measurement acceptance: exit 0, no timeout, readable JSON with measured=true, clean containment -- all four;
#     the measurement's exit code is also handed to summarize.js, which fails any nonzero exit on its own.
#   * ONE cleanup predicate (Test-CleanLaunch) for every launch: setup, mutate apply/restore, test, measurement and
#     summarizer. Lab inspection failures are -1 (never a zero count) and make the launch unclean.
#   * bounded waits: the diagnostic CIM query has -OperationTimeoutSec 5 (rev3's had none), so a sample can delay a
#     launch's deadline check by at most ~5.25 s; 29 launches x 5.25 s = ~152 s, inside the 300 s overhead allowance.
#   * call syntax: functions are invoked without parentheses ((Labs), not Labs()); rev2/rev3 used Labs().
#   * control flow: baseline must be GOOD before any mutation; each applied mutation is restored in a finally block;
#     any unexpected setup/measurement/containment/restoration failure halts further cases (HarnessHalt); an expected
#     RED failure at the intended assertion is evidence and the run continues to the next case.
# Output discipline: Say() prints fixed labels, counts and known messages only; raw files stay in -Work.
param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{40}$')][string]$HeadSha,
  [Parameter(Mandatory=$false)][ValidatePattern('^([0-9a-f]{40})?$')][string]$MergeSha = "",
  [Parameter(Mandatory=$true)][string]$RepoPath,
  [Parameter(Mandatory=$true)][string]$Work,
  [Parameter(Mandatory=$true)][string]$Harness,
  [int]$JobTimeoutMin = 90,
  [int]$WorkflowOverheadSec = 300,
  [int]$MinHeadroomSec = 900,
  [int]$GraceSec = 10,        # after the root exits: time for ActiveProcesses to reach 0 on its own
  [int]$TerminateSec = 10,    # after TerminateJobObject: time for ActiveProcesses to reach 0
  [int]$BudgetSec = 30, [int]$NodeVersionSec = 30, [int]$CatfileSec = 30, [int]$ArchiveSec = 60, [int]$UntarSec = 60,
  [int]$NpmCiSec = 480, [int]$CompileSec = 120, [int]$UtilSec = 30, [int]$RunSec = 300, [int]$MeasureSec = 180
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

# A halt carries a fixed label and the process exit code; it is thrown from anywhere and handled ONCE at the bottom,
# so finally blocks (mutation restore, job disposal) run before the process exits.
class HarnessHalt : System.Exception {
  [int]$HaltExitCode
  HarnessHalt([string]$label, [int]$haltExit) : base($label) { $this.HaltExitCode = $haltExit }
}
function Halt([string]$label, [int]$haltExit) { throw [HarnessHalt]::new($label, $haltExit) }

$started = Get-Date
New-Item -ItemType Directory -Force $Work | Out-Null
$copyRoot = Join-Path $Work "copy"
if (Test-Path -LiteralPath $copyRoot) { Write-Host "HARNESS-ERROR: work copy already exists; use a fresh -Work"; exit 2 }
New-Item -ItemType Directory -Force $copyRoot | Out-Null
$summaryPath = Join-Path $Work "summary.txt"
# Say: visible log line (information stream, never the success stream) + summary.txt. Functions that return values
# may call Say freely because Write-Host does not enter the pipeline.
function Say([string]$line) { Write-Host $line; Add-Content -Path $summaryPath -Value $line }
function LfSha([string]$filePath) {
  $text = [System.IO.File]::ReadAllText($filePath) -replace "`r`n", "`n"
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
  return ((([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)) | ForEach-Object { $_.ToString("x2") }) -join "")
}
function FirstLine([string]$filePath) {
  # first line of a captured file, or "" -- never throws on a missing/empty file (strict mode safe)
  if (-not (Test-Path -LiteralPath $filePath)) { return "" }
  $lines = @(Get-Content -LiteralPath $filePath -TotalCount 1)
  if ($lines.Count -eq 0 -or $null -eq $lines[0]) { return "" }
  return [string]$lines[0]
}

# ---- 0a. containment type: compile WinRed.cs; any failure is fatal (no fallback to uncontained launches)
try {
  $csSource = Get-Content -Raw -LiteralPath (Join-Path $Harness "WinRed.cs")
  Add-Type -TypeDefinition $csSource -ErrorAction Stop
} catch { Say "CONTAINMENT-ERROR: WinRed.cs did not compile; refusing to launch anything"; exit 9 }
# quoting self-test against the shared vectors BEFORE the first launch
$quoteVectors = Get-Content -Raw -LiteralPath (Join-Path $Harness "quote-vectors.json") | ConvertFrom-Json
[string[]]$quoteInputs = @($quoteVectors.vectors | ForEach-Object { [string]$_.input })
[string[]]$quoteExpected = @($quoteVectors.vectors | ForEach-Object { [string]$_.expected })
$quoteBad = [WinRed.ContainedProcess]::QuoteSelfTest($quoteInputs, $quoteExpected)
if ($quoteBad -ne -1) { Say "QUOTE-SELFTEST-FAILED: vector index $quoteBad"; exit 9 }
Say ("CONTAINMENT-OK: WinRed compiled; quoting self-test " + $quoteInputs.Count + " vectors ok")

# ---- resolution: executables must be .exe files; npm must be npm.cmd (never the npm.ps1 that Get-Command npm returns first)
function Resolve-Exe([string]$commandName) {
  $found = @(Get-Command $commandName -CommandType Application -ErrorAction Stop | Where-Object { $null -ne $_.Source -and $_.Source -match '\.exe$' })
  if ($found.Count -eq 0) { throw "no .exe for $commandName" }
  return [string]$found[0].Source
}
function Resolve-NpmCmd() {
  $found = @(Get-Command "npm.cmd" -CommandType Application -ErrorAction SilentlyContinue | Where-Object { $null -ne $_.Source -and $_.Source -match '\.cmd$' })
  if ($found.Count -gt 0) { return [string]$found[0].Source }
  $beside = Join-Path (Split-Path -Parent (Resolve-Exe "node")) "npm.cmd"   # the Node install always ships npm.cmd beside node.exe
  if (Test-Path -LiteralPath $beside) { return $beside }
  throw "npm.cmd not found"
}
try { $nodeExe = Resolve-Exe "node"; $gitExe = Resolve-Exe "git"; $tarExe = Resolve-Exe "tar"; $npmCmdPath = Resolve-NpmCmd }
catch { Say "SETUP-ERROR: could not resolve node.exe/git.exe/tar.exe/npm.cmd"; exit 5 }
if (-not [WinRed.ContainedProcess]::IsSafeCmdScriptPath($npmCmdPath)) { Say "SETUP-ERROR: npm.cmd path contains a cmd metacharacter; refusing"; exit 5 }

# ---- diagnostic sampler (never proof): live descendants of a PID by ParentProcessId; -1 when the query yields nothing usable
function Sample-Descendants([int]$rootPid) {
  try {
    $allProcs = @(Get-CimInstance -ClassName Win32_Process -OperationTimeoutSec 5 -ErrorAction Stop | Select-Object ProcessId, ParentProcessId)
    if ($allProcs.Count -eq 0) { return -1 }
    $seen = @{}; $frontier = @($rootPid); $count = 0
    while ($frontier.Count -gt 0) {
      $nextFrontier = @()
      foreach ($parentId in $frontier) {
        foreach ($proc in $allProcs) {
          if ($null -eq $proc -or $null -eq $proc.ProcessId -or $null -eq $proc.ParentProcessId) { continue }
          $childPid = [int]$proc.ProcessId
          if ([int]$proc.ParentProcessId -eq $parentId -and -not $seen.ContainsKey($childPid)) { $seen[$childPid] = $true; $nextFrontier += $childPid; $count++ }
        }
      }
      $frontier = $nextFrontier
    }
    return $count
  } catch { return -1 }
}
function Labs() {
  # count of secretloop-markers-* lab directories in TEMP; -1 when TEMP is unknown OR the inspection itself fails.
  # An inspection failure is never reported as a zero count (rev4: no SilentlyContinue here).
  $tempDir = $env:TEMP
  if ([string]::IsNullOrEmpty($tempDir)) { return -1 }
  try {
    if (-not (Test-Path -LiteralPath $tempDir -PathType Container)) { return -1 }
    return @(Get-ChildItem -LiteralPath $tempDir -Directory -Filter "secretloop-markers-*" -ErrorAction Stop).Count
  } catch { return -1 }
}

# ---- the only launcher. Returns ONE hashtable:
#   @{ code; timedOut; out; err; cleanup = @{ method; verified; labsDelta; lingered; survivors; treeTerminated; sampledMax; sampleFailures; reason } }
$script:launchSeq = 0
function Invoke-Contained([string]$application, [string[]]$arguments, [string]$workingDir, [int]$timeoutSec, [string]$tag, [bool]$viaCmd = $false) {
  $script:launchSeq++
  $outPath = Join-Path $Work ("c-" + $script:launchSeq + "-" + $tag + ".out"); $errPath = Join-Path $Work ("c-" + $script:launchSeq + "-" + $tag + ".err")
  $labsBefore = (Labs)
  $contained = $null
  try { $contained = [WinRed.ContainedProcess]::Start($application, $arguments, $workingDir, $outPath, $errPath, $viaCmd) }
  catch { Halt ("CONTAINMENT-ERROR: launch/assign failed for " + $tag + " -- stopping") 9 }
  $exitCode = -1; $timedOut = $false; $lingered = -1; $survivors = -1; $terminated = $false; $verified = $false; $reason = ""
  $sampledMax = 0; $sampleFailures = 0
  try {
    $deadline = (Get-Date).AddSeconds($timeoutSec); $nextSample = (Get-Date).AddSeconds(1)
    while (-not $contained.Wait(250)) {
      if ((Get-Date) -ge $nextSample) {
        $sampled = Sample-Descendants $contained.Pid
        if ($sampled -lt 0) { $sampleFailures++ } elseif ($sampled -gt $sampledMax) { $sampledMax = $sampled }
        $nextSample = (Get-Date).AddSeconds(1)
      }
      if ((Get-Date) -gt $deadline) { $timedOut = $true; break }
    }
    if ($timedOut) {
      $terminated = $true
      if (-not $contained.Terminate()) { throw "terminate-failed" }
      $survivors = [int]$contained.SettleToZero($TerminateSec * 1000)
      $lingered = 0   # not meaningful after a timeout; the launch is already unclean (treeTerminated)
    } else {
      $exitCode = [int]$contained.ExitCode
      $lingered = [int]$contained.SettleToZero($GraceSec * 1000)         # 0 = the whole tree ended with the root (kernel accounting)
      if ($lingered -gt 0) {
        $terminated = $true
        if (-not $contained.Terminate()) { throw "terminate-failed" }
        $survivors = [int]$contained.SettleToZero($TerminateSec * 1000)
      } else { $survivors = 0 }
    }
    $verified = $true
  } catch { $verified = $false; $reason = "job-accounting-unavailable" }
  finally { if ($null -ne $contained) { $contained.Dispose() } }   # kill-on-close: the backstop for anything still inside
  $labsAfter = (Labs)
  $labsDelta = -1
  if ($labsBefore -ge 0 -and $labsAfter -ge 0) { $labsDelta = $labsAfter - $labsBefore }
  else { $verified = $false; if ($reason -eq "") { $reason = "labs-inspection-failed" } }
  $cleanup = @{ method = "job-accounting"; verified = $verified; labsDelta = $labsDelta; lingered = $lingered; survivors = $survivors; treeTerminated = $terminated; sampledMax = $sampledMax; sampleFailures = $sampleFailures; reason = $reason }
  return @{ code = $exitCode; timedOut = $timedOut; out = $outPath; err = $errPath; cleanup = $cleanup }
}

# ---- ONE cleanup predicate for every launch. "" = clean; otherwise a fixed-label reason.
function Test-CleanLaunch($run) {
  $cleanup = $run.cleanup
  if ($run.timedOut) { return "timed-out" }
  if ($cleanup.verified -ne $true) { return ("cleanup-unverified(" + $cleanup.reason + ")") }
  if ($cleanup.lingered -ne 0) { return ("lingering-descendants(" + $cleanup.lingered + ")") }
  if ($cleanup.survivors -ne 0) { return ("survivors(" + $cleanup.survivors + ")") }
  if ($cleanup.treeTerminated) { return "tree-terminated" }
  if ($cleanup.labsDelta -ne 0) { return ("labs-left(" + $cleanup.labsDelta + ")") }
  return ""
}
# setup-phase launches: exit 0 AND clean, or halt
function Require-CleanSetup($run, [string]$what, [int]$setupHaltCode, [string]$haltLabel) {
  if ($run.code -ne 0) { Halt ($haltLabel + ": " + $what + " (exit " + $run.code + ", timedOut " + $run.timedOut + ")") $setupHaltCode }
  $unclean = Test-CleanLaunch $run
  if ($unclean -ne "") { Halt ($haltLabel + ": " + $what + " not clean: " + $unclean) $setupHaltCode }
}

# ---- 0b. time budget (budget.js is the arithmetic; this run is also the first contained launch)
$budgetArgs = @((Join-Path $Harness "budget.js"), "jobTimeoutMin=$JobTimeoutMin", "workflowOverheadSec=$WorkflowOverheadSec", "minHeadroomSec=$MinHeadroomSec",
  "graceSec=$GraceSec", "terminateSec=$TerminateSec", "budgetSec=$BudgetSec", "nodeVersionSec=$NodeVersionSec", "catfileSec=$CatfileSec", "archiveSec=$ArchiveSec",
  "untarSec=$UntarSec", "npmCiSec=$NpmCiSec", "compileSec=$CompileSec", "utilSec=$UtilSec", "runSec=$RunSec", "measureSec=$MeasureSec")
$budget = $null
$harnessDeadline = $started
$perCaseSec = 0; $mutationOpSec = 0; $launchUtilSec = 0
function Assert-Budget([int]$needSec, [string]$what) {
  $remain = [int][Math]::Floor(($script:harnessDeadline - (Get-Date)).TotalSeconds)
  if ($remain -lt $needSec) { Halt ("BUDGET-EXHAUSTED: " + $what + " needs " + $needSec + " s, " + $remain + " s of the modelled worst case remain; stopping") 8 }
}

# ---- one case: isolated test (contained) + independent measurement (contained) + verdict (contained).
# Returns ONE hashtable @{ code = [int]; unexpected = [bool] }. code is the summarizer's verdict exit (0 = as expected).
# unexpected = an infrastructure failure (containment, cleanup, measurement process, summarizer process), which halts the run;
# a verdict of NOT-RED/NOT-GOOD on a clean run is NOT unexpected -- it is a recorded result.
function Merge-Cleanup($first, $second) {
  $sumOrUnknown = { param($x, $y) if ($x -lt 0 -or $y -lt 0) { -1 } else { $x + $y } }
  return @{
    method = "job-accounting"
    verified = (($first.verified -eq $true) -and ($second.verified -eq $true))
    labsDelta = (& $sumOrUnknown $first.labsDelta $second.labsDelta)
    lingered = (& $sumOrUnknown $first.lingered $second.lingered)
    survivors = (& $sumOrUnknown $first.survivors $second.survivors)
    treeTerminated = ($first.treeTerminated -or $second.treeTerminated)
    sampledMax = [Math]::Max([int]$first.sampledMax, [int]$second.sampledMax)
    sampleFailures = ([int]$first.sampleFailures + [int]$second.sampleFailures)
    reason = $(if ($first.reason -ne "") { $first.reason } else { $second.reason })
  }
}
function Run-Case([string]$label, [string]$expect) {
  Assert-Budget $script:perCaseSec ("case " + $label)
  $infra = @()
  # 1. the isolated test (expected to fail for W1-W3; any exit is a result, but its launch must be clean)
  $testRun = Invoke-Contained $nodeExe @("node_modules\ts-node\dist\bin.js", "--transpile-only", "tests\__win-red-runtime.test.ts") $copyRoot $RunSec ("test-" + $label)
  $rawPath = Join-Path $Work ("raw-" + $label + ".txt")
  Copy-Item -LiteralPath $testRun.out -Destination $rawPath -Force
  if (Test-Path -LiteralPath $testRun.err) { Get-Content -LiteralPath $testRun.err | Add-Content -Path $rawPath }
  $testUnclean = Test-CleanLaunch $testRun
  if ($testUnclean -ne "") { $infra += ("test-launch " + $testUnclean) }
  # 2. the independent measurement: exit 0 AND no timeout AND readable JSON with measured=true AND clean
  $measureRun = Invoke-Contained $nodeExe @("-r", "ts-node/register/transpile-only", (Join-Path $Harness "measure-markers.js"), $copyRoot) $copyRoot $MeasureSec ("measure-" + $label)
  $measPath = Join-Path $Work ("measure-" + $label + ".json")
  $measReason = ""
  if ($measureRun.timedOut) { $measReason = "measure-timeout" }
  elseif ($measureRun.code -ne 0) { $measReason = "measure-exit-nonzero" }
  elseif (-not (Test-Path -LiteralPath $measureRun.out) -or ((Get-Item -LiteralPath $measureRun.out).Length -eq 0)) { $measReason = "measure-no-output" }
  else {
    try {
      $parsed = (FirstLine $measureRun.out) | ConvertFrom-Json
      if ($null -eq $parsed -or $parsed.measured -ne $true) { $measReason = "measure-not-measured" }
    } catch { $measReason = "measure-invalid-json" }
  }
  if ($measReason -ne "") { Set-Content -Path $measPath -Value ('{"measured":false,"reason":"' + $measReason + '"}'); $infra += ("measurement " + $measReason) }
  else { Copy-Item -LiteralPath $measureRun.out -Destination $measPath -Force }
  $measureUnclean = Test-CleanLaunch $measureRun
  if ($measureUnclean -ne "") { $infra += ("measure-launch " + $measureUnclean) }
  # 3. cleanup record for the summarizer (test + measurement), then the verdict
  $cleanupRecord = Merge-Cleanup $testRun.cleanup $measureRun.cleanup
  $cleanupPath = Join-Path $Work ("cleanup-" + $label + ".json")
  ($cleanupRecord | ConvertTo-Json -Compress) | Set-Content -Path $cleanupPath
  $verdictRun = Invoke-Contained $nodeExe @((Join-Path $Harness "summarize.js"), $label, $expect, $rawPath, "$($testRun.code)", $measPath, "$($measureRun.code)", $cleanupPath, (Join-Path $Harness "predictions.json")) $copyRoot $UtilSec ("summ-" + $label)
  $verdictLine = FirstLine $verdictRun.out
  if ($verdictLine -eq "") { $verdictLine = "$label`: SUMMARIZE-FAILED (no verdict line)"; $infra += "summarizer no-output" }
  $verdictUnclean = Test-CleanLaunch $verdictRun
  if ($verdictUnclean -ne "") { $infra += ("summarizer-launch " + $verdictUnclean) }
  Say $verdictLine
  if ($testRun.timedOut) { Say "$label`: isolated test HARNESS-TIMEOUT after $RunSec s (job terminated; not RED evidence)" }
  if ($infra.Count -gt 0) { Say ("$label`: INFRA-FAILURE " + ($infra -join "; ")); return @{ code = [int]1; unexpected = [bool]$true } }
  return @{ code = [int]$verdictRun.code; unexpected = [bool]$false }
}

# ================================ main flow: every halt is handled once, below ================================
$results = [ordered]@{}
$haltCode = $null
try {
  $budgetRun = Invoke-Contained $nodeExe $budgetArgs $Work $BudgetSec "budget"
  $budgetLine = FirstLine $budgetRun.out
  try { if ($budgetLine -ne "") { $budget = $budgetLine | ConvertFrom-Json } } catch { $budget = $null }
  if ($null -eq $budget -or $null -eq $budget.ok) { Halt "BUDGET-ERROR: budget.js produced no readable plan" 8 }
  Say ("BUDGET: " + [string]$budget.arithmetic)
  if ($budget.ok -ne $true -or $budgetRun.code -ne 0) { Halt "BUDGET-ERROR: the modelled worst case does not fit the job timeout with the required headroom; refusing to run" 8 }
  Require-CleanSetup $budgetRun "budget" 5 "SETUP-ERROR"
  $harnessDeadline = $started.AddSeconds([int]$budget.worstHarnessSec)
  $perCaseSec = [int]$budget.phases.perCaseSec; $mutationOpSec = [int]$budget.phases.mutationOpSec; $launchUtilSec = [int]$budget.phases.launchUtilSec

  # ---- 0c. identity line (node version through the contained launcher; no bare native call)
  $nodeVersionRun = Invoke-Contained $nodeExe @("-v") $Work $NodeVersionSec "node-v"
  Require-CleanSetup $nodeVersionRun "node -v" 5 "SETUP-ERROR"
  Say ("# win-red rev4; head " + $HeadSha + "; checkout/merge " + $(if ($MergeSha) { $MergeSha } else { "(not given)" }) + "; started " + $started.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") + "; node " + (FirstLine $nodeVersionRun.out) + "; orchestrator pwsh " + $PSVersionTable.PSVersion.ToString() + "; product helper Windows PowerShell 5.1; os " + [System.Environment]::OSVersion.Version)

  # ---- 1. identity: HeadSha present, archived, files hash-bound (B5). No regeneration on drift.
  $bound = Get-Content -Raw -LiteralPath (Join-Path $Harness "bound.json") | ConvertFrom-Json
  $catfileRun = Invoke-Contained $gitExe @("-C", $RepoPath, "cat-file", "-e", "$HeadSha^{commit}") $Work $CatfileSec "catfile"
  if ($catfileRun.timedOut -or $catfileRun.code -ne 0) { Halt "BIND-ERROR: head $HeadSha is not present in the checkout" 3 }
  Require-CleanSetup $catfileRun "git cat-file" 3 "BIND-ERROR"
  $archivePath = Join-Path $Work "head.tar"
  $archiveRun = Invoke-Contained $gitExe @("-C", $RepoPath, "archive", "--format=tar", "-o", $archivePath, $HeadSha) $Work $ArchiveSec "archive"
  if ($archiveRun.timedOut -or $archiveRun.code -ne 0) { Halt "BIND-ERROR: git archive of the head failed (exit $($archiveRun.code))" 3 }
  Require-CleanSetup $archiveRun "git archive" 3 "BIND-ERROR"
  $untarRun = Invoke-Contained $tarExe @("-xf", $archivePath, "-C", $copyRoot) $Work $UntarSec "untar"
  if ($untarRun.timedOut -or $untarRun.code -ne 0) { Halt "BIND-ERROR: tar extract failed (exit $($untarRun.code))" 3 }
  Require-CleanSetup $untarRun "tar" 3 "BIND-ERROR"
  $drift = 0
  foreach ($boundFile in $bound.boundFiles.PSObject.Properties) {
    $relPath = $boundFile.Name; $wantSha = $boundFile.Value
    $gotHead = LfSha (Join-Path $copyRoot ($relPath -replace "/", "\"))
    $gotCheckout = LfSha (Join-Path $RepoPath ($relPath -replace "/", "\"))
    Say ("BIND " + $relPath + ": head==bound " + $(if ($gotHead -eq $wantSha) { "yes" } else { "NO" }) + "; checkout==head " + $(if ($gotCheckout -eq $gotHead) { "yes" } else { "NO (synthetic merge differs here)" }))
    if ($gotHead -ne $wantSha) { $drift++ }
  }
  if ($drift -gt 0) { Halt "BIND-ERROR: $drift bound file(s) differ at the head; refusing to run (hashes are never regenerated here)" 4 }
  Say "BIND-OK: all bound files at head $HeadSha equal bound.json"

  # ---- 2. dependencies + compile (npm.cmd through cmd.exe with a restricted command line; exit codes checked)
  Assert-Budget ($NpmCiSec + $CompileSec + 2 * ($GraceSec + $TerminateSec)) "npm ci + compile"
  $npmCiRun = Invoke-Contained $npmCmdPath @("ci", "--no-audit", "--no-fund") $copyRoot $NpmCiSec "npm-ci" $true
  Require-CleanSetup $npmCiRun "npm ci" 5 "SETUP-ERROR"
  $compileRun = Invoke-Contained $npmCmdPath @("run", "compile") $copyRoot $CompileSec "compile" $true
  Require-CleanSetup $compileRun "compile" 5 "SETUP-ERROR"
  Say "SETUP-OK: npm ci + compile"

  # ---- 3. isolate the runtime test (hash-verified)
  Assert-Budget $launchUtilSec "extract"
  $extractRun = Invoke-Contained $nodeExe @((Join-Path $Harness "extract-runtime-test.js"), $copyRoot, (Join-Path $Harness "bound.json")) $copyRoot $UtilSec "extract"
  $extractLine = FirstLine $extractRun.out
  if ($extractRun.timedOut -or $extractRun.code -ne 0) { Halt ("EXTRACT-FAILED: " + $extractLine) 6 }
  Require-CleanSetup $extractRun "extract" 6 "EXTRACT-FAILED"
  Say $extractLine

  # ---- 4. baseline must be GOOD before any mutation is applied
  $baselineCase = Run-Case "BASELINE" "BASELINE"
  $results["BASELINE"] = [int]$baselineCase.code
  if ($baselineCase.unexpected) { Halt "CASE-INFRA-FAILURE: BASELINE; no mutation attempted" 11 }
  if ($baselineCase.code -ne 0) { Halt "BASELINE-NOT-GOOD: mutations not attempted (a RED result needs a GOOD baseline)" 1 }

  # ---- 5. mutations: apply -> case -> ALWAYS restore (finally) -> restore must be clean, or halt
  foreach ($mutation in @("W1", "W2", "W3")) {
    Assert-Budget $mutationOpSec ("apply " + $mutation)
    $applyRun = Invoke-Contained $nodeExe @((Join-Path $Harness "mutate.js"), $copyRoot, (Join-Path $Harness "bound.json"), "apply", $mutation, (Join-Path $Work ("mutation-" + $mutation + ".diff"))) $copyRoot $UtilSec ("apply-" + $mutation)
    $applyLine = FirstLine $applyRun.out; Say $(if ($applyLine -ne "") { $applyLine } else { "MUTATE-ERROR: no output for $mutation" })
    $restoreFailure = ""
    try {
      if ($applyRun.code -ne 0) { Halt ("MUTATE-FAILED: " + $mutation + " was not applied (exit " + $applyRun.code + ")") 12 }
      $applyUnclean = Test-CleanLaunch $applyRun
      if ($applyUnclean -ne "") { Halt ("MUTATE-FAILED: " + $mutation + " apply launch not clean: " + $applyUnclean) 12 }
      $mutationCase = Run-Case $mutation $mutation
      $results[$mutation] = [int]$mutationCase.code
      if ($mutationCase.unexpected) { Halt ("CASE-INFRA-FAILURE: " + $mutation) 11 }
    } finally {
      # restore runs whether the case passed, failed, or halted; it is budgeted as one mutation op
      $restoreRun = Invoke-Contained $nodeExe @((Join-Path $Harness "mutate.js"), $copyRoot, (Join-Path $Harness "bound.json"), "restore", $mutation) $copyRoot $UtilSec ("restore-" + $mutation)
      $restoreLine = FirstLine $restoreRun.out; Say $(if ($restoreLine -ne "") { $restoreLine } else { "RESTORE-ERROR: no output for $mutation" })
      if ($restoreRun.code -ne 0) { $restoreFailure = "exit " + $restoreRun.code }
      else { $restoreUnclean = Test-CleanLaunch $restoreRun; if ($restoreUnclean -ne "") { $restoreFailure = "launch not clean: " + $restoreUnclean } }
      if ($restoreFailure -ne "") { Say ("RESTORE-FAILED: " + $mutation + " (" + $restoreFailure + ")") }
    }
    if ($restoreFailure -ne "") { Halt ("RESTORE-FAILED: " + $mutation + "; stopping") 7 }
  }

  # ---- 6. baseline again on the restored source
  $afterCase = Run-Case "BASELINE-AFTER" "BASELINE"
  $results["BASELINE-AFTER"] = [int]$afterCase.code
  if ($afterCase.unexpected) { Halt "CASE-INFRA-FAILURE: BASELINE-AFTER" 11 }
} catch [HarnessHalt] {
  Say $_.Exception.Message
  $haltCode = [int]$_.Exception.HaltExitCode
} catch {
  # unexpected PowerShell exception: type name only (messages may carry paths)
  Say ("HARNESS-ERROR: unexpected exception " + $_.Exception.GetType().Name + "; stopping")
  $haltCode = 10
}

# ---- final gate: exactly five typed results, all zero, and no halt
$elapsed = [int][Math]::Floor(((Get-Date) - $started).TotalSeconds)
$worstText = $(if ($null -ne $budget -and $null -ne $budget.worstHarnessSec) { [string][int]$budget.worstHarnessSec } else { "n/a" })
Say ("ELAPSED: " + $elapsed + " s of modelled worst " + $worstText + " s; cases recorded " + $results.Count + "/5")
if ($null -ne $haltCode) { Say ("RESULT: NOT-ALL-EXPECTED (halted; " + $results.Count + " of 5 cases recorded)"); exit $haltCode }
$expectedLabels = @("BASELINE", "W1", "W2", "W3", "BASELINE-AFTER")
$typed = 0; $zero = 0
foreach ($caseLabel in $expectedLabels) {
  if ($results.Contains($caseLabel) -and ($results[$caseLabel] -is [int])) { $typed++; if ($results[$caseLabel] -eq 0) { $zero++ } }
}
if ($typed -ne 5) { Say ("HARNESS-ERROR: " + $typed + " of 5 results are typed integers; refusing to conclude"); exit 10 }
if ($zero -eq 5) { Say "RESULT: ALL-EXPECTED (baseline good, W1/W2/W3 red at intended assertions with predicted measurements, restored, baseline good again, cleanup proven by job accounting)"; exit 0 }
Say ("RESULT: NOT-ALL-EXPECTED (" + (5 - $zero) + " case(s) not as expected)"); exit 1
