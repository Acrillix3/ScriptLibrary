<#
What it does:
  Reports scheduled task results, missed runs, disabled tasks, and optional stale-run flags.

Available flags:
  -TaskPath: Task folder filter; defaults to *.
  -TaskName: Task name filter; defaults to *.
  -MaxTasks: Maximum tasks to inspect (default 500).
  -StaleAfterHours: Optional age threshold for the last run; zero disables it.
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Reads local ScheduledTasks metadata and task runtime information. Separates running, never-run,
  and scheduler status codes from nonzero results requiring review. No tasks are started or changed;
  action arguments are excluded. Elevation improves visibility.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()][string]$TaskPath='*',
    [ValidateNotNullOrEmpty()][string]$TaskName='*',
    [ValidateRange(1,10000)][int]$MaxTasks=500,
    [ValidateRange(0,876000)][int]$StaleAfterHours=0,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) {
    $OutputDirectory = Join-Path $PSScriptRoot '..\Reports'
}
$scriptLabel = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runName = '{0}-{1}-{2}' -f $scriptLabel,[datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),[guid]::NewGuid().ToString('N').Substring(0,8)
$reportDirectory = (New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force -ErrorAction Stop).FullName
$queryLog = New-Object 'System.Collections.Generic.List[object]'
$queryErrors = New-Object 'System.Collections.Generic.List[object]'
function Invoke-ReportQuery {
    param([string]$Section,[scriptblock]$Action,[switch]$RequireData)
    try {
        $items = @(& $Action)
        if ($RequireData -and $items.Count -eq 0) { throw 'Required data was not returned.' }
        $queryLog.Add([pscustomobject]@{Section=$Section;Status=$(if($items.Count){'Collected'}else{'Empty'});Count=$items.Count;Error=''})
        [pscustomobject]@{Succeeded=$true;Data=$items}
    } catch {
        $queryErrors.Add([pscustomobject]@{Section=$Section;Error=$_.Exception.Message;ErrorId=$_.FullyQualifiedErrorId})
        $queryLog.Add([pscustomobject]@{Section=$Section;Status='Unknown';Count=$null;Error=$_.Exception.Message})
        [pscustomobject]@{Succeeded=$false;Data=@()}
    }
}
function Write-ReportCsv {
    param([string]$Name,[object[]]$Rows,[string[]]$Columns)
    $path=Join-Path $reportDirectory ($Name+'.csv')
    if (@($Rows).Count) {
        $Rows | Select-Object -Property $Columns | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    } else {
        (($Columns | ForEach-Object { '"'+$_.Replace('"','""')+'"' }) -join ',') | Set-Content -LiteralPath $path -Encoding UTF8
    }
}
function Complete-Report {
    param([object]$Data,[string[]]$Notes)
    Write-ReportCsv -Name 'collection-status' -Rows $queryLog.ToArray() -Columns @('Section','Status','Count','Error')
    Write-ReportCsv -Name 'query-errors' -Rows $queryErrors.ToArray() -Columns @('Section','Error','ErrorId')
    $status='Complete'
    if($queryErrors.Count){$status='Partial'}
    if($queryErrors.Count -and @($queryLog | Where-Object Status -ne 'Unknown').Count -eq 0){$status='Unavailable'}
    $summary=[pscustomobject]@{
        Script=$scriptLabel;ComputerName=$env:COMPUTERNAME;CollectedUtc=[datetime]::UtcNow.ToString('o')
        CollectionStatus=$status;QueryErrorCount=$queryErrors.Count;ReportDirectory=$reportDirectory
        Data=$Data;Sections=$queryLog.ToArray();Notes=@('Collection status describes available evidence, not overall system health.')+$Notes
    }
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $reportDirectory 'summary.json') -Encoding UTF8
    @(
        $scriptLabel
        ('Collection: {0}; query errors: {1}' -f $status,$queryErrors.Count)
        ('Reports: '+$reportDirectory)
        ''
        'Collection results:'
        ($queryLog | Format-Table Section,Status,Count -AutoSize | Out-String -Width 180)
        'Interpretation:'
        ($summary.Notes -join [Environment]::NewLine)
    ) | Set-Content -LiteralPath (Join-Path $reportDirectory 'overview.txt') -Encoding UTF8
    if($queryErrors.Count){Write-Warning 'Some data was unavailable; review query-errors.csv and collection-status.csv.'}
    $summary
}

$taskRows=New-Object 'System.Collections.Generic.List[object]'
$taskCapReached=$false; $collectedAt=Get-Date
$tools=Invoke-ReportQuery -Section 'ScheduledTasks tools' -RequireData -Action { Import-Module ScheduledTasks -ErrorAction Stop; 'Available' }
if($tools.Succeeded){
    $tasks=Invoke-ReportQuery -Section 'Task enumeration' -Action { Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop | Select-Object -First ($MaxTasks+1) }
    $taskCapReached=$tasks.Data.Count -gt $MaxTasks
    foreach($task in @($tasks.Data | Select-Object -First $MaxTasks)){
        $info=Invoke-ReportQuery -Section ('Runtime '+$task.TaskPath+$task.TaskName) -RequireData -Action { Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop }
        $runtime=$info.Data | Select-Object -First 1
        $resultClass='Unknown';$hex='';$result=$null;$last=$null;$next=$null;$missed=$null;$ageHours=$null;$stale='Not assessed'
        if($info.Succeeded){
            $last=$runtime.LastRunTime;$next=$runtime.NextRunTime;$missed=$runtime.NumberOfMissedRuns
            if($null -ne $runtime.LastTaskResult){
                $result=[long]$runtime.LastTaskResult
                if($result -lt 0){$result+=4294967296}
                $hex='0x{0:X8}' -f $result
                if($result -eq 0){$resultClass='Success reported'}
                elseif($result -eq 267009 -or [string]$task.State -eq 'Running'){$resultClass='Running'}
                elseif($result -eq 267011){$resultClass='Never run'}
                elseif($result -eq 267045){$resultClass='Queued'}
                elseif($result -eq 267014){$resultClass='Terminated; review'}
                elseif(($result -ge 267008 -and $result -le 267016) -or $result -eq 267035 -or $result -eq 267036){$resultClass='Scheduler status; review'}
                else{$resultClass='Nonzero result; review'}
            }
            if($last -and [datetime]$last -gt [datetime]'2000-01-01'){
                $ageHours=[math]::Round(($collectedAt-[datetime]$last).TotalHours,2)
                if($StaleAfterHours -gt 0){$stale=$(if($ageHours -ge $StaleAfterHours){'Review age threshold'}else{'Below age threshold'})}
            }elseif($resultClass -eq 'Success reported'){$resultClass='Never run or time unavailable'}
        }
        $taskRows.Add([pscustomobject]@{TaskPath=$task.TaskPath;TaskName=$task.TaskName;State=[string]$task.State;RuntimeStatus=$(if($info.Succeeded){'Collected'}else{'Unknown'});LastRunTime=$last;NextRunTime=$next;LastTaskResult=$result;ResultHex=$hex;ResultClass=$resultClass;NumberOfMissedRuns=$missed;HoursSinceLastRun=$ageHours;StaleRunFlag=$stale;ActionCount=@($task.Actions).Count})
    }
}
Write-ReportCsv 'tasks' $taskRows.ToArray() @('TaskPath','TaskName','State','RuntimeStatus','LastRunTime','NextRunTime','LastTaskResult','ResultHex','ResultClass','NumberOfMissedRuns','HoursSinceLastRun','StaleRunFlag','ActionCount')
$summaryData=[pscustomobject]@{TaskCount=$taskRows.Count;DisabledCount=@($taskRows | Where-Object State -eq 'Disabled').Count;NonzeroReviewCount=@($taskRows | Where-Object ResultClass -eq 'Nonzero result; review').Count;RunningCount=@($taskRows | Where-Object ResultClass -eq 'Running').Count;NeverRunCount=@($taskRows | Where-Object ResultClass -like 'Never run*').Count;UnknownRuntimeCount=@($taskRows | Where-Object RuntimeStatus -eq 'Unknown').Count;TasksWithMissedRuns=@($taskRows | Where-Object NumberOfMissedRuns -gt 0).Count;StaleRunReviewCount=@($taskRows | Where-Object StaleRunFlag -eq 'Review age threshold').Count;StaleAfterHours=$StaleAfterHours;TaskCapReached=$taskCapReached}
Complete-Report $summaryData @('Nonzero application exit codes need application-specific interpretation; they are review findings, not automatically confirmed failures.','Scheduler running, queued, and never-run statuses are tracked separately. Disabled tasks can be intentional.','Stale-run flags compare last-run age only when StaleAfterHours is set. They do not infer a missed schedule or overdue task.','Counts cover inspected tasks only. The task cap limits follow-up queries; it is not a provider timeout. Action command lines and arguments are excluded.')

