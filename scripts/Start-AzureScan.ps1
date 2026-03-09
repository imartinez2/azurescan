[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$OutputFolder,
    [int]$CostLookbackDays = 30,
    [int]$TopCostResourceCount = 15,
    [switch]$RefreshAdvisorRecommendations,
    [switch]$SkipExcel,
    [switch]$ForceModuleInstall
)

$bootstrap = 'https://raw.githubusercontent.com/imartinez2/azurescan/main/bootstrap-azure-assessment.ps1'

if (-not $OutputFolder) {
    $cloudDrive = Join-Path $HOME 'clouddrive'
    if (Test-Path $cloudDrive) {
        $OutputFolder = Join-Path $cloudDrive 'azurescan'
    }
    else {
        $OutputFolder = Join-Path $PWD 'azurescan'
    }
}

$cmd = @("& { $(irm '$bootstrap') }")
if ($SubscriptionId) { $cmd += @('-SubscriptionId', "'$SubscriptionId'") }
if ($OutputFolder) { $cmd += @('-OutputFolder', "'$OutputFolder'") }
$cmd += @('-CostLookbackDays', $CostLookbackDays, '-TopCostResourceCount', $TopCostResourceCount)
if ($RefreshAdvisorRecommendations) { $cmd += '-RefreshAdvisorRecommendations' }
if ($SkipExcel) { $cmd += '-SkipExcel' }
if ($ForceModuleInstall) { $cmd += '-ForceModuleInstall' }

iex ($cmd -join ' ')
