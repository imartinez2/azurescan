[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$OutputFolder,
    [int]$CostLookbackDays = 30,
    [int]$TopCostResourceCount = 15,
    [switch]$RefreshAdvisorRecommendations,
    [switch]$SkipExcel,
    [switch]$SkipHtml,
    [string]$BootstrapUrl = 'https://raw.githubusercontent.com/imartinez2/azurescan/main/bootstrap-azure-assessment.ps1'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $OutputFolder) {
    $OutputFolder = Join-Path $HOME 'clouddrive/azurescan'
}

$arguments = @()
if ($SubscriptionId) { $arguments += "-SubscriptionId '$SubscriptionId'" }
if ($OutputFolder) { $arguments += "-OutputFolder '$OutputFolder'" }
$arguments += "-CostLookbackDays $CostLookbackDays"
$arguments += "-TopCostResourceCount $TopCostResourceCount"
if ($RefreshAdvisorRecommendations) { $arguments += '-RefreshAdvisorRecommendations' }
if ($SkipExcel) { $arguments += '-SkipExcel' }
if ($SkipHtml) { $arguments += '-SkipHtml' }

$argumentText = $arguments -join ' '
$command = "iex \"& { `$(irm '$BootstrapUrl') } $argumentText\""
Write-Host $command -ForegroundColor Green
