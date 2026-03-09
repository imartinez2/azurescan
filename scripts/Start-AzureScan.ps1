[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$OutputFolder = "$HOME/clouddrive/azurescan",
    [int]$CostLookbackDays = 30,
    [int]$TopCostResourceCount = 15,
    [switch]$RefreshAdvisorRecommendations,
    [switch]$SkipExcel,
    [switch]$ForceModuleInstall
)

$bootstrap = 'https://raw.githubusercontent.com/imartinez2/azurescan/main/bootstrap-azure-assessment.ps1'

iex "& { $(irm '$bootstrap') } -SubscriptionId '$SubscriptionId' -OutputFolder '$OutputFolder' -CostLookbackDays $CostLookbackDays -TopCostResourceCount $TopCostResourceCount -RefreshAdvisorRecommendations:$RefreshAdvisorRecommendations -SkipExcel:$SkipExcel -ForceModuleInstall:$ForceModuleInstall"
