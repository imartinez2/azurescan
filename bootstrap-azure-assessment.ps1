[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$OutputFolder,
    [int]$CostLookbackDays = 30,
    [int]$TopCostResourceCount = 15,
    [switch]$RefreshAdvisorRecommendations,
    [switch]$SkipExcel,
    [switch]$ForceModuleInstall,
    [string]$AssessmentScriptUrl = 'https://REPLACE-WITH-YOUR-PUBLIC-URL/Azure-Subscription-Assessment-Advanced.ps1'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)
    Write-Host "[AzureAssessment] $Message" -ForegroundColor Cyan
}

function Ensure-TrustedPSGallery {
    try {
        $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction Stop
        if ($repo.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction Stop
        }
    }
    catch {
        Write-Warning "Could not set PSGallery as trusted: $($_.Exception.Message)"
    }
}

function Ensure-Module {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$Optional
    )

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        if ($ForceModuleInstall -or -not $Optional) {
            Write-Step "Installing PowerShell module '$Name'"
            Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        }
        else {
            return $false
        }
    }

    Import-Module $Name -Force -ErrorAction Stop
    return $true
}

function Get-DefaultOutputFolder {
    if ($OutputFolder) { return $OutputFolder }

    $cloudDrive = Join-Path $HOME 'clouddrive'
    if (Test-Path $cloudDrive) {
        return (Join-Path $cloudDrive 'assessment')
    }

    return (Join-Path $PWD 'assessment')
}

if ($AssessmentScriptUrl -match 'REPLACE-WITH-YOUR-PUBLIC-URL') {
    throw 'Replace the default AssessmentScriptUrl with your real public URL before publishing this bootstrap script.'
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Ensure-TrustedPSGallery

Write-Step 'Checking required modules'
Ensure-Module -Name Az.Accounts | Out-Null
Ensure-Module -Name Az.ResourceGraph | Out-Null
if (-not $SkipExcel) {
    $null = Ensure-Module -Name ImportExcel -Optional
}

Write-Step 'Checking Azure context'
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    Connect-AzAccount -ErrorAction Stop | Out-Null
    $ctx = Get-AzContext -ErrorAction Stop
}

if (-not $SubscriptionId) {
    if (-not $ctx.Subscription -or -not $ctx.Subscription.Id) {
        throw 'No active Azure subscription was found in the current context. Pass -SubscriptionId explicitly.'
    }
    $SubscriptionId = $ctx.Subscription.Id
    Write-Step "Using current Azure context subscription: $SubscriptionId"
}

$OutputFolder = Get-DefaultOutputFolder
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

$localScript = Join-Path ([System.IO.Path]::GetTempPath()) 'Azure-Subscription-Assessment-Advanced.ps1'
Write-Step "Downloading assessment script from $AssessmentScriptUrl"
Invoke-WebRequest -Uri $AssessmentScriptUrl -OutFile $localScript -UseBasicParsing

if (-not (Test-Path $localScript)) {
    throw 'Failed to download the assessment script.'
}

Write-Step 'Launching assessment'
& $localScript `
    -SubscriptionId $SubscriptionId `
    -OutputFolder $OutputFolder `
    -CostLookbackDays $CostLookbackDays `
    -TopCostResourceCount $TopCostResourceCount `
    -RefreshAdvisorRecommendations:$RefreshAdvisorRecommendations `
    -SkipExcel:$SkipExcel

Write-Host ''
Write-Host 'Remote Azure assessment completed.' -ForegroundColor Green
Write-Host "Artifacts folder: $OutputFolder" -ForegroundColor Green
