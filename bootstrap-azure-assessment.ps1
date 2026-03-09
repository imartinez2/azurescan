[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$OutputFolder,
    [int]$CostLookbackDays = 30,
    [int]$TopCostResourceCount = 15,
    [switch]$RefreshAdvisorRecommendations,
    [switch]$SkipExcel,
    [switch]$SkipHtml,
    [string]$AssessmentScriptUrl = 'https://raw.githubusercontent.com/imartinez2/azurescan/main/scripts/Azure-Subscription-Assessment-Advanced-CloudShell.ps1'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Status {
    param([string]$Message)
    Write-Host "[AzureAssessment] $Message" -ForegroundColor Cyan
}

function Ensure-PSGalleryTrusted {
    try {
        $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction Stop
        if ($repo.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction Stop
        }
    }
    catch {
        Write-Warning "Unable to set PSGallery as trusted: $($_.Exception.Message)"
    }
}

function Ensure-Module {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$Optional
    )

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Status "Installing module $Name"
        try {
            Install-Module $Name -Scope CurrentUser -Force -AllowClobber -Repository PSGallery -ErrorAction Stop
        }
        catch {
            if ($Optional) {
                Write-Warning "Optional module '$Name' could not be installed: $($_.Exception.Message)"
                return $false
            }
            throw
        }
    }

    try {
        Import-Module $Name -Force -ErrorAction Stop
        return $true
    }
    catch {
        if ($Optional) {
            Write-Warning "Optional module '$Name' could not be imported: $($_.Exception.Message)"
            return $false
        }
        throw
    }
}

function Resolve-OutputFolder {
    param([string]$Candidate)
    if ($Candidate) { return $Candidate }
    $cloudDrive = Join-Path $HOME 'clouddrive'
    if (Test-Path $cloudDrive) { return (Join-Path $cloudDrive 'azurescan') }
    return (Join-Path $HOME 'azurescan')
}

Write-Status 'Checking required modules'
Ensure-PSGalleryTrusted
$null = Ensure-Module -Name 'Az.Accounts'
$null = Ensure-Module -Name 'Az.ResourceGraph'
$null = Ensure-Module -Name 'Az.Resources'
$null = Ensure-Module -Name 'ImportExcel' -Optional

Write-Status 'Checking Azure context'
try {
    $ctx = Get-AzContext -ErrorAction Stop
}
catch {
    $ctx = $null
}

if (-not $ctx) {
    Connect-AzAccount -ErrorAction Stop | Out-Null
    $ctx = Get-AzContext -ErrorAction Stop
}

if (-not $SubscriptionId -and $ctx.Subscription -and $ctx.Subscription.Id) {
    $SubscriptionId = $ctx.Subscription.Id
}

if (-not $SubscriptionId) {
    throw 'No active Azure context subscription was found. Pass -SubscriptionId explicitly.'
}

$OutputFolder = Resolve-OutputFolder -Candidate $OutputFolder
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

$localScript = Join-Path $HOME 'Azure-Subscription-Assessment-Advanced-CloudShell.ps1'

Write-Status "Downloading assessment script from $AssessmentScriptUrl"
Invoke-WebRequest -Uri $AssessmentScriptUrl -OutFile $localScript -UseBasicParsing

Write-Status 'Launching assessment'
& $localScript `
    -SubscriptionId $SubscriptionId `
    -OutputFolder $OutputFolder `
    -CostLookbackDays $CostLookbackDays `
    -TopCostResourceCount $TopCostResourceCount `
    -RefreshAdvisorRecommendations:$RefreshAdvisorRecommendations `
    -SkipExcel:$SkipExcel `
    -SkipHtml:$SkipHtml
