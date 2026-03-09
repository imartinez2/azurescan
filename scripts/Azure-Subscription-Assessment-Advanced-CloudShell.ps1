[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$OutputFolder,
    [int]$CostLookbackDays = 30,
    [int]$TopCostResourceCount = 15,
    [switch]$RefreshAdvisorRecommendations,
    [switch]$SkipExcel,
    [switch]$SkipHtml
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Status { param([string]$Message) Write-Host "[AzureScan] $Message" -ForegroundColor Cyan }

function Resolve-DefaultOutputFolder {
    if ($OutputFolder) { return $OutputFolder }
    $cloudDrive = Join-Path $HOME 'clouddrive'
    if (Test-Path $cloudDrive) { return (Join-Path $cloudDrive 'azurescan') }
    return (Join-Path $HOME 'azurescan')
}

function Ensure-Module {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$Optional
    )

    if (-not (Get-Module -ListAvailable -Name $Name)) {
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

function Convert-ObjectToJsonSafe {
    param([object]$InputObject)
    if ($null -eq $InputObject) { return $null }
    try { return ($InputObject | ConvertTo-Json -Depth 50 -Compress) }
    catch { return $null }
}

function Invoke-AzRestJson {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GET','POST','PUT','PATCH','DELETE')][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [object]$Body
    )

    $response = if ($PSBoundParameters.ContainsKey('Body')) {
        Invoke-AzRestMethod -Method $Method -Path $Path -Payload ($Body | ConvertTo-Json -Depth 50)
    } else {
        Invoke-AzRestMethod -Method $Method -Path $Path
    }

    if ([string]::IsNullOrWhiteSpace($response.Content)) { return $null }
    return ($response.Content | ConvertFrom-Json -Depth 100)
}

function Add-Finding {
    param(
        [ref]$Collection,
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$Category,
        [string]$Severity,
        [string]$Source,
        [string]$Title,
        [string]$ResourceId,
        [string]$Recommendation,
        [object]$RawData
    )

    $Collection.Value.Add([pscustomobject]@{
        SubscriptionName = $SubscriptionName
        SubscriptionId   = $SubscriptionId
        Category         = $Category
        Severity         = $Severity
        Source           = $Source
        Title            = $Title
        ResourceId       = $ResourceId
        Recommendation   = $Recommendation
        RawData          = Convert-ObjectToJsonSafe -InputObject $RawData
    }) | Out-Null
}

function Add-CategoryFindings {
    param(
        [ref]$Findings,
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$Category,
        [string]$Severity,
        [string]$Source,
        [array]$Items,
        [scriptblock]$TitleFactory,
        [scriptblock]$RecommendationFactory,
        [scriptblock]$ResourceIdFactory
    )

    foreach ($item in $Items) {
        Add-Finding -Collection ([ref]$Findings.Value) `
            -SubscriptionName $SubscriptionName `
            -SubscriptionId $SubscriptionId `
            -Category $Category `
            -Severity $Severity `
            -Source $Source `
            -Title (& $TitleFactory $item) `
            -ResourceId (& $ResourceIdFactory $item) `
            -Recommendation (& $RecommendationFactory $item) `
            -RawData $item
    }
}

function Get-SeverityFromAdvisorImpact {
    param([string]$Impact)
    if ([string]::IsNullOrWhiteSpace($Impact)) { return 'Info' }
    switch ($Impact.ToLowerInvariant()) {
        'high' { 'High' }
        'medium' { 'Medium' }
        'low' { 'Low' }
        default { 'Info' }
    }
}

function Search-GraphSafe {
    param([Parameter(Mandatory = $true)][string]$Query,[int]$First = 1000)
    try { return @(Search-AzGraph -Query $Query -First $First) }
    catch {
        Write-Warning "Resource Graph query failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-SecureScore {
    param([string]$SubscriptionId)
    try {
        $data = Invoke-AzRestJson -Method GET -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/secureScores?api-version=2020-01-01-preview"
        if ($null -eq $data -or $null -eq $data.value -or $data.value.Count -eq 0) { return $null }
        $score = $data.value | Select-Object -First 1
        $current = if ($null -ne $score.properties.score.current) { [double]$score.properties.score.current } else { 0.0 }
        $max = if ($null -ne $score.properties.score.max) { [double]$score.properties.score.max } else { 0.0 }
        $percentage = if ($max -gt 0) { [math]::Round(($current / $max) * 100, 2) } else { 0 }
        return [pscustomobject]@{ Name = $score.name; CurrentScore = $current; MaxScore = $max; Percentage = $percentage }
    }
    catch {
        Write-Warning "Secure Score query failed: $($_.Exception.Message)"
        return $null
    }
}

function Get-DefenderPricings {
    param([string]$SubscriptionId)
    try {
        $data = Invoke-AzRestJson -Method GET -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/pricings?api-version=2024-01-01"
        if ($null -eq $data -or $null -eq $data.value) { return @() }
        return @($data.value | ForEach-Object {
            [pscustomobject]@{ Name = $_.name; PricingTier = [string]$_.properties.pricingTier; SubPlan = [string]$_.properties.subPlan }
        })
    }
    catch {
        Write-Warning "Defender pricings query failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-AdvisorRecommendations {
    param([string]$SubscriptionId,[switch]$Refresh)
    if ($Refresh) {
        try {
            $null = Invoke-AzRestJson -Method POST -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Advisor/generateRecommendations?api-version=2025-01-01"
            Start-Sleep -Seconds 8
        }
        catch {
            Write-Warning "Advisor refresh could not be triggered for ${SubscriptionId}: $($_.Exception.Message)"
        }
    }

    try {
        $data = Invoke-AzRestJson -Method GET -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Advisor/recommendations?api-version=2025-01-01"
        if ($null -eq $data -or $null -eq $data.value) { return @() }
        return @($data.value)
    }
    catch {
        Write-Warning "Advisor query failed for ${SubscriptionId}: $($_.Exception.Message)"
        return @()
    }
}

function Get-CostLastNDays {
    param([string]$SubscriptionId,[int]$Days)
    $from = (Get-Date).Date.AddDays(-1 * $Days).ToString('yyyy-MM-ddT00:00:00Z')
    $to = (Get-Date).Date.AddDays(1).AddSeconds(-1).ToString('yyyy-MM-ddT23:59:59Z')
    $body = @{ type='ActualCost'; timeframe='Custom'; timePeriod=@{from=$from;to=$to}; dataset=@{ granularity='None'; aggregation=@{ totalCost=@{name='PreTaxCost';function='Sum'} }; grouping=@(@{type='Dimension';name='Currency'}) } }

    try {
        $data = Invoke-AzRestJson -Method POST -Path "/subscriptions/$SubscriptionId/providers/Microsoft.CostManagement/query?api-version=2025-03-01" -Body $body
        if ($null -eq $data.properties -or $null -eq $data.properties.rows -or $data.properties.rows.Count -eq 0) {
            return [pscustomobject]@{ Amount = [decimal]0; Currency = 'N/A'; From = $from; To = $to }
        }
        $columns = $data.properties.columns
        $row = $data.properties.rows | Select-Object -First 1
        $amountIndex = -1; $currencyIndex = -1
        for ($i = 0; $i -lt $columns.Count; $i++) {
            if ($columns[$i].name -eq 'totalCost') { $amountIndex = $i }
            if ($columns[$i].name -eq 'Currency') { $currencyIndex = $i }
        }
        return [pscustomobject]@{
            Amount = if ($amountIndex -ge 0) { [math]::Round([decimal]$row[$amountIndex],2) } else { [decimal]0 }
            Currency = if ($currencyIndex -ge 0) { [string]$row[$currencyIndex] } else { 'N/A' }
            From = $from
            To = $to
        }
    }
    catch {
        Write-Warning "Cost query failed for ${SubscriptionId}: $($_.Exception.Message)"
        return [pscustomobject]@{ Amount = [decimal]0; Currency = 'N/A'; From = $from; To = $to }
    }
}

function Get-TopCostResources {
    param([string]$SubscriptionId,[int]$Days,[int]$TopCount)
    $from = (Get-Date).Date.AddDays(-1 * $Days).ToString('yyyy-MM-ddT00:00:00Z')
    $to = (Get-Date).Date.AddDays(1).AddSeconds(-1).ToString('yyyy-MM-ddT23:59:59Z')
    $body = @{ type='ActualCost'; timeframe='Custom'; timePeriod=@{from=$from;to=$to}; dataset=@{ granularity='None'; aggregation=@{ totalCost=@{name='PreTaxCost';function='Sum'} }; grouping=@(@{type='Dimension';name='ResourceId'},@{type='Dimension';name='ResourceType'},@{type='Dimension';name='ResourceGroupName'},@{type='Dimension';name='Currency'}); sorting=@(@{name='totalCost';direction='descending'}) } }

    try {
        $data = Invoke-AzRestJson -Method POST -Path "/subscriptions/$SubscriptionId/providers/Microsoft.CostManagement/query?api-version=2025-03-01" -Body $body
        if ($null -eq $data.properties -or $null -eq $data.properties.rows) { return @() }
        $cols = $data.properties.columns
        $idx = @{}
        for ($i = 0; $i -lt $cols.Count; $i++) { $idx[$cols[$i].name] = $i }
        return @($data.properties.rows | Select-Object -First $TopCount | ForEach-Object {
            [pscustomobject]@{
                ResourceId    = [string]$_[$idx['ResourceId']]
                ResourceType  = [string]$_[$idx['ResourceType']]
                ResourceGroup = [string]$_[$idx['ResourceGroupName']]
                Currency      = [string]$_[$idx['Currency']]
                Cost          = [math]::Round([decimal]$_[$idx['totalCost']], 2)
            }
        })
    }
    catch {
        Write-Warning "Top cost query failed for ${SubscriptionId}: $($_.Exception.Message)"
        return @()
    }
}

function Get-InventoryCounts {
    param([string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId'
| summarize
    TotalResources = count(),
    VirtualMachines = countif(type =~ 'microsoft.compute/virtualmachines'),
    AppServices = countif(type =~ 'microsoft.web/sites'),
    FunctionApps = countif(type =~ 'microsoft.web/sites' and kind contains 'functionapp'),
    SqlServers = countif(type =~ 'microsoft.sql/servers'),
    SqlDatabases = countif(type =~ 'microsoft.sql/servers/databases'),
    StorageAccounts = countif(type =~ 'microsoft.storage/storageaccounts'),
    KeyVaults = countif(type =~ 'microsoft.keyvault/vaults'),
    PublicIPs = countif(type =~ 'microsoft.network/publicipaddresses'),
    LoadBalancers = countif(type =~ 'microsoft.network/loadbalancers'),
    ApplicationGateways = countif(type =~ 'microsoft.network/applicationgateways'),
    NSGs = countif(type =~ 'microsoft.network/networksecuritygroups'),
    VNets = countif(type =~ 'microsoft.network/virtualnetworks'),
    ManagedDisks = countif(type =~ 'microsoft.compute/disks')
"@
    $result = Search-GraphSafe -Query $query -First 1
    if (-not $result -or $result.Count -eq 0) {
        return [pscustomobject]@{ TotalResources=0;VirtualMachines=0;AppServices=0;FunctionApps=0;SqlServers=0;SqlDatabases=0;StorageAccounts=0;KeyVaults=0;PublicIPs=0;LoadBalancers=0;ApplicationGateways=0;NSGs=0;VNets=0;ManagedDisks=0 }
    }
    return $result[0]
}

function Get-UntaggedResources {
    param([string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId'
| extend tagCount = array_length(bag_keys(tags))
| where isnull(tags) or tagCount == 0
| project name, type, resourceGroup, id
| order by type asc, name asc
"@
    Search-GraphSafe -Query $query -First 5000
}

function Get-UnattachedDisks {
    param([string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId' and type =~ 'microsoft.compute/disks'
| where isempty(tostring(properties.managedBy))
| project name, resourceGroup, id, sku=tostring(sku.name), diskSizeGB=tostring(properties.diskSizeGB)
| order by resourceGroup asc, name asc
"@
    Search-GraphSafe -Query $query -First 5000
}

function Get-UnattachedNics {
    param([string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId' and type =~ 'microsoft.network/networkinterfaces'
| where isempty(tostring(properties.virtualMachine.id))
| project name, resourceGroup, id
| order by resourceGroup asc, name asc
"@
    Search-GraphSafe -Query $query -First 5000
}

function Get-IdlePublicIPs {
    param([string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId' and type =~ 'microsoft.network/publicipaddresses'
| where isempty(tostring(properties.ipConfiguration.id))
| project name, resourceGroup, id, sku=tostring(sku.name), ipAddress=tostring(properties.ipAddress)
| order by resourceGroup asc, name asc
"@
    Search-GraphSafe -Query $query -First 5000
}

function Get-OpenNsgRules {
    param([string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId' and type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rule = properties.securityRules
| extend access = tostring(rule.properties.access)
| extend direction = tostring(rule.properties.direction)
| extend source = tostring(rule.properties.sourceAddressPrefix)
| extend destinationPort = tostring(rule.properties.destinationPortRange)
| extend sourceList = tostring(rule.properties.sourceAddressPrefixes)
| extend destinationPorts = tostring(rule.properties.destinationPortRanges)
| where access =~ 'Allow' and direction =~ 'Inbound'
| where source in ('*','0.0.0.0/0','Internet','Any') or sourceList has '0.0.0.0/0' or sourceList has '*'
| where destinationPort in ('*','22','3389','1433','3306','5432','1521','27017') or destinationPorts has '*' or destinationPorts has '22' or destinationPorts has '3389' or destinationPorts has '1433' or destinationPorts has '3306' or destinationPorts has '5432' or destinationPorts has '1521' or destinationPorts has '27017'
| project nsgName=name, resourceGroup, id, ruleName=tostring(rule.name), source, destinationPort, destinationPorts, priority=tostring(rule.properties.priority), protocol=tostring(rule.properties.protocol)
| order by resourceGroup asc, nsgName asc, toint(priority) asc
"@
    Search-GraphSafe -Query $query -First 5000
}

function Get-AppServiceExposure {
    param([string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId' and type =~ 'microsoft.web/sites'
| extend publicNetworkAccess = tostring(properties.publicNetworkAccess)
| extend peCount = array_length(properties.privateEndpointConnections)
| extend httpsOnly = tostring(properties.httpsOnly)
| extend clientCertEnabled = tostring(properties.clientCertEnabled)
| extend minTlsVersion = tostring(properties.siteConfig.minTlsVersion)
| project name, kind, resourceGroup, id, publicNetworkAccess, peCount, httpsOnly, clientCertEnabled, minTlsVersion
| order by resourceGroup asc, name asc
"@
    Search-GraphSafe -Query $query -First 5000
}

function Get-StorageExposure {
    param([string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId' and type =~ 'microsoft.storage/storageaccounts'
| extend publicNetworkAccess = tostring(properties.publicNetworkAccess)
| extend supportsHttpsTrafficOnly = tostring(properties.supportsHttpsTrafficOnly)
| extend minTlsVersion = tostring(properties.minimumTlsVersion)
| extend allowBlobPublicAccess = tostring(properties.allowBlobPublicAccess)
| extend peCount = array_length(properties.privateEndpointConnections)
| project name, resourceGroup, id, publicNetworkAccess, supportsHttpsTrafficOnly, minTlsVersion, allowBlobPublicAccess, peCount
| order by resourceGroup asc, name asc
"@
    Search-GraphSafe -Query $query -First 5000
}

function Get-KeyVaultExposure {
    param([string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId' and type =~ 'microsoft.keyvault/vaults'
| extend publicNetworkAccess = tostring(properties.publicNetworkAccess)
| extend enablePurgeProtection = tostring(properties.enablePurgeProtection)
| extend enableSoftDelete = tostring(properties.enableSoftDelete)
| extend peCount = array_length(properties.privateEndpointConnections)
| project name, resourceGroup, id, publicNetworkAccess, enablePurgeProtection, enableSoftDelete, peCount
| order by resourceGroup asc, name asc
"@
    Search-GraphSafe -Query $query -First 5000
}

function Get-VMsWithoutBackup {
    param([string]$SubscriptionId)
    $query = @"
let protectedItems = RecoveryServicesResources
| where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems'
| extend sourceResourceId = tostring(properties.sourceResourceId)
| where sourceResourceId has '/subscriptions/$SubscriptionId/'
| project sourceResourceId;
Resources
| where subscriptionId =~ '$SubscriptionId' and type =~ 'microsoft.compute/virtualmachines'
| join kind=leftanti protectedItems on $left.id == $right.sourceResourceId
| project name, resourceGroup, vmId=id
| order by resourceGroup asc, name asc
"@
    Search-GraphSafe -Query $query -First 5000
}

function Get-PolicyCoverage {
    param([string]$SubscriptionId)
    try {
        $assignments = @(Get-AzPolicyAssignment -Scope "/subscriptions/$SubscriptionId" -ErrorAction Stop)
    }
    catch {
        Write-Warning "Policy assignment query failed: $($_.Exception.Message)"
        $assignments = @()
    }
    return $assignments
}

function Get-NetworkTopologySummary {
    param([string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId'
| where type in~ ('microsoft.network/virtualnetworks','microsoft.network/azurefirewalls','microsoft.network/applicationgateways','microsoft.network/loadbalancers','microsoft.network/networkwatchers','microsoft.network/virtualnetworkgateways','microsoft.network/privateendpoints','microsoft.network/publicipaddresses')
| summarize ResourceCount=count() by type
| order by type asc
"@
    Search-GraphSafe -Query $query -First 1000
}

function Get-EstimatedLandingZoneScore {
    param(
        [object]$Inventory,
        [array]$PolicyAssignments,
        [object]$SecureScore,
        [array]$OpenNsgRules,
        [array]$UntaggedResources
    )

    $score = 0
    if ($PolicyAssignments.Count -ge 5) { $score += 20 } elseif ($PolicyAssignments.Count -gt 0) { $score += 10 }
    if ($Inventory.VNets -gt 0) { $score += 10 }
    if ($Inventory.KeyVaults -gt 0) { $score += 10 }
    if ($Inventory.PublicIPs -eq 0) { $score += 10 } elseif ($Inventory.PublicIPs -lt 5) { $score += 5 }
    if ($OpenNsgRules.Count -eq 0) { $score += 15 }
    if ($UntaggedResources.Count -eq 0) { $score += 10 } elseif ($UntaggedResources.Count -lt 10) { $score += 5 }
    if ($SecureScore -and $SecureScore.Percentage -ge 75) { $score += 25 } elseif ($SecureScore -and $SecureScore.Percentage -ge 50) { $score += 15 } elseif ($SecureScore) { $score += 5 }

    $tier = if ($score -ge 80) { 'Advanced' } elseif ($score -ge 55) { 'Intermediate' } else { 'Basic' }
    [pscustomobject]@{ Score = $score; Tier = $tier }
}

function Export-HtmlReport {
    param(
        [string]$Path,
        [array]$Summary,
        [array]$Findings,
        [array]$TopCosts,
        [array]$NetworkTopology,
        [object]$LandingZone
    )

    $summaryHtml = $Summary | Select-Object SubscriptionName,SubscriptionId,SecureScorePercent,Last30DaysCost,Currency,TotalFindings,HighFindings,SecurityFindings,CostFindings,PerformanceFindings,LandingZoneScore,LandingZoneTier | ConvertTo-Html -Fragment
    $highFindingsHtml = ($Findings | Where-Object Severity -eq 'High' | Select-Object SubscriptionName,Category,Source,Title,ResourceId,Recommendation | ConvertTo-Html -Fragment)
    $topCostHtml = ($TopCosts | Select-Object -First 15 SubscriptionName,ResourceType,ResourceGroup,Cost,Currency,ResourceId | ConvertTo-Html -Fragment)
    $topologyHtml = ($NetworkTopology | ConvertTo-Html -Fragment)

    $html = @"
<html>
<head>
<title>AzureScan Assessment Report</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #222; }
h1, h2, h3 { color: #0b5cab; }
table { border-collapse: collapse; width: 100%; margin-bottom: 24px; }
th, td { border: 1px solid #d0d7de; padding: 8px; text-align: left; font-size: 12px; }
th { background: #f3f6fa; }
.kpi { display: inline-block; padding: 12px 16px; margin-right: 12px; margin-bottom: 12px; border: 1px solid #d0d7de; border-radius: 8px; background: #fafcff; }
.small { font-size: 12px; color: #555; }
</style>
</head>
<body>
<h1>AzureScan Assessment Report</h1>
<p class='small'>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<div class='kpi'><strong>Landing Zone Score:</strong> $($LandingZone.Score)</div>
<div class='kpi'><strong>Landing Zone Tier:</strong> $($LandingZone.Tier)</div>
<h2>Executive Summary</h2>
$summaryHtml
<h2>Top High Severity Findings</h2>
$highFindingsHtml
<h2>Top Cost Drivers</h2>
$topCostHtml
<h2>Network Topology Summary</h2>
$topologyHtml
</body>
</html>
"@
    Set-Content -Path $Path -Value $html -Encoding UTF8
}

function Export-PptOutline {
    param([string]$Path,[array]$Summary,[array]$Findings)
    $high = @($Findings | Where-Object Severity -eq 'High' | Select-Object -First 10)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# AzureScan Executive Deck Outline') | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add('## Slide 1 - Title') | Out-Null
    $lines.Add('Azure Subscription Assessment') | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add('## Slide 2 - Executive Summary') | Out-Null
    foreach ($s in $Summary) {
        $lines.Add(("- {0}: Secure Score {1}%, Cost {2} {3}, Total Findings {4}, High Findings {5}, Landing Zone {6}/{7}" -f $s.SubscriptionName, $s.SecureScorePercent, $s.Last30DaysCost, $s.Currency, $s.TotalFindings, $s.HighFindings, $s.LandingZoneScore, $s.LandingZoneTier)) | Out-Null
    }
    $lines.Add('') | Out-Null
    $lines.Add('## Slide 3 - Top Risks') | Out-Null
    foreach ($item in $high) {
        $lines.Add(("- [{0}] {1} - {2}" -f $item.Category, $item.Title, $item.Recommendation)) | Out-Null
    }
    $lines.Add('') | Out-Null
    $lines.Add('## Slide 4 - 30 Day Priorities') | Out-Null
    $lines.Add('- Remediate internet-exposed management ports and weak network controls') | Out-Null
    $lines.Add('- Address low Secure Score and Defender posture gaps') | Out-Null
    $lines.Add('- Eliminate idle resources and review top cost drivers') | Out-Null
    $lines.Add('- Enforce tagging, policy, and private access patterns') | Out-Null
    Set-Content -Path $Path -Value ($lines -join [Environment]::NewLine) -Encoding UTF8
}

Write-Status 'Preparing environment'
$OutputFolder = Resolve-DefaultOutputFolder
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$null = Ensure-Module -Name 'Az.Accounts'
$null = Ensure-Module -Name 'Az.ResourceGraph'
$null = Ensure-Module -Name 'Az.Resources'
$excelAvailable = $false
if (-not $SkipExcel) { $excelAvailable = Ensure-Module -Name 'ImportExcel' -Optional }

try { $ctx = Get-AzContext -ErrorAction Stop } catch { $ctx = $null }
if (-not $ctx) { Connect-AzAccount -ErrorAction Stop | Out-Null }

$subscriptions = if ($SubscriptionId) {
    @(Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop)
} else {
    $ctx = Get-AzContext -ErrorAction Stop
    if ($ctx.Subscription -and $ctx.Subscription.Id) { @(Get-AzSubscription -SubscriptionId $ctx.Subscription.Id -ErrorAction Stop) } else { throw 'No active subscription found. Pass -SubscriptionId explicitly.' }
}
if (-not $subscriptions -or $subscriptions.Count -eq 0) { throw "No Azure subscriptions found for '${SubscriptionId}'." }

$findings = New-Object System.Collections.Generic.List[object]
$summary = New-Object System.Collections.Generic.List[object]
$inventoryAll = New-Object System.Collections.Generic.List[object]
$topCostsAll = New-Object System.Collections.Generic.List[object]
$networkTopologyAll = New-Object System.Collections.Generic.List[object]
$policySummaryAll = New-Object System.Collections.Generic.List[object]

foreach ($sub in $subscriptions) {
    Write-Status "Processing subscription $($sub.Name) [$($sub.Id)]"
    Set-AzContext -SubscriptionId $sub.Id | Out-Null

    $inventory = Get-InventoryCounts -SubscriptionId $sub.Id
    $cost = Get-CostLastNDays -SubscriptionId $sub.Id -Days $CostLookbackDays
    $secureScore = Get-SecureScore -SubscriptionId $sub.Id
    $advisor = @(Get-AdvisorRecommendations -SubscriptionId $sub.Id -Refresh:$RefreshAdvisorRecommendations)
    $topCosts = @(Get-TopCostResources -SubscriptionId $sub.Id -Days $CostLookbackDays -TopCount $TopCostResourceCount)
    $untaggedResources = @(Get-UntaggedResources -SubscriptionId $sub.Id)
    $unattachedDisks = @(Get-UnattachedDisks -SubscriptionId $sub.Id)
    $unattachedNics = @(Get-UnattachedNics -SubscriptionId $sub.Id)
    $idlePublicIps = @(Get-IdlePublicIPs -SubscriptionId $sub.Id)
    $openNsgRules = @(Get-OpenNsgRules -SubscriptionId $sub.Id)
    $appServices = @(Get-AppServiceExposure -SubscriptionId $sub.Id)
    $storageAccounts = @(Get-StorageExposure -SubscriptionId $sub.Id)
    $keyVaults = @(Get-KeyVaultExposure -SubscriptionId $sub.Id)
    $unprotectedVms = @(Get-VMsWithoutBackup -SubscriptionId $sub.Id)
    $defenderPricings = @(Get-DefenderPricings -SubscriptionId $sub.Id)
    $policyAssignments = @(Get-PolicyCoverage -SubscriptionId $sub.Id)
    $networkTopology = @(Get-NetworkTopologySummary -SubscriptionId $sub.Id)
    $landingZone = Get-EstimatedLandingZoneScore -Inventory $inventory -PolicyAssignments $policyAssignments -SecureScore $secureScore -OpenNsgRules $openNsgRules -UntaggedResources $untaggedResources

    $inventoryAll.Add([pscustomobject]@{
        SubscriptionName = $sub.Name
        SubscriptionId = $sub.Id
        TotalResources = $inventory.TotalResources
        VirtualMachines = $inventory.VirtualMachines
        AppServices = $inventory.AppServices
        FunctionApps = $inventory.FunctionApps
        SqlServers = $inventory.SqlServers
        SqlDatabases = $inventory.SqlDatabases
        StorageAccounts = $inventory.StorageAccounts
        KeyVaults = $inventory.KeyVaults
        PublicIPs = $inventory.PublicIPs
        LoadBalancers = $inventory.LoadBalancers
        ApplicationGateways = $inventory.ApplicationGateways
        NSGs = $inventory.NSGs
        VNets = $inventory.VNets
        ManagedDisks = $inventory.ManagedDisks
    }) | Out-Null

    foreach ($item in $topCosts) {
        $topCostsAll.Add([pscustomobject]@{ SubscriptionName=$sub.Name; SubscriptionId=$sub.Id; ResourceId=$item.ResourceId; ResourceType=$item.ResourceType; ResourceGroup=$item.ResourceGroup; Cost=$item.Cost; Currency=$item.Currency }) | Out-Null
    }
    foreach ($item in $networkTopology) {
        $networkTopologyAll.Add([pscustomobject]@{ SubscriptionName=$sub.Name; SubscriptionId=$sub.Id; ResourceType=$item.type; Count=$item.ResourceCount }) | Out-Null
    }
    $policySummaryAll.Add([pscustomobject]@{ SubscriptionName=$sub.Name; SubscriptionId=$sub.Id; PolicyAssignments=$policyAssignments.Count; LandingZoneScore=$landingZone.Score; LandingZoneTier=$landingZone.Tier }) | Out-Null

    if ($secureScore) {
        $sev = if ($secureScore.Percentage -lt 40) { 'High' } elseif ($secureScore.Percentage -lt 70) { 'Medium' } else { 'Low' }
        Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Security' -Severity $sev -Source 'DefenderForCloud' -Title 'Secure Score posture' -ResourceId '' -Recommendation 'Review Defender for Cloud recommendations and improve hardening controls.' -RawData $secureScore
    }

    foreach ($plan in ($defenderPricings | Where-Object { $_.PricingTier -eq 'Free' })) {
        Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Security' -Severity 'Medium' -Source 'DefenderForCloud' -Title "Defender plan in Free tier: $($plan.Name)" -ResourceId '' -Recommendation 'Evaluate whether this workload should be protected with a paid Defender plan.' -RawData $plan
    }

    foreach ($rec in $advisor) {
        $title = [string]$rec.properties.shortDescription.problem
        $recommendation = [string]$rec.properties.shortDescription.solution
        $resourceId = [string]$rec.properties.resourceMetadata.resourceId
        Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category ([string]$rec.properties.category) -Severity (Get-SeverityFromAdvisorImpact -Impact ([string]$rec.properties.impact)) -Source 'AzureAdvisor' -Title $title -ResourceId $resourceId -Recommendation $recommendation -RawData $rec
    }

    Add-CategoryFindings -Findings ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Governance' -Severity 'Medium' -Source 'ResourceGraph' -Items $untaggedResources -TitleFactory { param($x) "Resource without tags: $($x.name)" } -RecommendationFactory { param($x) 'Apply the required tag policy and ownership metadata.' } -ResourceIdFactory { param($x) [string]$x.id }
    Add-CategoryFindings -Findings ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Cost' -Severity 'Medium' -Source 'ResourceGraph' -Items $unattachedDisks -TitleFactory { param($x) "Unattached disk: $($x.name)" } -RecommendationFactory { param($x) 'Validate whether the disk is still required. Remove or archive idle disks.' } -ResourceIdFactory { param($x) [string]$x.id }
    Add-CategoryFindings -Findings ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Cost' -Severity 'Medium' -Source 'ResourceGraph' -Items $unattachedNics -TitleFactory { param($x) "Unattached NIC: $($x.name)" } -RecommendationFactory { param($x) 'Delete unattached NICs when no longer required.' } -ResourceIdFactory { param($x) [string]$x.id }
    Add-CategoryFindings -Findings ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Cost' -Severity 'Medium' -Source 'ResourceGraph' -Items $idlePublicIps -TitleFactory { param($x) "Unassociated Public IP: $($x.name)" } -RecommendationFactory { param($x) 'Remove unused Public IPs to reduce cost and attack surface.' } -ResourceIdFactory { param($x) [string]$x.id }
    Add-CategoryFindings -Findings ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Security' -Severity 'High' -Source 'ResourceGraph' -Items $openNsgRules -TitleFactory { param($x) "Internet-exposed NSG rule: $($x.ruleName) on $($x.nsgName)" } -RecommendationFactory { param($x) 'Restrict management or database ports from the internet. Use private access, Bastion, VPN, or firewall controls.' } -ResourceIdFactory { param($x) [string]$x.id }
    Add-CategoryFindings -Findings ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Reliability' -Severity 'High' -Source 'RecoveryServices' -Items $unprotectedVms -TitleFactory { param($x) "VM without backup: $($x.name)" } -RecommendationFactory { param($x) 'Protect the VM with Azure Backup or an approved backup service.' } -ResourceIdFactory { param($x) [string]$x.vmId }

    foreach ($app in $appServices) {
        if ($app.peCount -eq 0 -and $app.publicNetworkAccess -ne 'Disabled') {
            Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Security' -Severity 'Medium' -Source 'ResourceGraph' -Title "App Service without Private Endpoint: $($app.name)" -ResourceId ([string]$app.id) -Recommendation 'Consider Private Endpoint and disable public network access when business requirements allow it.' -RawData $app
        }
        if ($app.httpsOnly -ne 'true') {
            Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Security' -Severity 'High' -Source 'ResourceGraph' -Title "App Service without HTTPS only: $($app.name)" -ResourceId ([string]$app.id) -Recommendation 'Enable HTTPS only.' -RawData $app
        }
        if ($app.minTlsVersion -and $app.minTlsVersion -lt '1.2') {
            Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Security' -Severity 'Medium' -Source 'ResourceGraph' -Title "App Service with weak TLS: $($app.name)" -ResourceId ([string]$app.id) -Recommendation 'Set minimum TLS version to 1.2 or higher.' -RawData $app
        }
    }

    foreach ($sa in $storageAccounts) {
        if ($sa.publicNetworkAccess -ne 'Disabled') {
            Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Security' -Severity 'Medium' -Source 'ResourceGraph' -Title "Storage account publicly reachable: $($sa.name)" -ResourceId ([string]$sa.id) -Recommendation 'Review whether public network access should be disabled and replaced with private endpoints.' -RawData $sa
        }
        if ($sa.supportsHttpsTrafficOnly -ne 'true') {
            Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Security' -Severity 'High' -Source 'ResourceGraph' -Title "Storage account without secure transfer required: $($sa.name)" -ResourceId ([string]$sa.id) -Recommendation 'Enable HTTPS only / secure transfer required.' -RawData $sa
        }
        if ($sa.minTlsVersion -and $sa.minTlsVersion -lt 'TLS1_2') {
            Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Security' -Severity 'Medium' -Source 'ResourceGraph' -Title "Storage account with weak TLS: $($sa.name)" -ResourceId ([string]$sa.id) -Recommendation 'Set minimum TLS version to TLS 1.2.' -RawData $sa
        }
        if ($sa.allowBlobPublicAccess -eq 'true') {
            Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Security' -Severity 'High' -Source 'ResourceGraph' -Title "Storage account allows blob public access: $($sa.name)" -ResourceId ([string]$sa.id) -Recommendation 'Disable blob public access unless there is a documented business requirement.' -RawData $sa
        }
    }

    foreach ($kv in $keyVaults) {
        if ($kv.publicNetworkAccess -ne 'Disabled') {
            Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Security' -Severity 'High' -Source 'ResourceGraph' -Title "Key Vault publicly reachable: $($kv.name)" -ResourceId ([string]$kv.id) -Recommendation 'Disable public network access and use private endpoints where possible.' -RawData $kv
        }
        if ($kv.enablePurgeProtection -ne 'true') {
            Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Security' -Severity 'Medium' -Source 'ResourceGraph' -Title "Key Vault without purge protection: $($kv.name)" -ResourceId ([string]$kv.id) -Recommendation 'Enable purge protection to reduce deletion risk.' -RawData $kv
        }
    }

    if ($cost.Amount -ge 10000) {
        Add-Finding -Collection ([ref]$findings) -SubscriptionName $sub.Name -SubscriptionId $sub.Id -Category 'Cost' -Severity 'Medium' -Source 'CostManagement' -Title 'High monthly spend' -ResourceId '' -Recommendation 'Review rightsizing, idle resources, reservations, and top cost drivers.' -RawData $cost
    }

    $subFindings = @($findings | Where-Object { $_.SubscriptionId -eq $sub.Id })
    $summary.Add([pscustomobject]@{
        SubscriptionName = $sub.Name
        SubscriptionId = $sub.Id
        SecureScorePercent = if ($secureScore) { $secureScore.Percentage } else { $null }
        SecureScoreCurrent = if ($secureScore) { $secureScore.CurrentScore } else { $null }
        SecureScoreMax = if ($secureScore) { $secureScore.MaxScore } else { $null }
        Last30DaysCost = $cost.Amount
        Currency = $cost.Currency
        TotalFindings = $subFindings.Count
        HighFindings = @($subFindings | Where-Object Severity -eq 'High').Count
        MediumFindings = @($subFindings | Where-Object Severity -eq 'Medium').Count
        LowFindings = @($subFindings | Where-Object Severity -eq 'Low').Count
        SecurityFindings = @($subFindings | Where-Object { $_.Category -match 'Security' }).Count
        CostFindings = @($subFindings | Where-Object { $_.Category -match 'Cost' }).Count
        PerformanceFindings = @($subFindings | Where-Object { $_.Category -match 'Performance' }).Count
        ReliabilityFindings = @($subFindings | Where-Object { $_.Category -match 'Reliability' }).Count
        GovernanceFindings = @($subFindings | Where-Object { $_.Category -match 'Governance|Operational' }).Count
        LandingZoneScore = $landingZone.Score
        LandingZoneTier = $landingZone.Tier
        PolicyAssignments = $policyAssignments.Count
        PublicIPs = $inventory.PublicIPs
        UntaggedResources = $untaggedResources.Count
    }) | Out-Null
}

$summaryCsv = Join-Path $OutputFolder 'AzureAssessment-Summary.csv'
$findingsCsv = Join-Path $OutputFolder 'AzureAssessment-Findings.csv'
$inventoryCsv = Join-Path $OutputFolder 'AzureAssessment-Inventory.csv'
$topCostsCsv = Join-Path $OutputFolder 'AzureAssessment-TopCostResources.csv'
$policyCsv = Join-Path $OutputFolder 'AzureAssessment-PolicySummary.csv'
$networkCsv = Join-Path $OutputFolder 'AzureAssessment-NetworkTopology.csv'
$summaryJson = Join-Path $OutputFolder 'AzureAssessment-Summary.json'
$pptOutline = Join-Path $OutputFolder 'AzureAssessment-Executive-Deck-Outline.md'
$htmlReport = Join-Path $OutputFolder 'AzureAssessment-Report.html'

$summary | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $summaryCsv
$findings | Select-Object SubscriptionName,SubscriptionId,Category,Severity,Source,Title,ResourceId,Recommendation | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $findingsCsv
$inventoryAll | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $inventoryCsv
$topCostsAll | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $topCostsCsv
$policySummaryAll | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $policyCsv
$networkTopologyAll | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $networkCsv
$summary | ConvertTo-Json -Depth 10 | Out-File -FilePath $summaryJson -Encoding UTF8
Export-PptOutline -Path $pptOutline -Summary $summary -Findings $findings

if (-not $SkipHtml) {
    $landingZoneOverall = if ($summary.Count -gt 0) {
        [pscustomobject]@{ Score = [math]::Round((($summary | Measure-Object -Property LandingZoneScore -Average).Average),2); Tier = 'Mixed' }
    } else {
        [pscustomobject]@{ Score = 0; Tier = 'Unknown' }
    }
    Export-HtmlReport -Path $htmlReport -Summary $summary -Findings $findings -TopCosts $topCostsAll -NetworkTopology $networkTopologyAll -LandingZone $landingZoneOverall
}

if ($excelAvailable) {
    $excelPath = Join-Path $OutputFolder 'AzureAssessment-Summary.xlsx'
    Remove-Item $excelPath -ErrorAction SilentlyContinue
    $summary | Export-Excel -Path $excelPath -WorksheetName 'Summary' -AutoSize -FreezeTopRow -BoldTopRow
    $findings | Export-Excel -Path $excelPath -WorksheetName 'AllFindings' -AutoSize -FreezeTopRow -BoldTopRow -Append
    ($findings | Where-Object { $_.Category -match 'Security' }) | Export-Excel -Path $excelPath -WorksheetName 'Security' -AutoSize -FreezeTopRow -BoldTopRow -Append
    ($findings | Where-Object { $_.Category -match 'Cost' }) | Export-Excel -Path $excelPath -WorksheetName 'Cost' -AutoSize -FreezeTopRow -BoldTopRow -Append
    ($findings | Where-Object { $_.Category -match 'Performance' }) | Export-Excel -Path $excelPath -WorksheetName 'Performance' -AutoSize -FreezeTopRow -BoldTopRow -Append
    ($findings | Where-Object { $_.Category -match 'Reliability' }) | Export-Excel -Path $excelPath -WorksheetName 'Reliability' -AutoSize -FreezeTopRow -BoldTopRow -Append
    ($findings | Where-Object { $_.Category -match 'Governance|Operational' }) | Export-Excel -Path $excelPath -WorksheetName 'Governance' -AutoSize -FreezeTopRow -BoldTopRow -Append
    $inventoryAll | Export-Excel -Path $excelPath -WorksheetName 'Inventory' -AutoSize -FreezeTopRow -BoldTopRow -Append
    $topCostsAll | Export-Excel -Path $excelPath -WorksheetName 'TopCostResources' -AutoSize -FreezeTopRow -BoldTopRow -Append
    $policySummaryAll | Export-Excel -Path $excelPath -WorksheetName 'LandingZone' -AutoSize -FreezeTopRow -BoldTopRow -Append
    $networkTopologyAll | Export-Excel -Path $excelPath -WorksheetName 'NetworkTopology' -AutoSize -FreezeTopRow -BoldTopRow -Append
    Write-Status "Excel report generated at $excelPath"
} else {
    Write-Warning 'ImportExcel is not available. Excel output was skipped, but CSV/JSON/HTML outputs were generated.'
}

Write-Status "Assessment completed. Output folder: $OutputFolder"
