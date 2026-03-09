<#
.SYNOPSIS
    Advanced Azure subscription assessment with executive Excel output.

.DESCRIPTION
    Evaluates one Azure subscription and generates:
      - Executive Excel workbook with Overview, Summary, Security, Performance, Cost, Reliability,
        OperationalExcellence, Inventory, TopCostResources, and AllFindings tabs
      - CSV exports for findings, summary, inventory, and top costs
      - JSON summary

    Assessment sources:
      - Azure Advisor recommendations
      - Microsoft Defender for Cloud Secure Score and Defender plans
      - Azure Cost Management Query API
      - Azure Resource Graph inventory and posture queries

    This version is prepared for direct execution from Azure Cloud Shell, GitHub Raw, or Blob Storage URLs.
#>

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$OutputFolder,
    [int]$CostLookbackDays = 30,
    [int]$TopCostResourceCount = 15,
    [switch]$RefreshAdvisorRecommendations,
    [switch]$SkipExcel
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-DefaultOutputFolder {
    if ($OutputFolder) { return $OutputFolder }
    $cloudDrive = Join-Path $HOME 'clouddrive'
    if (Test-Path $cloudDrive) { return (Join-Path $cloudDrive 'assessment') }
    return (Join-Path $PWD 'assessment')
}

function Ensure-ModulePresent {
    param([Parameter(Mandatory = $true)][string]$ModuleName)
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        throw "Required module '$ModuleName' is not installed. Install it first or run through the bootstrap script."
    }
    Import-Module $ModuleName -Force -ErrorAction Stop
}

function Invoke-AzRestJson {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GET','POST','PUT','PATCH','DELETE')][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [object]$Body
    )

    $response = if ($PSBoundParameters.ContainsKey('Body')) {
        Invoke-AzRestMethod -Method $Method -Path $Path -Payload ($Body | ConvertTo-Json -Depth 50)
    }
    else {
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
        RawData          = if ($null -ne $RawData) { $RawData | ConvertTo-Json -Depth 50 -Compress } else { $null }
    }) | Out-Null
}

function Get-SeverityFromAdvisorImpact {
    param([string]$Impact)
    if ([string]::IsNullOrWhiteSpace($Impact)) { return 'Info' }
    switch ($Impact.ToLowerInvariant()) {
        'high'   { 'High' }
        'medium' { 'Medium' }
        'low'    { 'Low' }
        default  { 'Info' }
    }
}

function Search-GraphSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Query,
        [int]$First = 1000
    )
    try {
        return Search-AzGraph -Query $Query -First $First
    }
    catch {
        Write-Warning "Resource Graph query failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-SecureScore {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)

    $data = Invoke-AzRestJson -Method GET -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/secureScores?api-version=2020-01-01-preview"
    if ($null -eq $data -or $null -eq $data.value -or $data.value.Count -eq 0) { return $null }

    $score = $data.value | Select-Object -First 1
    $current = 0.0
    $max = 0.0
    if ($null -ne $score.properties.score.current) { $current = [double]$score.properties.score.current }
    if ($null -ne $score.properties.score.max) { $max = [double]$score.properties.score.max }
    $percentage = if ($max -gt 0) { [math]::Round(($current / $max) * 100, 2) } else { 0 }

    [pscustomobject]@{
        Name         = $score.name
        CurrentScore = $current
        MaxScore     = $max
        Percentage   = $percentage
    }
}

function Get-DefenderPricings {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)
    try {
        $data = Invoke-AzRestJson -Method GET -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Security/pricings?api-version=2024-01-01"
        if ($null -eq $data -or $null -eq $data.value) { return @() }
        return @($data.value | ForEach-Object {
            [pscustomobject]@{
                Name        = $_.name
                PricingTier = [string]$_.properties.pricingTier
                SubPlan     = [string]$_.properties.subPlan
            }
        })
    }
    catch {
        Write-Warning "Could not retrieve Defender plans: $($_.Exception.Message)"
        return @()
    }
}

function Get-AdvisorRecommendations {
    param(
        [Parameter(Mandatory = $true)][string]$SubscriptionId,
        [switch]$Refresh
    )

    if ($Refresh) {
        try {
            $null = Invoke-AzRestJson -Method POST -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Advisor/generateRecommendations?api-version=2025-01-01"
            Start-Sleep -Seconds 8
        }
        catch {
            Write-Warning "Could not trigger Advisor refresh for $SubscriptionId. Cached recommendations will be used."
        }
    }

    $data = Invoke-AzRestJson -Method GET -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Advisor/recommendations?api-version=2025-01-01"
    if ($null -eq $data -or $null -eq $data.value) { return @() }
    return $data.value
}

function Get-CostLastNDays {
    param(
        [Parameter(Mandatory = $true)][string]$SubscriptionId,
        [Parameter(Mandatory = $true)][int]$Days
    )

    $from = (Get-Date).Date.AddDays(-1 * $Days).ToString('yyyy-MM-ddT00:00:00Z')
    $to = (Get-Date).Date.AddDays(1).AddSeconds(-1).ToString('yyyy-MM-ddT23:59:59Z')

    $body = @{
        type = 'ActualCost'
        timeframe = 'Custom'
        timePeriod = @{ from = $from; to = $to }
        dataset = @{
            granularity = 'None'
            aggregation = @{ totalCost = @{ name = 'PreTaxCost'; function = 'Sum' } }
            grouping = @(@{ type = 'Dimension'; name = 'Currency' })
        }
    }

    $data = Invoke-AzRestJson -Method POST -Path "/subscriptions/$SubscriptionId/providers/Microsoft.CostManagement/query?api-version=2025-03-01" -Body $body

    if ($null -eq $data.properties -or $null -eq $data.properties.rows -or $data.properties.rows.Count -eq 0) {
        return [pscustomobject]@{ Amount = [decimal]0; Currency = 'N/A'; From = $from; To = $to }
    }

    $columns = $data.properties.columns
    $row = $data.properties.rows | Select-Object -First 1
    $amountIndex = -1
    $currencyIndex = -1
    for ($i = 0; $i -lt $columns.Count; $i++) {
        if ($columns[$i].name -eq 'totalCost') { $amountIndex = $i }
        if ($columns[$i].name -eq 'Currency') { $currencyIndex = $i }
    }

    [pscustomobject]@{
        Amount   = if ($amountIndex -ge 0) { [math]::Round([decimal]$row[$amountIndex], 2) } else { [decimal]0 }
        Currency = if ($currencyIndex -ge 0) { [string]$row[$currencyIndex] } else { 'N/A' }
        From     = $from
        To       = $to
    }
}

function Get-TopCostResources {
    param(
        [Parameter(Mandatory = $true)][string]$SubscriptionId,
        [Parameter(Mandatory = $true)][int]$Days,
        [Parameter(Mandatory = $true)][int]$TopCount
    )

    $from = (Get-Date).Date.AddDays(-1 * $Days).ToString('yyyy-MM-ddT00:00:00Z')
    $to = (Get-Date).Date.AddDays(1).AddSeconds(-1).ToString('yyyy-MM-ddT23:59:59Z')

    $body = @{
        type = 'ActualCost'
        timeframe = 'Custom'
        timePeriod = @{ from = $from; to = $to }
        dataset = @{
            granularity = 'None'
            aggregation = @{ totalCost = @{ name = 'PreTaxCost'; function = 'Sum' } }
            grouping = @(
                @{ type = 'Dimension'; name = 'ResourceId' },
                @{ type = 'Dimension'; name = 'ResourceType' },
                @{ type = 'Dimension'; name = 'ResourceGroupName' },
                @{ type = 'Dimension'; name = 'Currency' }
            )
            sorting = @(@{ name = 'totalCost'; direction = 'descending' })
        }
    }

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
        Write-Warning "Top cost query failed for $SubscriptionId: $($_.Exception.Message)"
        return @()
    }
}

function Get-InventoryCounts {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)

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
        return [pscustomobject]@{
            TotalResources = 0; VirtualMachines = 0; AppServices = 0; FunctionApps = 0; SqlServers = 0; SqlDatabases = 0
            StorageAccounts = 0; KeyVaults = 0; PublicIPs = 0; LoadBalancers = 0; ApplicationGateways = 0; NSGs = 0; VNets = 0; ManagedDisks = 0
        }
    }
    return $result[0]
}

function Get-UntaggedResources {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId'
| extend tagCount = array_length(bag_keys(tags))
| where isnull(tags) or tagCount == 0
| project name, type, resourceGroup, id
| order by type asc, name asc
"@
    return @(Search-GraphSafe -Query $query -First 5000)
}

function Get-UnattachedDisks {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId' and type =~ 'microsoft.compute/disks'
| where isempty(tostring(properties.managedBy))
| project name, resourceGroup, id, sku=tostring(sku.name), diskSizeGB=tostring(properties.diskSizeGB)
| order by resourceGroup asc, name asc
"@
    return @(Search-GraphSafe -Query $query -First 5000)
}

function Get-UnattachedNics {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId' and type =~ 'microsoft.network/networkinterfaces'
| where isempty(tostring(properties.virtualMachine.id))
| project name, resourceGroup, id
| order by resourceGroup asc, name asc
"@
    return @(Search-GraphSafe -Query $query -First 5000)
}

function Get-IdlePublicIPs {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)
    $query = @"
Resources
| where subscriptionId =~ '$SubscriptionId' and type =~ 'microsoft.network/publicipaddresses'
| where isempty(tostring(properties.ipConfiguration.id))
| project name, resourceGroup, id, sku=tostring(sku.name), ipAddress=tostring(properties.ipAddress)
| order by resourceGroup asc, name asc
"@
    return @(Search-GraphSafe -Query $query -First 5000)
}

function Get-OpenNsgRules {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)
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
    return @(Search-GraphSafe -Query $query -First 5000)
}

function Get-AppServiceExposure {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)
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
    return @(Search-GraphSafe -Query $query -First 5000)
}

function Get-StorageExposure {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)
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
    return @(Search-GraphSafe -Query $query -First 5000)
}

function Get-KeyVaultExposure {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)
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
    return @(Search-GraphSafe -Query $query -First 5000)
}

function Get-VMsWithoutBackup {
    param([Parameter(Mandatory = $true)][string]$SubscriptionId)

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
    return @(Search-GraphSafe -Query $query -First 5000)
}

Ensure-ModulePresent -ModuleName Az.Accounts
Ensure-ModulePresent -ModuleName Az.ResourceGraph
if (-not $SkipExcel) { Ensure-ModulePresent -ModuleName ImportExcel }

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    Connect-AzAccount -ErrorAction Stop | Out-Null
}

$subscriptions = if ($SubscriptionId) {
    @(Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop)
}
else {
    $ctx = Get-AzContext -ErrorAction Stop
    if ($ctx.Subscription -and $ctx.Subscription.Id) {
        @(Get-AzSubscription -SubscriptionId $ctx.Subscription.Id -ErrorAction Stop)
    }
    else {
        throw 'No active Azure subscription context was found. Pass -SubscriptionId explicitly.'
    }
}

if (-not $subscriptions -or $subscriptions.Count -eq 0) {
    throw "No Azure subscriptions found for the provided context or SubscriptionId '$SubscriptionId'."
}

$OutputFolder = Resolve-DefaultOutputFolder
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

$findings = New-Object System.Collections.Generic.List[object]
$summary = New-Object System.Collections.Generic.List[object]
$inventoryAll = New-Object System.Collections.Generic.List[object]
$topCostsAll = New-Object System.Collections.Generic.List[object]

foreach ($sub in $subscriptions) {
    Write-Host "Processing subscription: $($sub.Name) [$($sub.Id)]" -ForegroundColor Yellow
    Set-AzContext -SubscriptionId $sub.Id | Out-Null

    $inventory = Get-InventoryCounts -SubscriptionId $sub.Id
    $cost = Get-CostLastNDays -SubscriptionId $sub.Id -Days $CostLookbackDays
    $secureScore = Get-SecureScore -SubscriptionId $sub.Id
    $advisor = Get-AdvisorRecommendations -SubscriptionId $sub.Id -Refresh:$RefreshAdvisorRecommendations
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

    $inventoryAll.Add([pscustomobject]@{
        SubscriptionName = $sub.Name
        SubscriptionId   = $sub.Id
        TotalResources   = $inventory.TotalResources
        VirtualMachines  = $inventory.VirtualMachines
        AppServices      = $inventory.AppServices
        FunctionApps     = $inventory.FunctionApps
        SqlServers       = $inventory.SqlServers
        SqlDatabases     = $inventory.SqlDatabases
        StorageAccounts  = $inventory.StorageAccounts
        KeyVaults        = $inventory.KeyVaults
        PublicIPs        = $inventory.PublicIPs
        LoadBalancers    = $inventory.LoadBalancers
        ApplicationGateways = $inventory.ApplicationGateways
        NSGs             = $inventory.NSGs
        VNets            = $inventory.VNets
        ManagedDisks     = $inventory.ManagedDisks
    }) | Out-Null

    foreach ($tc in $topCosts) {
        $topCostsAll.Add([pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceId       = $tc.ResourceId
            ResourceType     = $tc.ResourceType
            ResourceGroup    = $tc.ResourceGroup
            Cost             = $tc.Cost
            Currency         = $tc.Currency
        }) | Out-Null
    }

    if ($secureScore) {
        if ($secureScore.Percentage -lt 40) {
            Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'High' 'DefenderForCloud' 'Low Secure Score' '' 'Secure Score is below 40%. Prioritize remediation of Defender for Cloud recommendations.' $secureScore
        }
        elseif ($secureScore.Percentage -lt 70) {
            Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'Medium' 'DefenderForCloud' 'Moderate Secure Score' '' 'Secure Score is below 70%. Review and remediate hardening recommendations.' $secureScore
        }
    }

    if ([decimal]$cost.Amount -ge 10000) {
        Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Cost' 'Medium' 'CostManagement' 'High spend detected in lookback period' '' 'Review top cost drivers, rightsize services, and validate reservations or savings plans.' $cost
    }

    foreach ($resource in $untaggedResources) {
        Add-Finding ([ref]$findings) $sub.Name $sub.Id 'OperationalExcellence' 'Low' 'ResourceGraph' 'Resource without tags' $resource.id 'Apply mandatory tags for ownership, environment, cost center, and application context.' $resource
    }

    foreach ($disk in $unattachedDisks) {
        Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Cost' 'Medium' 'ResourceGraph' 'Unattached managed disk' $disk.id 'Validate whether this disk is still required. Unattached disks often generate unnecessary cost.' $disk
    }

    foreach ($nic in $unattachedNics) {
        Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Cost' 'Low' 'ResourceGraph' 'Unattached network interface' $nic.id 'Validate whether this NIC is still required and remove stale network resources.' $nic
    }

    foreach ($pip in $idlePublicIps) {
        Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Cost' 'Low' 'ResourceGraph' 'Idle public IP address' $pip.id 'Remove or justify unattached public IP addresses to reduce exposure and cost.' $pip
    }

    foreach ($rule in $openNsgRules) {
        Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'High' 'ResourceGraph' "NSG rule exposed to Internet ($($rule.ruleName))" $rule.id 'Review inbound NSG rules open to the Internet on administrative or database ports.' $rule
    }

    foreach ($app in $appServices) {
        $peCount = if ($null -ne $app.peCount -and $app.peCount -ne '') { [int]$app.peCount } else { 0 }
        if (($app.publicNetworkAccess -ne 'Disabled') -and ($peCount -eq 0)) {
            Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'Medium' 'ResourceGraph' 'App Service without Private Endpoint' $app.id 'Review whether this App Service should be reachable privately and disable public network access if applicable.' $app
        }
        if ($app.httpsOnly -ne 'true') {
            Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'High' 'ResourceGraph' 'App Service HTTPS Only disabled' $app.id 'Enable HTTPS Only for App Service.' $app
        }
        if ([string]$app.minTlsVersion -and [version]([string]$app.minTlsVersion) -lt [version]'1.2') {
            Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'Medium' 'ResourceGraph' 'App Service TLS minimum version below 1.2' $app.id 'Set minimum TLS version to 1.2 or higher.' $app
        }
    }

    foreach ($st in $storageAccounts) {
        $peCount = if ($null -ne $st.peCount -and $st.peCount -ne '') { [int]$st.peCount } else { 0 }
        if ($st.supportsHttpsTrafficOnly -ne 'true') {
            Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'High' 'ResourceGraph' 'Storage account allows non-HTTPS traffic' $st.id 'Enable secure transfer required on the storage account.' $st
        }
        if ([string]$st.minTlsVersion -and [version]([string]$st.minTlsVersion) -lt [version]'1.2') {
            Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'Medium' 'ResourceGraph' 'Storage account TLS minimum version below 1.2' $st.id 'Set minimum TLS version to 1.2 or higher.' $st
        }
        if ($st.allowBlobPublicAccess -eq 'true') {
            Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'Medium' 'ResourceGraph' 'Storage account allows blob public access' $st.id 'Disable blob public access unless there is a documented business requirement.' $st
        }
        if (($st.publicNetworkAccess -ne 'Disabled') -and ($peCount -eq 0)) {
            Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'Medium' 'ResourceGraph' 'Storage account publicly reachable' $st.id 'Review network rules, private endpoints, and whether public network access should remain enabled.' $st
        }
    }

    foreach ($kv in $keyVaults) {
        $peCount = if ($null -ne $kv.peCount -and $kv.peCount -ne '') { [int]$kv.peCount } else { 0 }
        if ($kv.enablePurgeProtection -ne 'true') {
            Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'High' 'ResourceGraph' 'Key Vault purge protection disabled' $kv.id 'Enable purge protection to reduce the risk of destructive deletion.' $kv
        }
        if (($kv.publicNetworkAccess -ne 'Disabled') -and ($peCount -eq 0)) {
            Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'Medium' 'ResourceGraph' 'Key Vault publicly reachable' $kv.id 'Review private endpoints and network ACLs for Key Vault exposure.' $kv
        }
    }

    foreach ($vm in $unprotectedVms) {
        Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Reliability' 'High' 'ResourceGraph' 'VM without detected backup protection' $vm.vmId 'Validate Azure Backup or another approved backup mechanism. Unprotected VMs create recovery risk.' $vm
    }

    foreach ($plan in $defenderPricings) {
        if ($plan.PricingTier -eq 'Free') {
            Add-Finding ([ref]$findings) $sub.Name $sub.Id 'Security' 'Low' 'DefenderForCloud' "Defender plan '$($plan.Name)' not on Standard tier" '' 'Review which Microsoft Defender for Cloud plans should be enabled for this workload profile.' $plan
        }
    }

    foreach ($rec in $advisor) {
        $category = [string]$rec.properties.category
        $impact = [string]$rec.properties.impact
        $severity = Get-SeverityFromAdvisorImpact -Impact $impact
        $title = [string]$rec.properties.shortDescription.problem
        $recommendation = [string]$rec.properties.shortDescription.solution
        $resourceId = [string]$rec.properties.resourceMetadata.resourceId
        Add-Finding ([ref]$findings) $sub.Name $sub.Id $category $severity 'AzureAdvisor' $title $resourceId $recommendation $rec
    }

    $subFindings = @($findings | Where-Object { $_.SubscriptionId -eq $sub.Id })

    $appServicesWithoutPe = @($appServices | Where-Object {
        $peCount = if ($null -ne $_.peCount -and $_.peCount -ne '') { [int]$_.peCount } else { 0 }
        $_.publicNetworkAccess -ne 'Disabled' -and $peCount -eq 0
    }).Count

    $storagePublicReachable = @($storageAccounts | Where-Object {
        $peCount = if ($null -ne $_.peCount -and $_.peCount -ne '') { [int]$_.peCount } else { 0 }
        $_.publicNetworkAccess -ne 'Disabled' -and $peCount -eq 0
    }).Count

    $keyVaultPublicReachable = @($keyVaults | Where-Object {
        $peCount = if ($null -ne $_.peCount -and $_.peCount -ne '') { [int]$_.peCount } else { 0 }
        $_.publicNetworkAccess -ne 'Disabled' -and $peCount -eq 0
    }).Count

    $summary.Add([pscustomobject]@{
        SubscriptionName              = $sub.Name
        SubscriptionId                = $sub.Id
        State                         = $sub.State
        SecureScorePercent            = if ($secureScore) { $secureScore.Percentage } else { $null }
        SecureScoreCurrent            = if ($secureScore) { $secureScore.CurrentScore } else { $null }
        SecureScoreMax                = if ($secureScore) { $secureScore.MaxScore } else { $null }
        LastNDaysCost                 = $cost.Amount
        Currency                      = $cost.Currency
        TotalResources                = $inventory.TotalResources
        VirtualMachines               = $inventory.VirtualMachines
        AppServices                   = $inventory.AppServices
        StorageAccounts               = $inventory.StorageAccounts
        KeyVaults                     = $inventory.KeyVaults
        PublicIPs                     = $inventory.PublicIPs
        UntaggedResources             = $untaggedResources.Count
        UnattachedDisks               = $unattachedDisks.Count
        UnattachedNICs                = $unattachedNics.Count
        IdlePublicIPs                 = $idlePublicIps.Count
        OpenNSGRules                  = $openNsgRules.Count
        AppServicesWithoutPrivateEP   = $appServicesWithoutPe
        StoragePublicReachable        = $storagePublicReachable
        KeyVaultPublicReachable       = $keyVaultPublicReachable
        VMsWithoutDetectedBackup      = $unprotectedVms.Count
        TotalFindings                 = $subFindings.Count
        HighFindings                  = @($subFindings | Where-Object Severity -eq 'High').Count
        MediumFindings                = @($subFindings | Where-Object Severity -eq 'Medium').Count
        LowFindings                   = @($subFindings | Where-Object Severity -eq 'Low').Count
        InfoFindings                  = @($subFindings | Where-Object Severity -eq 'Info').Count
        SecurityFindings              = @($subFindings | Where-Object Category -match 'Security').Count
        PerformanceFindings           = @($subFindings | Where-Object Category -match 'Performance').Count
        CostFindings                  = @($subFindings | Where-Object Category -match 'Cost').Count
        ReliabilityFindings           = @($subFindings | Where-Object Category -match 'Reliability').Count
        OperationalExcellenceFindings = @($subFindings | Where-Object Category -match 'Operational').Count
    }) | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$summaryCsv = Join-Path $OutputFolder "AzureAssessment-Summary-$timestamp.csv"
$findingsCsv = Join-Path $OutputFolder "AzureAssessment-Findings-$timestamp.csv"
$summaryJson = Join-Path $OutputFolder "AzureAssessment-Summary-$timestamp.json"
$topCostsCsv = Join-Path $OutputFolder "AzureAssessment-TopCosts-$timestamp.csv"
$inventoryCsv = Join-Path $OutputFolder "AzureAssessment-Inventory-$timestamp.csv"
$xlsxPath = Join-Path $OutputFolder "AzureAssessment-Executive-$timestamp.xlsx"

$summary | Sort-Object SubscriptionName | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $summaryCsv
$findings | Select-Object SubscriptionName, SubscriptionId, Category, Severity, Source, Title, ResourceId, Recommendation | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $findingsCsv
$topCostsAll | Sort-Object SubscriptionName, @{ Expression = 'Cost'; Descending = $true } | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $topCostsCsv
$inventoryAll | Sort-Object SubscriptionName | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $inventoryCsv
$summary | ConvertTo-Json -Depth 20 | Out-File -FilePath $summaryJson -Encoding utf8

if (-not $SkipExcel) {
    if (Test-Path $xlsxPath) { Remove-Item $xlsxPath -Force }

    $overview = @()
    foreach ($row in $summary) {
        $overview += [pscustomobject]@{ Metric = 'Subscription'; Value = $row.SubscriptionName }
        $overview += [pscustomobject]@{ Metric = 'Secure Score %'; Value = $row.SecureScorePercent }
        $overview += [pscustomobject]@{ Metric = "Cost (Last $CostLookbackDays Days)"; Value = "$($row.LastNDaysCost) $($row.Currency)" }
        $overview += [pscustomobject]@{ Metric = 'Total Findings'; Value = $row.TotalFindings }
        $overview += [pscustomobject]@{ Metric = 'High Findings'; Value = $row.HighFindings }
        $overview += [pscustomobject]@{ Metric = 'Security Findings'; Value = $row.SecurityFindings }
        $overview += [pscustomobject]@{ Metric = 'Cost Findings'; Value = $row.CostFindings }
        $overview += [pscustomobject]@{ Metric = 'Performance Findings'; Value = $row.PerformanceFindings }
        $overview += [pscustomobject]@{ Metric = 'Reliability Findings'; Value = $row.ReliabilityFindings }
        $overview += [pscustomobject]@{ Metric = 'Operational Excellence Findings'; Value = $row.OperationalExcellenceFindings }
        $overview += [pscustomobject]@{ Metric = '--'; Value = '--' }
    }

    $null = $overview | Export-Excel -Path $xlsxPath -WorksheetName 'Overview' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium2
    $null = $summary | Sort-Object SubscriptionName | Export-Excel -Path $xlsxPath -WorksheetName 'Summary' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium6 -Append
    $null = $inventoryAll | Sort-Object SubscriptionName | Export-Excel -Path $xlsxPath -WorksheetName 'Inventory' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium4 -Append
    $null = $topCostsAll | Sort-Object SubscriptionName, @{ Expression = 'Cost'; Descending = $true } | Export-Excel -Path $xlsxPath -WorksheetName 'TopCostResources' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium5 -Append
    $null = ($findings | Where-Object Category -match 'Security' | Sort-Object Severity, SubscriptionName) | Export-Excel -Path $xlsxPath -WorksheetName 'Security' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium7 -Append
    $null = ($findings | Where-Object Category -match 'Performance' | Sort-Object Severity, SubscriptionName) | Export-Excel -Path $xlsxPath -WorksheetName 'Performance' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium3 -Append
    $null = ($findings | Where-Object Category -match 'Cost' | Sort-Object Severity, SubscriptionName) | Export-Excel -Path $xlsxPath -WorksheetName 'Cost' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium8 -Append
    $null = ($findings | Where-Object Category -match 'Reliability' | Sort-Object Severity, SubscriptionName) | Export-Excel -Path $xlsxPath -WorksheetName 'Reliability' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium9 -Append
    $null = ($findings | Where-Object Category -match 'Operational' | Sort-Object Severity, SubscriptionName) | Export-Excel -Path $xlsxPath -WorksheetName 'OperationalExcellence' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium10 -Append
    $null = $findings | Sort-Object SubscriptionName, Category, Severity | Export-Excel -Path $xlsxPath -WorksheetName 'AllFindings' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium11 -Append
}

Write-Host ''
Write-Host 'Assessment completed.' -ForegroundColor Green
Write-Host "Summary CSV : $summaryCsv"
Write-Host "Findings CSV: $findingsCsv"
Write-Host "Top Costs CSV: $topCostsCsv"
Write-Host "Inventory CSV: $inventoryCsv"
Write-Host "Summary JSON: $summaryJson"
if (-not $SkipExcel) { Write-Host "Excel      : $xlsxPath" }

$summary | Sort-Object HighFindings -Descending | Format-Table SubscriptionName, SecureScorePercent, LastNDaysCost, Currency, TotalFindings, HighFindings, SecurityFindings, CostFindings, PerformanceFindings -AutoSize
