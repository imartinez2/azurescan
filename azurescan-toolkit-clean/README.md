# AzureScan Toolkit

Toolkit para ejecutar un assessment automatizado de una Azure subscription desde Azure Cloud Shell.

## Estructura

```text
azurescan/
  bootstrap-azure-assessment.ps1
  README.md
  scripts/
    Azure-Subscription-Assessment-Advanced-CloudShell.ps1
    Start-AzureScan.ps1
```

## Comando recomendado desde Azure Cloud Shell

```powershell
iex "& { $(irm 'https://raw.githubusercontent.com/imartinez2/azurescan/main/bootstrap-azure-assessment.ps1') } -SubscriptionId '36b48b9c-3f04-4d71-a75d-38cf1248b447' -OutputFolder (Join-Path $HOME 'clouddrive/azurescan') -RefreshAdvisorRecommendations"
```

## Comando usando la subscription actual del contexto

```powershell
iex "& { $(irm 'https://raw.githubusercontent.com/imartinez2/azurescan/main/bootstrap-azure-assessment.ps1') } -OutputFolder (Join-Path $HOME 'clouddrive/azurescan')"
```

## Atajo local dentro del repo

```powershell
pwsh ./scripts/Start-AzureScan.ps1 -SubscriptionId '36b48b9c-3f04-4d71-a75d-38cf1248b447' -RefreshAdvisorRecommendations
```

## Qué genera

- CSV de summary
- CSV de findings
- JSON de summary
- Excel ejecutivo con tabs por categoría

## Hallazgos incluidos

- Secure Score
- Azure Advisor
- recursos sin tags
- NSG abiertos a Internet
- App Services sin Private Endpoint, sin HTTPS only o TLS débil
- Storage Accounts expuestos, con blob public access o TLS débil
- Key Vaults expuestos o sin purge protection
- discos, NICs y Public IPs huérfanos
- VMs sin backup detectado
- top recursos con mayor costo
- planes de Defender en tier Free
