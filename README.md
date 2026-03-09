# AzureScan Toolkit

AzureScan is a lightweight Azure subscription assessment toolkit built for Cloud Shell and GitHub Raw delivery.

## What it checks

- Azure Advisor recommendations
- Microsoft Defender for Cloud Secure Score
- Defender plans in Free tier
- Top cost resources from Cost Management
- Resources without tags
- NSGs open to the Internet on common management or database ports
- App Services without Private Endpoint, HTTPS Only, or strong TLS
- Storage Accounts with public exposure or weak TLS
- Key Vaults with public exposure or missing purge protection
- Unattached managed disks
- Unattached NICs
- Idle Public IPs
- VMs without backup detected

## Repo layout

```text
bootstrap-azure-assessment.ps1
README.md
scripts/
  Azure-Subscription-Assessment-Advanced-CloudShell.ps1
  Start-AzureScan.ps1
```

## Publish to GitHub

1. Create or use the repo `https://github.com/imartinez2/azurescan`
2. Upload the files preserving the folder structure above.
3. Commit to the `main` branch.

## One-line execution from Azure Cloud Shell

Using the current Azure context subscription:

```powershell
iex "& { $(irm 'https://raw.githubusercontent.com/imartinez2/azurescan/main/bootstrap-azure-assessment.ps1') } -OutputFolder '$HOME/clouddrive/azurescan'"
```

Using an explicit subscription id:

```powershell
iex "& { $(irm 'https://raw.githubusercontent.com/imartinez2/azurescan/main/bootstrap-azure-assessment.ps1') } -SubscriptionId '00000000-0000-0000-0000-000000000000' -OutputFolder '$HOME/clouddrive/azurescan' -RefreshAdvisorRecommendations"
```

## Output artifacts

The toolkit writes results to the folder you pass in `-OutputFolder`.

Typical output:

- `AzureAssessment-Summary.csv`
- `AzureAssessment-Findings.csv`
- `AzureAssessment-Inventory.csv`
- `AzureAssessment-TopCostResources.csv`
- `AzureAssessment-Summary.json`
- `AzureAssessment-Workbook.xlsx` when `ImportExcel` is available and `-SkipExcel` is not used

## Recommended Cloud Shell path

Use a persistent folder so the artifacts survive the session:

```powershell
$HOME/clouddrive/azurescan
```

## Notes

- If your default branch is not `main`, update the raw GitHub URLs in `bootstrap-azure-assessment.ps1` and `scripts/Start-AzureScan.ps1`.
- The bootstrap script installs missing PowerShell modules into the current user scope when needed.
- For locked-down environments, you can use `-SkipExcel` and rely on CSV and JSON output only.
