# AzureScan Toolkit

AzureScan is a Cloud Shell friendly Azure subscription assessment toolkit for:

- Security posture
- Cost and FinOps findings
- Performance and Advisor findings
- Governance and Landing Zone maturity
- Network topology summary
- Executive reporting

## Repository structure

```text
azurescan/
  bootstrap-azure-assessment.ps1
  README.md
  scripts/
    Azure-Subscription-Assessment-Advanced-CloudShell.ps1
    Start-AzureScan.ps1
```

## One-line execution from Azure Cloud Shell

```powershell
iex "& { $(irm 'https://raw.githubusercontent.com/imartinez2/azurescan/main/bootstrap-azure-assessment.ps1') } -OutputFolder (Join-Path $HOME 'clouddrive/azurescan')"
```

With a specific subscription:

```powershell
iex "& { $(irm 'https://raw.githubusercontent.com/imartinez2/azurescan/main/bootstrap-azure-assessment.ps1') } -SubscriptionId '00000000-0000-0000-0000-000000000000' -OutputFolder (Join-Path $HOME 'clouddrive/azurescan') -RefreshAdvisorRecommendations"
```

## Outputs

The toolkit generates these outputs in the target folder:

- `AzureAssessment-Summary.csv`
- `AzureAssessment-Findings.csv`
- `AzureAssessment-Inventory.csv`
- `AzureAssessment-TopCostResources.csv`
- `AzureAssessment-PolicySummary.csv`
- `AzureAssessment-NetworkTopology.csv`
- `AzureAssessment-Summary.json`
- `AzureAssessment-Report.html`
- `AzureAssessment-Executive-Deck-Outline.md`
- `AzureAssessment-Summary.xlsx` if ImportExcel is available

## What the assessment checks

### Security
- Defender for Cloud Secure Score
- Defender plans in Free tier
- Azure Advisor security recommendations
- NSG rules exposing management or database ports to the internet
- App Services without HTTPS Only, weak TLS, or no Private Endpoint pattern
- Storage Accounts with public access, weak TLS, or blob public access enabled
- Key Vaults with public access or without purge protection
- VMs without backup coverage detected via Recovery Services data

### Cost and FinOps
- Last N days subscription spend from Cost Management
- Top cost drivers by resource
- Unattached managed disks
- Unattached NICs
- Unassociated Public IPs
- Azure Advisor cost findings

### Governance and Landing Zone
- Resources without tags
- Policy assignment count
- Estimated Landing Zone maturity score and tier

### Network topology
- Summary counts for VNets, Private Endpoints, Firewalls, Application Gateways, Load Balancers, and related network resources

## Notes

- The bootstrap script installs required modules automatically.
- If `ImportExcel` cannot be installed, the toolkit still completes and generates CSV, JSON, HTML, and Markdown outputs.
- This toolkit is designed for read-only assessment workflows.
