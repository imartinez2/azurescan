Files included:
- bootstrap-azure-assessment.ps1
- Azure-Subscription-Assessment-Advanced-CloudShell.ps1

Recommended hosting:
1. Publish both files to GitHub Raw, Azure Blob with SAS, or any HTTPS public URL.
2. Edit bootstrap-azure-assessment.ps1 and replace:
   https://REPLACE-WITH-YOUR-PUBLIC-URL/Azure-Subscription-Assessment-Advanced.ps1
   with the real public URL of Azure-Subscription-Assessment-Advanced-CloudShell.ps1.
3. Rename Azure-Subscription-Assessment-Advanced-CloudShell.ps1 to Azure-Subscription-Assessment-Advanced.ps1 if you want the default bootstrap URL string to match exactly.

Single-line execution from Azure Cloud Shell:
iex "& { $(irm 'https://YOUR-PUBLIC-URL/bootstrap-azure-assessment.ps1') } -SubscriptionId 'SUBSCRIPTION-GUID' -OutputFolder '$HOME/clouddrive/assessment' -RefreshAdvisorRecommendations"

Without Excel:
iex "& { $(irm 'https://YOUR-PUBLIC-URL/bootstrap-azure-assessment.ps1') } -SubscriptionId 'SUBSCRIPTION-GUID' -SkipExcel"
