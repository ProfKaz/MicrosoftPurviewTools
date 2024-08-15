## About Microsoft Purview Information Protection Export script tool

This tool allows you to easily export Sensitivity Labels and Policies from your Microsoft 365 Tenant, saving the results in JSON or CSV format, or exporting them to Log Analytics.
Are you sure all your labels are properly configured? Do you know if they’re all published and protected? This tool can help you answer these questions and more.

### To use the script

💠**Description:** To have a list of all available options you can execute.
```
.\MSPurviewIPCollector.ps1 -Help
```
<br>
<br>

💠**Description:** Using only the script by default, you'll be able to get your Sensitivity Labels and Policies in Json format.
```
.\MSPurviewIPCollector.ps1
``` 
<br>
<br>

💠**Description:** Using the attribute `-OnlyLabels` you will be able only to export Sensitivity Labels information.
```
.\MSPurviewIPCollector.ps1 -OnlyLabels
```
<br>  
<br>

💠**Description:** Using the attribute `-OnlyPolicies` you will be able only to export Sensitivity Labels Policies information.
```
.\MSPurviewIPCollector.ps1 -OnlyPolicies
```
<br>  
<br>

💠**Description:** Using the attribute `-ExportToLogsAnalytics` you will be able only to export all the data to a Logs Analytics workspace.
```
.\MSPurviewIPCollector.ps1 -ExportToLogsAnalytics
```
<br>  
<br>

💠**Description:** If you are not comfortable working with JSON format, you can use the attribute `-ExportToCsv` to export the data in CSV format.
```
.\MSPurviewIPCollector.ps1 -ExportToCsv
```
<br>  
<br>

💠**Description:** You can combine different attributes available in the script to customize its functionality. For example:
```
.\MSPurviewIPCollector.ps1 -OnlyLabels -ExportToLogsAnalytics
```
<br>  
<br>

### A little more than 2 cents ;)

I'm adding a Power BI Template to display part of the data collected in Logs Analytics.
![MSPurview Export script](https://github.com/user-attachments/assets/0fbb3d0f-92f3-4c70-a8d6-abfe7979f5b5)
