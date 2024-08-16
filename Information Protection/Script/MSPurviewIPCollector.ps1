<#PSScriptInfo

.VERSION 2.0.2

.GUID 883af802-166c-4708-f4d1-352686c02f01

.AUTHOR 
https://www.linkedin.com/in/profesorkaz/; Sebastian Zamorano

.COMPANYNAME 
Microsoft Purview Advanced Rich Reports

.TAGS 
#Microsoft365 #M365 #MPARR #MicrosoftPurview #ActivityExplorer

.PROJECTURI 
https://aka.ms/MPARR-YouTube 

.RELEASENOTES
The MIT License (MIT)
Copyright (c) 2015 Microsoft Corporation
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

#>

<# 

.DESCRIPTION 
This script permit to export Information Protection configuration

#>

<#
HISTORY
	Script      : MSPurviewIPCollector.ps1
	Author      : S. Zamorano
	Version     : 2.0.2
	Description : Export Activity Explorer activities to CSV or Json format.
	17-04-2024		S. Zamorano		- Public release
	12-08-2024		S. Zamorano		- Version 2 Public release
	16-08-2024		S. Zamorano		- Conditions field added to the query
#>

[CmdletBinding(DefaultParameterSetName = "None")]
param(
	[string]$SensitivityLabelTableName = "MSPurviewIPSensitivityLabelsDetailed",
	[string]$PoliciesLabelTableName = "MSPurviewIPPoliciesDetailed",
	[Parameter()] 
        [switch]$Help,
	[Parameter()] 
        [switch]$ExportToCsv,
	[Parameter()] 
        [switch]$ExportToLogsAnalytics,
	[Parameter()] 
        [switch]$OnlyLabels,
	[Parameter()] 
        [switch]$OnlyPolicies
)

function CheckPowerShellVersion
{
    # Check PowerShell version
    Write-Host "`nChecking PowerShell version... " -NoNewline
    if ($Host.Version.Major -gt 5)
    {
        Write-Host "`t`t`t`tPassed!" -ForegroundColor Green
    }
    else
    {
        Write-Host "Failed" -ForegroundColor Red
        Write-Host "`tCurrent version is $($Host.Version). PowerShell version 7 or newer is required."
        exit(1)
    }
}

function CheckIfElevated
{
    $IsElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$IsElevated)
    {
        Write-Host "`nPlease start PowerShell as Administrator.`n" -ForegroundColor Yellow
        exit(1)
    }
}

function CheckRequiredModules 
{
    # Check PowerShell modules
    Write-Host "Checking PowerShell modules..."
    $requiredModules = @(
        @{Name="ExchangeOnlineManagement"; MinVersion="0.0"}
        )

    $modulesToInstall = @()
    foreach ($module in $requiredModules)
    {
        Write-Host "`t$($module.Name) - " -NoNewline
        $installedVersions = Get-Module -ListAvailable $module.Name
        if ($installedVersions)
        {
            if ($installedVersions[0].Version -lt [version]$module.MinVersion)
            {
                Write-Host "`t`t`tNew version required" -ForegroundColor Red
                $modulesToInstall += $module.Name
            }
            else 
            {
                Write-Host "`t`t`tInstalled" -ForegroundColor Green
            }
        }
        else
        {
            Write-Host "`t`t`tNot installed" -ForegroundColor Red
            $modulesToInstall += $module.Name
        }
    }

    if ($modulesToInstall.Count -gt 0)
    {
        CheckIfElevated
		$choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice("", "Misisng required modules. Proceed with installation?", $choices, 0)
        if ($decision -eq 0) 
        {
            Write-Host "Installing modules..."
            foreach ($module in $modulesToInstall)
            {
                Write-Host "`t$module"
				Install-Module $module -ErrorAction Stop
                
            }
            Write-Host "`nModules installed. Please start the script again."
            exit(0)
        } 
        else 
        {
            Write-Host "`nExiting setup. Please install required modules and re-run the setup."
            exit(1)
        }
    }
}

function CheckPrerequisites
{
    CheckPowerShellVersion
	CheckRequiredModules
}

function connect2service
{
	Write-Host "`nAuthentication is required, please check your browser" -ForegroundColor DarkYellow
	Connect-IPPSSession -UseRPSSession:$false -ShowBanner:$false
}

function DecryptSharedKey 
{
    param(
        [string] $encryptedKey
    )

    try {
        $secureKey = $encryptedKey | ConvertTo-SecureString -ErrorAction Stop  
    }
    catch {
        Write-Error "Workspace key: $($_.Exception.Message)"
        exit(1)
    }
    $BSTR =  [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    $plainKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $plainKey
}

function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) 
{
    # ---------------------------------------------------------------   
    #    Name           : Build-Signature
    #    Value          : Creates the authorization signature used in the REST API call to Log Analytics
    # ---------------------------------------------------------------

	#Original function to Logs Analytics
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

function WriteToLogsAnalytics($body, $LogAnalyticsTableName) 
{
    # ---------------------------------------------------------------   
    #    Name           : Post-LogAnalyticsData
    #    Value          : Writes the data to Log Analytics using a REST API
    #    Input          : 1) PSObject with the data
    #                     2) Table name in Log Analytics
    #    Return         : None
    # ---------------------------------------------------------------
    
	#Read configuration file
	$CONFIGFILE = "$PSScriptRoot\ConfigFiles\MSPurviewIPConfiguration.json"
	$json = Get-Content -Raw -Path $CONFIGFILE
	[PSCustomObject]$config = ConvertFrom-Json -InputObject $json
	
	$EncryptedKeys = $config.EncryptedKeys
	$WLA_CustomerID = $config.Workspace_ID
	$WLA_SharedKey = $config.WorkspacePrimaryKey
	if ($EncryptedKeys -eq "True")
	{
		$WLA_SharedKey = DecryptSharedKey $WLA_SharedKey
	}

	# Your Log Analytics workspace ID
	$LogAnalyticsWorkspaceId = $WLA_CustomerID

	# Use either the primary or the secondary Connected Sources client authentication key   
	$LogAnalyticsPrimaryKey = $WLA_SharedKey
	
	#Step 0: sanity checks
    if($body -isnot [array]) {return}
    if($body.Count -eq 0) {return}
	
	#Step 1: convert the body.ResultData to JSON
	$json_array = @()
	$parse_array = @()
	$parse_array = $body #| ConvertFrom-Json
	foreach($item in $parse_array) 
	{
		$json_array += $item
	}
	$json = $json_array | ConvertTo-Json -Depth 6
	
	#Step 2: convert the PSObject to JSON
	$bodyJson = $json
	#Step 2.5: sanity checks
	if($bodyJson.Count -eq 0) {return}

    #Step 3: get the UTF8 bytestream for the JSON
    $bodyJsonUTF8 = ([System.Text.Encoding]::UTF8.GetBytes($bodyJson))
	
	#Step 4: build the signature        
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $bodyJsonUTF8.Length    
    $signature = Build-Signature -customerId $LogAnalyticsWorkspaceId -sharedKey $LogAnalyticsPrimaryKey -date $rfc1123date -contentLength $contentLength -method $method -contentType $contentType -resource $resource
    
    #Step 5: create the header
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $LogAnalyticsTableName;
        "x-ms-date" = $rfc1123date;
    };

    #Step 6: REST API call
    $uri = 'https://' + $LogAnalyticsWorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    $response = Invoke-WebRequest -Uri $uri -Method Post -Headers $headers -ContentType $contentType -Body $bodyJsonUTF8 -UseBasicParsing

    if ($Response.StatusCode -eq 200) {   
        $rows = $json_array.Count
        Write-Information -MessageData "$rows rows written to Log Analytics workspace $uri" -InformationAction Continue
    }
}

function WriteToJson($results, $ExportFolder, $QueryType, $date)
{
	$json_array = @() 
	$parse_array = @()
	$parse_array = $results 
	foreach($item in $parse_array) 
	{
		$json_array += $item
	}
	$json = $json_array | ConvertTo-Json -Depth 6
	$FileName = "ActivityExplorer export - "+"$QueryType"+" - "+"$date"+".Json"
	$pathJson = $PSScriptRoot+"\"+$ExportFolder+"\"+$FileName
	$path = $pathJson
	$json | Add-Content -Path $path
	Write-Host "`nData exported to... :" -NoNewLine
	Write-Host $pathJson -ForeGroundColor Cyan
	Write-Host "`n----------------------------------------------------------------------------------------`n`n" -ForeGroundColor DarkBlue
}

function WriteToCsv($results, $ExportFolder, $QueryType, $date)
{
	$parse_array = @()
	$nextpages_array = @()
	$TotalResults = @()
	$TotalResults = $results
	foreach($item in $TotalResults)
	{
		$FileName = "ActivityExplorer export - "+"$QueryType"+" - "+"$date"+".Csv"
		$pathCsv = $PSScriptRoot+"\"+$ExportFolder+"\"+$FileName
		$path = $pathCsv
		$parse_array = $item
		$values = $parse_array[0].psobject.properties.name
		$parse_array | Export-Csv -Path $path -NTI -Force -Append | Out-Null
	}
	Write-Host "Total results $($results.count)"
	Write-Host "`nData exported to..." -NoNewline
	Write-Host "`n$pathCsv" -ForeGroundColor Cyan
	Write-Host "`n----------------------------------------------------------------------------------------`n`n" -ForeGroundColor DarkBlue
}

function MSPuviewIPCollectorHelp
{
	cls
	Write-Host "`n"
	Write-Host "################################################################################" -ForegroundColor Green
	Write-Host "`n How to use this script `n" -ForegroundColor Green
	Write-Host "################################################################################" -ForegroundColor Green
	Write-Host "`nDescription: " -ForegroundColor Blue -NoNewLine
	Write-Host "This menu"
	Write-Host ".\MSPurviewIPCollector.ps1 -Help" -ForeGroundColor DarkYellow
	Write-Host "`n`nDescription: " -ForegroundColor Blue -NoNewLine
	Write-Host "Using only the script by default, you'll be able to get your Sensitivity Labels and Policies in Json format."
	Write-Host ".\MSPurviewIPCollector.ps1" -ForeGroundColor DarkYellow
	Write-Host "`n`nDescription: " -ForegroundColor Blue -NoNewLine
	Write-Host "Using the attribute '-OnlyLabels' you will be able only to export Sensitivity Labels information"
	Write-Host ".\MSPurviewIPCollector.ps1 -OnlyLabels" -ForeGroundColor DarkYellow
	Write-Host "`n`nDescription: " -ForegroundColor Blue -NoNewLine
	Write-Host "Using the attribute '-OnlyPolicies' you will be able only to export Sensitivity Labels Policies information"
	Write-Host ".\MSPurviewIPCollector.ps1 -OnlyPolicies" -ForeGroundColor DarkYellow
	Write-Host "`n`nDescription: " -ForegroundColor Blue -NoNewLine
	Write-Host "Using the attribute '-ExportToLogsAnalytics' you will be able only to export all the data to a Logs Analytics workspace"
	Write-Host ".\MSPurviewIPCollector.ps1 -ExportToLogsAnalytics" -ForeGroundColor DarkYellow
	Write-Host "`n`nDescription: " -ForegroundColor Blue -NoNewLine
	Write-Host "If you are not comfortable working with JSON format, you can use the attribute '-ExportToCsv' to export the data in CSV format."
	Write-Host ".\MSPurviewIPCollector.ps1 -ExportToCsv" -ForeGroundColor DarkYellow
	Write-Host "`n`nDescription: " -ForegroundColor Blue -NoNewLine
	Write-Host "You can combine different attributes available in the script to customize its functionality. For example:"
	Write-Host ".\MSPurviewIPCollector.ps1 -OnlyLabels -ExportToLogsAnalytics" -ForeGroundColor DarkYellow
	Write-Host "`n"
	Write-Host "### You can now proceed using any of the options listed in the Help menu. ###" -ForegroundColor Green
	Write-Host "`n"
	return
}

function GetInformationProtectionData($ExportFormat, $ExportFolder, $ExportOption)
{
	Write-Host "`nExecuting Get cmdlet for your selection..." -ForeGroundColor Blue
	
	$date = (Get-Date).ToString("yyyy-MM-dd HHmm")
	$ExportExtension = $ExportFormat
	if($ExportFormat -eq "LA")
	{
		$ExportExtension="Json"
	}
	if($ExportOption -eq "All")
	{
		#Request Sensitivity Labels
		$results = New-Object PSObject
		$TotalResults = @()
		$Query = "SensitivityLabels"
		$results = Get-Label | select DisplayName,Name,Guid,ParentLabelDisplayName,ParentId,IsParent,IsLabelGroup,Tooltip,DefaultContentLabel,ContentType,LocaleSettings,SchematizedDataCondition,ColumnAssetCondition,LabelActions,Settings,Priority,Workload,Policy,CreatedBy,LastModifiedBy,WhenChangedUTC,WhenCreatedUTC,Comment
		$TotalResults += $results
		if($results.TotalResultCount -eq "0")
			{
				Write-Host "The previous combination does not return any values."
				Write-Host "Exiting...`n"
			}else
			{
				Write-Host "`nCollecting data..." -ForegroundColor DarkBlue -NoNewLine
				Write-Host $TotalResults.Count -ForegroundColor Blue -NoNewLine
				Write-Host " records returned"
				#Run the below steps in loop until all results are fetched

				if($ExportFormat -eq "Csv")
				{
					$CSVresults = $TotalResults
					WriteToCsv -results $CSVresults -ExportFolder $ExportFolder -QueryType $Query -date $date
				}elseif($ExportFormat -eq "LA")
				{
					#WriteToLogsAnalytics -LogAnalyticsTableName $TableName -body $TotalResults
				}else
				{
					WriteToJson -results $TotalResults -ExportFolder $ExportFolder -QueryType $Query -date $date
				}
			}
		#Request Labels policies
		$results = New-Object PSObject
		$TotalResults = @()
		$Query = "LabelsPolicies"
		$results = Get-LabelPolicy | select Name,Guid,WhenChangedUTC,WhenCreatedUTC,Enabled,Mode,DistributionStatus,Type,Settings,Labels,ScopedLabels,PolicySettingsBlob,Workload,CreatedBy,LastModifiedBy
		$TotalResults += $results
		if($results.TotalResultCount -eq "0")
			{
				Write-Host "The previous combination does not return any values."
				Write-Host "Exiting...`n"
			}else
			{
				Write-Host "`nCollecting data..." -ForegroundColor DarkBlue -NoNewLine
				Write-Host $TotalResults.Count -ForegroundColor Blue -NoNewLine
				Write-Host " records returned"
				#Run the below steps in loop until all results are fetched

				if($ExportFormat -eq "Csv")
				{
					$CSVresults = $TotalResults
					WriteToCsv -results $CSVresults -ExportFolder $ExportFolder -QueryType $Query -date $date
				}elseif($ExportFormat -eq "LA")
				{
					#WriteToLogsAnalytics -LogAnalyticsTableName $TableName -body $TotalResults
				}else
				{
					WriteToJson -results $TotalResults -ExportFolder $ExportFolder -QueryType $Query -date $date
				}
			}
	}elseif($ExportOption -eq "OnlyLabels")
	{
		$results = New-Object PSObject
		$TotalResults = @()
		$Query = "SensitivityLabels"
		$results = Get-Label | select DisplayName,Name,Guid,ParentLabelDisplayName,ParentId,IsParent,IsLabelGroup,Tooltip,DefaultContentLabel,ContentType,LocaleSettings,SchematizedDataCondition,ColumnAssetCondition,LabelActions,Settings,Priority,Workload,Policy,CreatedBy,LastModifiedBy,WhenChangedUTC,WhenCreatedUTC,Comment,Conditions
		$TotalResults += $results
		if($results.TotalResultCount -eq "0")
			{
				Write-Host "The previous combination does not return any values."
				Write-Host "Exiting...`n"
			}else
			{
				Write-Host "`nCollecting data..." -ForegroundColor DarkBlue -NoNewLine
				Write-Host $TotalResults.count -ForegroundColor Blue -NoNewLine
				Write-Host " records returned"
				#Run the below steps in loop until all results are fetched

				if($ExportFormat -eq "Csv")
				{
					$CSVresults = $TotalResults
					WriteToCsv -results $CSVresults -ExportFolder $ExportFolder -QueryType $Query -date $date
				}elseif($ExportFormat -eq "LA")
				{
					#WriteToLogsAnalytics -LogAnalyticsTableName $SensitivityLabelTableName -body $TotalResults
				}else
				{
					WriteToJson -results $TotalResults -ExportFolder $ExportFolder -QueryType $Query -date $date
				}
			}
	}elseif($ExportOption -eq "OnlyPolicies")
	{
		$results = New-Object PSObject
		$TotalResults = @()
		$Query = "LabelsPolicies"
		$results = Get-LabelPolicy | select Name,Guid,WhenChangedUTC,WhenCreatedUTC,Enabled,Mode,DistributionStatus,Type,Settings,Labels,ScopedLabels,PolicySettingsBlob,Workload,CreatedBy,LastModifiedBy
		$TotalResults += $results
		if($results.TotalResultCount -eq "0")
			{
				Write-Host "The previous combination does not return any values."
				Write-Host "Exiting...`n"
			}else
			{
				Write-Host "`nCollecting data..." -ForegroundColor DarkBlue -NoNewLine
				Write-Host $results.TotalResultCount -ForegroundColor Blue -NoNewLine
				Write-Host " records returned"
				#Run the below steps in loop until all results are fetched

				if($ExportFormat -eq "Csv")
				{
					$CSVresults = $TotalResults
					WriteToCsv -results $CSVresults -ExportFolder $ExportFolder -QueryType $Query -date $date
				}elseif($ExportFormat -eq "LA")
				{
					#WriteToLogsAnalytics -LogAnalyticsTableName $PoliciesLabelTableName -body $TotalResults
				}else
				{
					WriteToJson -results $TotalResults -ExportFolder $ExportFolder -QueryType $Query -date $date
				}
			}
	}
}

function MainFunction
{
	#Welcome header
	cls
	Clear-Host
	
	Write-Host "`n`n----------------------------------------------------------------------------------------"
	Write-Host "`nWelcome to Information Protection Export script!" -ForegroundColor Green
	Write-Host "This script will permit to collect data from Sensitivity Labels and Policies related"
	Write-Host "`n----------------------------------------------------------------------------------------" 
	
	
	#Initiate variables
	
	$ExportOption = "All"
		
	##List only Labels
	if($OnlyLabels)
	{
		$ExportOption = "OnlyLabels"
	}
	if($OnlyPolicies)
	{
		$ExportOption = "OnlyPolicies"
	}
	
	##Export format
	$ExportFormat = "Json"
	if($ExportToCsv)
	{
		$ExportFormat = "Csv"
	}
	if($ExportToLogsAnalytics)
	{
		$ExportFormat = "LA"
		$LogsAnalyticsConfigurationFile = "$PSScriptRoot\ConfigFiles\MSPurviewIPConfiguration.json"
		if(-not (Test-Path -Path $LogsAnalyticsConfigurationFile))
		{
			Write-Host "`nConfiguration file is not present" -ForegroundColor DarkYellow
			Write-Host "Please download the configuration file from http://activityexplorer.kaznets.com and save inside of the ConfigFiles folder.`n"
			Write-Host "Press any key to continue..."
			$key = ([System.Console]::ReadKey($true))
			exit
		}	
	}
	
	##Export folder Name
	$ExportFolderName = "ExportedData"
	$ExportPath = "$PSScriptRoot\$ExportFolderName"
	if(-Not (Test-Path $ExportPath))
	{
		New-Item -ItemType Directory -Force -Path "$PSScriptRoot\$ExportFolderName" | Out-Null
		$StatusFolder = "Created"
	}else
	{
		$StatusFolder = "Available"
	}
	
	##Show variables set
	Write-Host "Export format set to`t`t`t:" -NoNewline
	Write-Host "`t$ExportFormat" -ForegroundColor Green
	Write-Host "Export folder set to`t`t`t:" -NoNewline
	Write-Host "`t$ExportFolderName ($StatusFolder)" -ForegroundColor Green
	Write-Host "Export Option selected`t`t`t:" -NoNewline
	Write-Host "`t$ExportOption" -ForegroundColor Green
	if($ExportToLogsAnalytics)
	{
		if($OnlyLabels)
		{
			Write-Host "Table name for Sensitivity Labels`t:" -NoNewline
			Write-Host "`t$SensitivityLabelTableName" -ForegroundColor Green
		}elseif($OnlyPolicies)
		{
			Write-Host "Table name for Policies Labels`t`t:" -NoNewline
			Write-Host "`t$PoliciesLabelTableName" -ForegroundColor Green
		}else
		{
			Write-Host "Table name for Sensitivity Labels`t:" -NoNewline
			Write-Host "`t$SensitivityLabelTableName" -ForegroundColor Green
			Write-Host "Table name for Policies Labels`t`t:" -NoNewline
			Write-Host "`t$PoliciesLabelTableName" -ForegroundColor Green
		}
	}
	Write-Host "`n`nYou will be prompted for your credentials, remember that you need Compliance Administrator role"
	Write-Host "Press any key to continue..."
    $key = ([System.Console]::ReadKey($true))
	#connect2service
	
	Write-Host "Calling script..."
	
	#Call function to export data from Activity Explorer
	GetInformationProtectionData -ExportFormat $ExportFormat -ExportFolder $ExportFolderName -ExportOption $ExportOption
}

if($Help)
{
	MSPuviewIPCollectorHelp
	exit
}

CheckPrerequisites
MainFunction