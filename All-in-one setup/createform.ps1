# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users","HID_administrators") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Azure Active Directory","Group Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> AADtenantID
$tmpName = @'
AADtenantID
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> AADAppId
$tmpName = @'
AADAppId
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"
# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}
# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}
# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  
 
function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )
    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid
            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}
function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task
            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = [Object[]]($Variables | ConvertFrom-Json);
            }
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid
            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }
    $returnObject.Value = $taskGuid
}
function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = [Object[]]($DatasourceModel | ConvertFrom-Json);
                automationTaskGUID = $AutomationTaskGuid;
                value              = [Object[]]($DatasourceStaticValue | ConvertFrom-Json);
                script             = $DatasourcePsScript;
                input              = [Object[]]($DatasourceInput | ConvertFrom-Json);
            }
            $body = ConvertTo-Json -InputObject $body
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }
    $returnObject.Value = $datasourceGuid
}
function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = [Object[]]($FormSchema | ConvertFrom-Json)
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }
    $returnObject.Value = $formGuid
}
function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][String][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                accessGroups    = [Object[]]($AccessGroups | ConvertFrom-Json);
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true
            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }
    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "Azure-AD-Group-Create-generate-table-Users" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }
 
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    Write-Information -Message "Searching for AzureAD users.."

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users" + '?$select=Id,UserPrincipalName,displayName'  + '&$top=999'
 
    $azureADUsersResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    $azureADUsers = $azureADUsersResponse.value
    while (![string]::IsNullOrEmpty($azureADUsersResponse.'@odata.nextLink')) {
        $azureADUsersResponse = Invoke-RestMethod -Uri $azureADUsersResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
        $azureADUsers += $azureADUsersResponse.value
    }

    $users = $azureADUsers | Sort-Object -Property DisplayName
    $resultCount = @($users).Count
    Write-Information -Message "Result count: $resultCount"

    if($resultCount -gt 0){
        foreach($user in $users){
            $returnObject = @{
                Id=$user.Id;
                UserPrincipalName=$user.UserPrincipalName;
                displayName=$user.displayName;
            }
            Write-Output $returnObject
        }
    }
} catch {
    if($_.ErrorDetails.Message) { $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message } 
    Write-Error ("Error searching for AzureAD users. Error: $_" + $errorDetailsMessage)
}
'@ 
$tmpModel = @'
[{"key":"UserPrincipalName","type":0},{"key":"displayName","type":0},{"key":"Id","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
Azure-AD-Group-Create-generate-table-Users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Azure-AD-Group-Create-generate-table-Users" #>

<# Begin: DataSource "Azure-AD-Group-Create-generate-table-Users" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }
 
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    Write-Information -Message "Searching for AzureAD users.."

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/users" + '?$select=Id,UserPrincipalName,displayName'  + '&$top=999'
 
    $azureADUsersResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    $azureADUsers = $azureADUsersResponse.value
    while (![string]::IsNullOrEmpty($azureADUsersResponse.'@odata.nextLink')) {
        $azureADUsersResponse = Invoke-RestMethod -Uri $azureADUsersResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
        $azureADUsers += $azureADUsersResponse.value
    }

    $users = $azureADUsers | Sort-Object -Property DisplayName
    $resultCount = @($users).Count
    Write-Information -Message "Result count: $resultCount"

    if($resultCount -gt 0){
        foreach($user in $users){
            $returnObject = @{
                Id=$user.Id;
                UserPrincipalName=$user.UserPrincipalName;
                displayName=$user.displayName;
            }
            Write-Output $returnObject
        }
    }
} catch {
    if($_.ErrorDetails.Message) { $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message } 
    Write-Error ("Error searching for AzureAD users. Error: $_" + $errorDetailsMessage)
}
'@ 
$tmpModel = @'
[{"key":"UserPrincipalName","type":0},{"key":"displayName","type":0},{"key":"Id","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
Azure-AD-Group-Create-generate-table-Users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "Azure-AD-Group-Create-generate-table-Users" #>

<# Begin: DataSource "Azure-AD-Group-Create-check-names " #>
$tmpPsScript = @'
# AzureAD Application Parameters #
$Mailsuffix = "enyoi.local"
$Name = "M365-" + $datasource.Name
$Description = "Microsoft 365 group for $($datasource.Name)"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#region Supporting Functions
function Get-ADSanitizeGroupName
{
    param(
        [parameter(Mandatory = $true)][String]$Name
    )
    $newName = $name.trim();
    $newName = $newName -replace ' - ','_'
    $newName = $newName -replace '[`,~,!,#,$,%,^,&,*,(,),+,=,<,>,?,/,'',",;,:,\,|,},{,.]',''
    $newName = $newName -replace '\[','';
    $newName = $newName -replace ']','';
    $newName = $newName -replace ' ','_';
    $newName = $newName -replace '\.\.\.\.\.','.';
    $newName = $newName -replace '\.\.\.\.','.';
    $newName = $newName -replace '\.\.\.','.';
    $newName = $newName -replace '\.\.','.';
    return $newName;
}
#endregion Supporting Functions

try {
    $iterationMax = 10
    $iterationStart = 1;

    for($i = $iterationStart; $i -lt $iterationMax; $i++) {
        $tempName = Get-ADSanitizeGroupName -Name $Name
        
        if($i -eq $iterationStart) {
            $tempName = $tempName
        } else {
            $tempName = $tempName + "$i"
        }

        #Shorten Name to max. 20 characters
        #$Name = $Name.substring(0, [System.Math]::Min(20, $Name.Length)) 
        
        $DisplayName    = $tempName
        #Shorten DisplayName to max. 20 characters
        #$DisplayName = $DisplayName.substring(0, [System.Math]::Min(20, $DisplayName.Length)) 
        $Description    = $Description
        $Mail           = $tempName.Replace(" ","") + "@" + $Mailsuffix 
        $MailNickname   = $tempName.Replace(" ","")

        Write-Information "Generating Microsoft Graph API Access Token.."

        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$AADTenantID/oauth2/token"

        $body = @{
            grant_type      = "client_credentials"
            client_id       = "$AADAppId"
            client_secret   = "$AADAppSecret"
            resource        = "https://graph.microsoft.com"
        }
    
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token;

        Write-Information "Searching for AzureAD group.."

        #Add the authorization header to the request
        $authorization = @{
            Authorization       = "Bearer $accesstoken";
            'Content-Type'      = "application/json";
            Accept              = "application/json";
            ConsistencyLevel    = "eventual";
        }

        Write-Verbose -Verbose "Searching for Group displayName=$DisplayName or mail=$Mail or mailNickname=$MailNickname"
        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + 'v1.0/groups?$filter=displayName+eq+' + "'$DisplayName'" + ' OR mail+eq+' + "'$Mail'" + ' OR mailNickname+eq+' + "'$MailNickname'" + '&$count=true'

        $azureADGroupResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
        $azureADGroup = $azureADGroupResponse.value

        if(@($azureADGroup).count -eq 0) {
            Write-Information "Group displayName=$DisplayName or mail=$Mail or mailNickname=$MailNickname not found"

            $returnObject = @{
                displayName=$DisplayName; 
                description=$Description; 
                mail=$Mail; 
                mailNickname=$MailNickname
            }
            
            Write-Output $returnObject
            break;
        } else {
            Write-Warning "Group displayName=$DisplayName or mail=$PrimarySmtpAddress or mailNickname=$MailNickname found"
        }
    }
} catch {
    if($_.ErrorDetails.Message) { $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message } 
    Write-Verbose -Verbose ("Error generating names. Error: $_" + $errorDetailsMessage)
}
'@ 
$tmpModel = @'
[{"key":"mail","type":0},{"key":"description","type":0},{"key":"displayName","type":0},{"key":"mailNickname","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"Name","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
Azure-AD-Group-Create-check-names 
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "Azure-AD-Group-Create-check-names " #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Azure AD Group - Create" #>
$tmpSchema = @"
[{"key":"groupType","templateOptions":{"label":"Group type","required":true,"useObjects":false,"useDataSource":false,"useFilter":false,"options":["Microsoft 365 group","Security group"]},"type":"dropdown","defaultValue":"Microsoft 365 group","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"groupName","templateOptions":{"label":"Group Name","required":true},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"naming","templateOptions":{"label":"Naming","required":true,"grid":{"columns":[{"headerName":"Display Name","field":"displayName"},{"headerName":"Description","field":"description"},{"headerName":"Mail","field":"mail"},{"headerName":"Mail Nickname","field":"mailNickname"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"Name","otherFieldValue":{"otherFieldKey":"groupName"}}]}},"useFilter":true,"defaultSelectorProperty":"mail","useDefault":true},"hideExpression":"!model[\"groupType\"]","type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true},{"key":"displayName","templateOptions":{"label":"Display Name","useDataSource":false,"displayField":"displayName","required":true,"placeholder":"Loading...","useDependOn":true,"dependOn":"naming","dependOnProperty":"displayName"},"hideExpression":"!model[\"naming\"]","type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"description","templateOptions":{"label":"Description","useDataSource":false,"displayField":"description","placeholder":"Loading...","useDependOn":true,"dependOn":"naming","dependOnProperty":"description"},"hideExpression":"!model[\"naming\"]","type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"mailNickname","templateOptions":{"label":"Mail Nickname","useDependOn":true,"dependOn":"naming","dependOnProperty":"mailNickname","placeholder":"Loading...","required":true},"hideExpression":"!model[\"naming\"]","type":"input","defaultValue":"","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"multiselectOwners","templateOptions":{"label":"Owners","useObjects":false,"useFilter":true,"options":["Option 1","Option 2","Option 3"],"useDataSource":true,"valueField":"UserPrincipalName","textField":"UserPrincipalName","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[]}}},"hideExpression":"!model[\"naming\"]","type":"multiselect","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"multiselectMembers","templateOptions":{"label":"Members","useObjects":false,"useFilter":true,"options":["Option 1","Option 2","Option 3"],"useDataSource":true,"valueField":"UserPrincipalName","textField":"UserPrincipalName","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[]}}},"hideExpression":"!model[\"naming\"]","type":"multiselect","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Azure AD Group - Create
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
    } catch {
        Write-Error "HelloID (access)group '$group', message: $_"
    }
}
$delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Compress)
$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Azure AD Group - Create
'@
Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-users" -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

<# Begin: Delegated Form Task #>
if($delegatedFormRef.created -eq $true) { 
	$tmpScript = @'
# Fixed values
$visibility = "Public"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try{   
    Hid-Write-Status -Message "Generating Microsoft Graph API Access Token.." -Event Information

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }
 
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    Hid-Write-Status -Message "Creating AzureAD group [$($Name)].." -Event Information
 
    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $baseCreateUri = "https://graph.microsoft.com/"
    $createUri = $baseCreateUri + "v1.0/groups"


    Switch($GroupType){
        'Microsoft 365 group' {
            $group = [PSCustomObject]@{
                description = $Description;
                displayName = $DisplayName;

                groupTypes = @("Unified");

                mailEnabled = $true;
                mailNickname = $MailNickname;
                # allowExternalSenders = $allowExternalSenders; - Not supported with Application permissions
                # autoSubscribeNewMembers = $autoSubscribeNewMembers; - Not supported with Application permissions

                securityEnabled = $false;

                visibility = $visibility;
            }
        }

        'Security group' {
            $group = [PSCustomObject]@{
                description = $Description;
                displayName = $DisplayName;

                #groupTypes = @(""); - Needs to be empty to create Security group

                mailEnabled = $false;
                mailNickname = $MailNickname;
                # allowExternalSenders = $allowExternalSenders; - Not supported with Application permissions
                # autoSubscribeNewMembers = $autoSubscribeNewMembers; - Not supported with Application permissions

                securityEnabled = $true;

                visibility = $visibility;
            }
        }
    }

    if(![string]::IsNullOrEmpty($owners)){
        Hid-Write-Status -Message "Adding Owners: $owners" -Event Warning
        $ownersToAdd = ($owners | ConvertFrom-Json)
    
        $ownersBody =  @(foreach($user in $ownersToAdd){
            "https://graph.microsoft.com/v1.0/users/$($user.id)"
        })
        $group | Add-Member -MemberType NoteProperty -Name "owners@odata.bind" -Value $ownersBody -Force
    }
    
    if(![string]::IsNullOrEmpty($members)){
        Hid-Write-Status -Message "Adding Members: $members" -Event Warning
        $membersToAdd = ($members | ConvertFrom-Json)
    
        $membersBody =  @(foreach($user in $membersToAdd){
            "https://graph.microsoft.com/v1.0/users/$($user.id)"
        })
        $group | Add-Member -MemberType NoteProperty -Name "members@odata.bind" -Value $membersBody -Force
    }
    

    $body = $group | ConvertTo-Json -Depth 10
 
    $response = Invoke-RestMethod -Uri $createUri -Method POST -Headers $authorization -Body $body -Verbose:$false

    Hid-Write-Status -Message "AzureAD group [$($DisplayName)] created successfully" -Event Success
    HID-Write-Summary -Message "AzureAD group [$($DisplayName)] created successfully" -Event Success
} catch {
    if($_.ErrorDetails.Message) { $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message } 
    HID-Write-Status -Message -Event Error ("Error creating AzureAD group [$($DisplayName)]. Error: $_" + $errorDetailsMessage)
    HID-Write-Summary -Message -Event Failed "Error creating AzureAD group [$($DisplayName)]"
}
'@; 

	$tmpVariables = @'
[{"name":"Description","value":"{{form.description}}","secret":false,"typeConstraint":"string"},{"name":"DisplayName","value":"{{form.displayName}}","secret":false,"typeConstraint":"string"},{"name":"GroupType","value":"{{form.groupType}}","secret":false,"typeConstraint":"string"},{"name":"MailNickname","value":"{{form.mailNickname}}","secret":false,"typeConstraint":"string"},{"name":"Members","value":"{{form.multiselectMembers.toJsonString}}","secret":false,"typeConstraint":"string"},{"name":"Owners","value":"{{form.multiselectOwners.toJsonString}}","secret":false,"typeConstraint":"string"}]
'@ 

	$delegatedFormTaskGuid = [PSCustomObject]@{} 
$delegatedFormTaskName = @'
Azure-AD-Group-Create
'@
	Invoke-HelloIDAutomationTask -TaskName $delegatedFormTaskName -UseTemplate "False" -AutomationContainer "8" -Variables $tmpVariables -PowershellScript $tmpScript -ObjectGuid $delegatedFormRef.guid -ForceCreateTask $true -returnObject ([Ref]$delegatedFormTaskGuid) 
} else {
	Write-Warning "Delegated form '$delegatedFormName' already exists. Nothing to do with the Delegated Form task..." 
}
<# End: Delegated Form Task #>
