# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Fixed values
$visibility = "Public"

# variables configured in form
$Description = $form.description
$DisplayName = $form.displayName
$MailNickname = $form.mailNickname
$GroupType = $form.groupType
$members = $form.multiselectmembers
$owners = $form.multiselectowners

try {   
    Write-Information "Generating Microsoft Graph API Access Token.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type    = "client_credentials"
        client_id     = "$AADAppId"
        client_secret = "$AADAppSecret"
        resource      = "https://graph.microsoft.com"
    }
 
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    Write-Information "Creating AzureAD group [$($DisplayName)].."
 
    #Add the authorization header to the request
    $authorization = @{
        Authorization  = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept         = "application/json";
    }
 
    $baseCreateUri = "https://graph.microsoft.com/"
    $createUri = $baseCreateUri + "v1.0/groups"


    Switch ($GroupType) {
        'Microsoft 365 group' {
            $group = [PSCustomObject]@{
                description     = $Description;
                displayName     = $DisplayName;

                groupTypes      = @("Unified");

                mailEnabled     = $true;
                mailNickname    = $MailNickname;
                # allowExternalSenders = $allowExternalSenders; - Not supported with Application permissions
                # autoSubscribeNewMembers = $autoSubscribeNewMembers; - Not supported with Application permissions

                securityEnabled = $false;

                visibility      = $visibility;
            }
        }

        'Security group' {
            $group = [PSCustomObject]@{
                description     = $Description;
                displayName     = $DisplayName;

                #groupTypes = @(""); - Needs to be empty to create Security group

                mailEnabled     = $false;
                mailNickname    = $MailNickname;
                # allowExternalSenders = $allowExternalSenders; - Not supported with Application permissions
                # autoSubscribeNewMembers = $autoSubscribeNewMembers; - Not supported with Application permissions

                securityEnabled = $true;

                visibility      = $visibility;
            }
        }
    }
    
    if ($owners) {
        Write-Warning "Adding Owners: $($owners.displayName) [$($owners.UserPrincipalName)]"
        #$ownersToAdd = ($owners | ConvertFrom-Json)
    
        $ownersBody = @(foreach ($user in $owners) {
                "https://graph.microsoft.com/v1.0/users/$($user.id)"
            })
        $group | Add-Member -MemberType NoteProperty -Name "owners@odata.bind" -Value $ownersBody -Force
    }
    
    if ($members) {
        Write-Warning "Adding Members: $($members.displayName) [$($members.UserPrincipalName)]"
        #$membersToAdd = ($members | ConvertFrom-Json)
    
        $membersBody = @(foreach ($user in $members) {
                "https://graph.microsoft.com/v1.0/users/$($user.id)"
            })
        $group | Add-Member -MemberType NoteProperty -Name "members@odata.bind" -Value $membersBody -Force
    }
    

    $body = $group | ConvertTo-Json -Depth 10
 
    #Write-Information $body
    $response = Invoke-RestMethod -Uri $createUri -Method POST -Headers $authorization -Body $body -Verbose:$false
    
    Write-Information "AzureAD group [$($DisplayName)] created successfully"
    $Log = @{
        Action            = "CreateResource" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "AzureAD group [$($DisplayName)] created successfully" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $DisplayName # optional (free format text) 
        TargetIdentifier  = $([string]$response.id) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
    
}
catch {
    if ($_.ErrorDetails.Message) { $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message } 
    Write-Error "Error creating AzureAD group [$($DisplayName)]. Error: $_ $errorDetailsMessage"
    $Log = @{
        Action            = "CreateResource" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "Failed to create AzureAD group [$($DisplayName)]." # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $DisplayName # optional (free format text) 
        TargetIdentifier  = $([string]$response.id) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
