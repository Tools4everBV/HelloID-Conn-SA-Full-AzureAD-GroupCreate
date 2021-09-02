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
