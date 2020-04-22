# PSSophos #
Powershell Module for the Sophos Central APIs

## Purpose ##

This module is intended to simplify interfacing with the Sophos Central's public API
https://developer.sophos.com/apis

## Sample usage ##

#### Set the variables ####
The ClientId and ClientSecret need to be created in the Sophos enterprise console, once created, these should be stored securely, but for demo purposes I will show how they are assigned as plain text.

```
$ClientId = "873f51e8-8d71-4fee-99f7-ffc381174b6f"
$ClientSecret = "VABoAGkAcwAgAGkAcwBuACcAdAAgAHIAZQBhAGwAbAB5ACAAbQB5ACAAcwBlAGMAcgBlAHQA"
```
_note: these are invalid_

#### Obtain a logon token ####
The logon token is good for 1 hour, and is used as an input to all other functions.  This is the first call, and logs you into the API with your API Key/Secret

```
$AccessToken = Get-SophosAccessToken -ClientId $ClientId -ClientSecret $ClientSecret
````

#### Obtain the PartnerId ####
The next step is to get your PartnerId, which is used to access your tenants
```
$PartnerId = Get-SophosPartnerId -AccessToken $AccessToken
```

#### List Tenants ####
The tenants show you which sub-estates you have in your organization. You need the tenant ID in order to manage endpoints for that tenant/sub-estate.  The following will l ist all tenants.
```
Get-SophosTenant -PartnerId $PartnerId -AccessToken $AccessToken
```

You can also get the tenant info based on name/id:

```
Get-SophosTenant -PartnerId $PartnerId -AccessToken $AccessToken -TenantId 17e9b3f3-c147-4d1f-87d5-313f44c4febe
$Tenant = Get-SophosTenant -PartnerId $PartnerId -AccessToken $AccessToken -TenantName "My Target Tenant"
$Tenant
id            : 17e9b3f3-c147-4d1f-87d5-313f44c4febe
name          : My Target Tenant
dataGeography : US
dataRegion    : us03
billingType   : trial
partner       : @{id=30e744d9-6805-4f7b-afce-58dc36948b8c}
organization  : @{id=4296be4d-55d9-4f1e-8f7a-e6797336742f}
apiHost       : https://api-us02.central.sophos.com
```
_note: all guids above were generated with New-Guid and are assumed invalid_
The Tenant ID and APIHost are required for the endpoint specific functions.

#### List all Endpoints under a given tenant ####
```
$EndPoints = Get-SophosEndpoint -TenantId $Tenant.id -TenantApiHost $Tenant.ApiHost -AccessToken $AccessToken 
```
Those 3 parameters are required for all Endpoint functions.  There is also filtering available:

__List all endpoints with TamperProtection disabled__
```
Get-SophosEndpoint -TenantId $Tenant.id -TenantApiHost $Tenant.ApiHost -AccessToken $AccessToken -TamperProtectionEnabled $False
```

__List all endpoints based on LastSeen__
```
# Last seen before a specific date
Get-SophosEndpoint -TenantId $Tenant.id -TenantApiHost $Tenant.ApiHost -AccessToken $AccessToken -LastSeenBefore '01/01/2020'

# Last seen after a specific date
Get-SophosEndpoint -TenantId $Tenant.id -TenantApiHost $Tenant.ApiHost -AccessToken $AccessToken -LastSeenAfter '01/01/2020'

# Last seen more than 30 days ago
Get-SophosEndpoint -TenantId $Tenant.id -TenantApiHost $Tenant.ApiHost -AccessToken $AccessToken -LastSeenBefore -P30D
```
_More information for specific filtering for lastSeenBefore/lastSeenAfter can be found on Sophos documentation(https://developer.sophos.com/docs/endpoint-and-server/1/routes/endpoints/get)_

__List endpoints with suspicious health status__
```
Get-SophosEndpoint -TenantId $Tenant.id -TenantApiHost $Tenant.ApiHost -AccessToken $AccessToken -healthStatus suspicious
```

#### There is also functionality for Disabling/Enabling tamper protect, removing endpoints, and invoking scans/update checks ####
```
Enable-SophosTamperProtection -TenantId $Tenant.id -TenantApiHost $Tenant.ApiHost -AccessToken $AccessToken -EndpointId 4296be4d-55d9-4f1e-8f7a-e6797336742f -RegeneratePassword $False

Disable-SophosTamperProtection -TenantId $Tenant.id -TenantApiHost $Tenant.ApiHost -AccessToken $AccessToken -EndpointId 4296be4d-55d9-4f1e-8f7a-e6797336742f -RegeneratePassword $False

Invoke-SophosEndpointUpdateCheck -TenantId $Tenant.id -TenantApiHost $Tenant.ApiHost -AccessToken $AccessToken -EndpointId 4296be4d-55d9-4f1e-8f7a-e6797336742f

Invoke-SophosEndpointScan -TenantId $Tenant.id -TenantApiHost $Tenant.ApiHost -AccessToken $AccessToken -EndpointId 4296be4d-55d9-4f1e-8f7a-e6797336742f

Remove-SophosEndpoint -TenantId $Tenant.id -TenantApiHost $Tenant.ApiHost -AccessToken $AccessToken -EndpointId 4296be4d-55d9-4f1e-8f7a-e6797336742f -DisableTamperProtect $True
```
