#  https://developer.sophos.com/apis
#region functions
Function Get-SophosAccessToken {
	[CmdletBinding()]
	PARAM (
		[Parameter(Mandatory=$True)]
		[string]
		$ClientId,

		[Parameter(Mandatory=$True)]
		[string]
		$ClientSecret
	)
	
	PROCESS {
		# Uri of endpoint
		$AuthUri = 'https://id.sophos.com/api/v2/oauth2/token'
		$contentType = 'application/x-www-form-urlencoded'

		# Body of the request
		$Body = @{
		  grant_type='client_credentials'
		  client_id=$ClientId
		  client_secret=$ClientSecret
		  scope="token"
		}

		# Call the Uri and get the logon token
		$Content = Invoke-RestMethod -Method POST -Body $Body -Uri $AuthUri -ContentType $contentType
		$Content.access_token
	}
} # Function Get-SophosAccessToken

Function Get-SophosPartnerId {
	[CmdletBinding(DefaultParameterSetName="AccessToken")]
	PARAM(
		[Parameter(Mandatory=$True,ParameterSetName="Credentials")]
		[string]
		$ClientId,

		[Parameter(Mandatory=$True,ParameterSetName="Credentials")]
		[string]
		$ClientSecret,

		[Parameter(Mandatory=$True,ParameterSetName="AccessToken")]
		[string]
		$AccessToken
	)

	PROCESS {
		if ( $PSCmdlet.ParameterSetName -eq "Credentials" ) {
			$AccessToken = Get-SophosAccessToken @PSBoundParameters
		}

		$Bearer = "Bearer {0}" -f $AccessToken
		$AuthHeaders = @{Authorization = $Bearer} 

		$MyIdentity = Invoke-RestMethod -Uri https://api.central.sophos.com/whoami/v1 -Headers $AuthHeaders
		$PartnerId = $MyIdentity.Id

		$PartnerId
	}
} # Function Get-SophosPartnerId

Function Get-SophosTenant {
	[CmdletBinding()]
	PARAM (
		[Parameter(Mandatory=$True)]
		[string]
		$PartnerId,

		[Parameter(Mandatory=$True)]
		[string]
		$AccessToken,

		[Parameter(Mandatory=$False)]
		[string]
		$TenantId,

		[Parameter(Mandatory=$False)]
		[string]
		$TenantName
	)
	BEGIN {}
	PROCESS {
		$Bearer = "Bearer {0}" -f $AccessToken
		$AuthHeaders = @{
			Authorization = $Bearer
			"X-Partner-ID" = $PartnerId
		}

		if ( $PSBoundParameters.ContainsKey("TenantId") ) {
			$TenantUri = "https://api.central.sophos.com/partner/v1/tenants/{0}" -f $TenantId
			$AllTenants = Invoke-RestMethod -Method GET -Headers $AuthHEaders -Uri $TenantUri
			$AllTenants
		} # Specific ID provided
		else {
			$TenantUri = "https://api.central.sophos.com/partner/v1/tenants?pageTotal=$True"
			$AllTenants = Invoke-RestMethod -Method GET -Headers $AuthHEaders -Uri $TenantUri

			#  If a specific tenant name was specified, use that
			if ( $PSBoundParameters.ContainsKey("TenantName" ) ) {
				$AllTenants.Items.Where({$_.name -eq $TenantName})
			} 
			else { # Return all tenants
				$AllTenants.Items
			}
		} # No ID provided
	}

	END {}
} # Function Get-SophosTenant

Function Get-SophosEndpoint {
	[CmdletBinding()]
	PARAM (
		[Parameter(Mandatory=$True)]
		[string]
		$TenantId,

		[Parameter(Mandatory=$True)]
		[string]
		$AccessToken,

		[Parameter(Mandatory=$True)]
		[string]
		$TenantApiHost,

		[Parameter(Mandatory=$False)]
		[string]
		$EndpointId,

		[Parameter(Mandatory=$False)]
		[string]
		$EndpointName,

		[Parameter(Mandatory=$False)]
		[Boolean]
		$TamperProtectEnabled,

		[Parameter(Mandatory=$False)]
		[string]
		$LastSeenBefore,

		[Parameter(Mandatory=$False)]
		[string]
		$LastSeenAfter,

		[Parameter(Mandatory=$False)]
		[ValidateSet("creatingWhitelist", "installing", "locked", "notInstalled", "registering", "starting", "stopping", "unavailable", "uninstalled", "unlocked")]
		[string]
		$LockdownStatus,

		[Parameter(Mandatory=$False)]
		[ValidateSet("bad", "good", "suspicious")]
		[string]
		$HealthStatus,

		[Parameter(Mandatory=$False)]
		[ValidateSet("basic", "summary", "full")]
		[string]
		$View,

		[Parameter(Mandatory=$False)]
		[ValidateSet("computer", "server", "securityVm")]
		[string]
		$Type,

		[Parameter(Mandatory=$False)]
		[int]
		$PageSize = 200

	)
	BEGIN {}
	PROCESS {
		$Bearer = "Bearer {0}" -f $AccessToken
		$AuthHeaders = @{
			Authorization = $Bearer
			"X-Tenant-ID" = $TenantId
		}

		$TenantUri = "{0}/endpoint/v1/endpoints" -f $TenantApiHost

		# If ID was specified, we only need to return the one
		if ( $PSBoundParameters.ContainsKey("EndpointId") ) {
			$TenantUri = "{0}/{1}" -f $TenantUri, $EndpointId
			$TenantReturn = Invoke-RestMethod -Headers $AuthHeaders -Uri $TenantUri -Method GET
			$TenantReturn
		}
		<#elseif ($PSBoundParameters.ContainsKey("TamperProtectEnabled")) {
			$TenantUri = "{0}" -f $TenantUri, $EndpointId
			$TenantReturn = Invoke-RestMethod -Headers $AuthHeaders -Uri $TenantUri -Method GET
			$TenantReturn
		}#>
		# Otherwise, we need to loop over all the pages
		else {
			#region customparameters
			$QueryOperator = "?" 

			if ( $PSBoundParameters.ContainsKey("TamperProtectEnabled") ) {
				$TenantUri = "{0}{1}tamperProtectionEnabled={2}" -f $TenantUri, $QueryOperator, $TamperProtectEnabled.toString().toLower()
				$QueryOperator = "&"
			}

			if ( $PSBoundParameters.ContainsKey("LastSeenBefore") ) {
				$LastSeenBefore = try{([datetime]$LastSeenBefore).ToUniversalTime().ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'")}catch{$LastSeenBefore}
				$TenantUri = "{0}{1}lastSeenBefore={2}" -f $TenantUri, $QueryOperator, $LastSeenBefore
				$QueryOperator = "&"
			}

			if ( $PSBoundParameters.ContainsKey("LastSeenAfter") ) {
				#$LastSeenBefore = try{([datetime]$LastSeenAfter).ToUniversalTime().ToString("s") + "Z"}catch{$LastSeenAfter}
				$LastSeenBefore = try{([datetime]$LastSeenAfter).ToUniversalTime().ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'")}catch{$LastSeenAfter}
				$TenantUri = "{0}{1}lastSeenAfter={2}" -f $TenantUri, $QueryOperator, $LastSeenAfter
				$QueryOperator = "&"
			}

			if ( $PSBoundParameters.ContainsKey("LastSeenAfter") ) {
				#$LastSeenBefore = try{([datetime]$LastSeenAfter).ToUniversalTime().ToString("s") + "Z"}catch{$LastSeenAfter}
				$LastSeenBefore = try{([datetime]$LastSeenAfter).ToUniversalTime().ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'")}catch{$LastSeenAfter}
				$TenantUri = "{0}{1}lastSeenAfter={2}" -f $TenantUri, $QueryOperator, $LastSeenAfter
				$QueryOperator = "&"
			}

			if ( $PSBoundParameters.ContainsKey("LockdownStatus") ) {
				$ValidLockdownList = @("creatingWhitelist", "installing", "locked", "notInstalled", "registering", "starting", "stopping", "unavailable", "uninstalled", "unlocked")
				$LockdownStatus = $ValidLockdownList.Where({$_ -match $LockdownStatus})
				$TenantUri = "{0}{1}lockdownStatus={2}" -f $TenantUri, $QueryOperator, $LockdownStatus
				$QueryOperator = "&"
			}

			if ( $PSBoundParameters.ContainsKey("HealthStatus") ) {
				$ValidHealthList = @("bad", "good", "suspicious")
				$HealthStatus = $ValidHealthList.Where({$_ -match $HealthStatus})
				$TenantUri = "{0}{1}healthStatus={2}" -f $TenantUri, $QueryOperator, $HealthStatus
				$QueryOperator = "&"
			}

			if ( $PSBoundParameters.ContainsKey("View") ) {
				$ValidViewList = @("basic", "summary", "full")
				$View = $ValidViewList.Where({$_ -match $View})
				$TenantUri = "{0}{1}view={2}" -f $TenantUri, $QueryOperator, $View
				$QueryOperator = "&"
			}

			if ( $PSBoundParameters.ContainsKey("Type") ) {
				$ValidTypeList = @("computer", "server", "securityVm")
				$Type = $ValidTypeList.Where({$_ -match $Type})
				$TenantUri = "{0}{1}type={2}" -f $TenantUri, $QueryOperator, $Type
				$QueryOperator = "&"
			}

			$TenantUri = "{0}{1}pageSize={2}" -f $TenantUri, $QueryOperator, $PageSize
			$QueryOperator = "&"
			
			#endregion customparameters

			$AllObjs = New-Object -TypeName "System.Collections.ArrayList"

			Write-Verbose "Calling Page 1"
			$TenantObj = Invoke-RestMethod -Headers $AuthHeaders -Uri $TenantUri -Method GET

			$PageNo = 2
			[void]$AllObjs.AddRange($TenantObj.Items)
			While ( $TenantObj.pages.nextKey ) {
				if ( $PSBoundParameters.ContainsKey("EndpointName") -and $TenantObj.Items.Where({$_.Hostname -contains $EndpointName}) ) {
					$TenantObj.Items.Where({$_.Hostname -contains $EndpointName})
					break
				}
				
				Write-Verbose "Calling Page $PageNo"
				$NextUri = "{0}{1}pageFromKey={2}" -f $TenantUri, $QueryOperator, $TenantObj.pages.nextKey
				$TenantObj = Invoke-RestMethod -Method GET -Headers $AuthHeaders -Uri $NextUri
				[void]$AllObjs.AddRange($TenantObj.Items)
				$PageNo++
			} # While

			$AllObjs
		} # Else
	} # PROCESS

	END {}
} # Function Get-SophosEndpoint

Function Get-SophosEndpointTamperProtection {
	[CmdletBinding()]
	PARAM (
		[Parameter(Mandatory=$True)]
		[string]
		$TenantId,

		[Parameter(Mandatory=$True)]
		[string]
		$AccessToken,

		[Parameter(Mandatory=$True)]
		[string]
		$TenantApiHost,

		[Parameter(Mandatory=$True)]
		[string[]]
		$EndpointId
	)
	BEGIN {}
	PROCESS {
		$Bearer = "Bearer {0}" -f $AccessToken
		$AuthHeaders = @{
			Authorization = $Bearer
			"X-Tenant-ID" = $TenantId
		}

		$TenantUri = "{0}/endpoint/v1/endpoints" -f $TenantApiHost

		ForEach ($Id in $EndpointId) {
			$TamperProtectUri = "{0}/{1}/tamper-protection" -f $TenantUri, $Id
			$TenantReturn = Invoke-RestMethod -Headers $AuthHeaders -Uri $TamperProtectUri -Method GET 
			$TenantReturn
		}
	} # PROCESS

	END {}
} # Get-SophosEndpointTamperProtection

Function Enable-SophosTamperProtection {
	[CmdletBinding()]
	PARAM (
		[Parameter(Mandatory=$True)]
		[string]
		$TenantId,

		[Parameter(Mandatory=$True)]
		[string]
		$AccessToken,

		[Parameter(Mandatory=$True)]
		[string]
		$TenantApiHost,

		[Parameter(Mandatory=$True)]
		[string[]]
		$EndpointId,

		[Parameter(Mandatory=$False)]
		[boolean]
		$RegeneratePassword = $False
	)
	BEGIN {}
	PROCESS {
		$Bearer = "Bearer {0}" -f $AccessToken
		$AuthHeaders = @{
			Authorization = $Bearer
			"X-Tenant-ID" = $TenantId
		}

		$TenantUri = "{0}/endpoint/v1/endpoints" -f $TenantApiHost

		ForEach ($Id in $EndpointId) {
			$TamperProtectUri = "{0}/{1}/tamper-protection" -f $TenantUri, $Id

			$TamperProtectBody = @{
				enabled = $True
				regeneratePassword = $RegeneratePassword
			} | ConvertTo-JSON

			$TenantReturn = Invoke-RestMethod -Headers $AuthHeaders -Uri $TamperProtectUri -Method POST -Body $TamperProtectBody -ContentType "application/json"
			$TenantReturn
		}
	} # PROCESS

	END {}
} # Function Enable-SophosTamperProtection

Function Disable-SophosTamperProtection {
	[CmdletBinding()]
	PARAM (
		[Parameter(Mandatory=$True)]
		[string]
		$TenantId,

		[Parameter(Mandatory=$True)]
		[string]
		$AccessToken,

		[Parameter(Mandatory=$True)]
		[string]
		$TenantApiHost,

		[Parameter(Mandatory=$True)]
		[string[]]
		$EndpointId,

		[Parameter(Mandatory=$False)]
		[boolean]
		$RegeneratePassword = $False
	)
	BEGIN {}
	PROCESS {
		$Bearer = "Bearer {0}" -f $AccessToken
		$AuthHeaders = @{
			Authorization = $Bearer
			"X-Tenant-ID" = $TenantId
		}

		$TenantUri = "{0}/endpoint/v1/endpoints" -f $TenantApiHost

		ForEach ($Id in $EndpointId) {
			$TamperProtectUri = "{0}/{1}/tamper-protection" -f $TenantUri, $Id

			$TamperProtectBody = @{
				enabled = $False
				regeneratePassword = $RegeneratePassword
			} | ConvertTo-JSON

			$TenantReturn = Invoke-RestMethod -Headers $AuthHeaders -Uri $TamperProtectUri -Method POST -Body $TamperProtectBody -ContentType "application/json"
			$TenantReturn
		}
	} # PROCESS

	END {}
} # Function Disable-SophosTamperProtection

Function Invoke-SophosEndpointUpdateCheck {
	[CmdletBinding()]
	PARAM (
		[Parameter(Mandatory=$True)]
		[string]
		$TenantId,

		[Parameter(Mandatory=$True)]
		[string]
		$AccessToken,

		[Parameter(Mandatory=$True)]
		[string]
		$TenantApiHost,

		[Parameter(Mandatory=$True)]
		[string[]]
		$EndpointId
	)
	BEGIN {}
	PROCESS {
		$Bearer = "Bearer {0}" -f $AccessToken
		$AuthHeaders = @{
			Authorization = $Bearer
			"X-Tenant-ID" = $TenantId
		}

		$TenantUri = "{0}/endpoint/v1/endpoints" -f $TenantApiHost

		$EndpointUri = "{0}/{1}/update-checks" -f $TenantUri, $EndpointId

		$TamperProtectBody = @{} | ConvertTo-JSON

		$TenantReturn = Invoke-RestMethod -Headers $AuthHeaders -Uri $EndpointUri -Method POST -Body $Body -ContentType "application/json"
		$TenantReturn
	} # PROCESS

	END {}
} # Invoke-SophosEndpointUpdateCheck

Function Invoke-SophosEndpointScan {
	[CmdletBinding()]
	PARAM (
		[Parameter(Mandatory=$True)]
		[string]
		$TenantId,

		[Parameter(Mandatory=$True)]
		[string]
		$AccessToken,

		[Parameter(Mandatory=$True)]
		[string]
		$TenantApiHost,

		[Parameter(Mandatory=$True)]
		[string[]]
		$EndpointId
	)
	BEGIN {}
	PROCESS {
		$Bearer = "Bearer {0}" -f $AccessToken
		$AuthHeaders = @{
			Authorization = $Bearer
			"X-Tenant-ID" = $TenantId
		}

		$TenantUri = "{0}/endpoint/v1/endpoints" -f $TenantApiHost

		$EndpointUri = "{0}/{1}/scans" -f $TenantUri, $EndpointId

		$TamperProtectBody = @{} | ConvertTo-JSON

		$TenantReturn = Invoke-RestMethod -Headers $AuthHeaders -Uri $EndpointUri -Method POST -Body $Body -ContentType "application/json"
		$TenantReturn
	} # PROCESS

	END {}
} # Invoke-SophosEndpointScan

Function Remove-SophosEndpoint {
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
	PARAM (
		[Parameter(Mandatory=$True)]
		[string]
		$TenantId,

		[Parameter(Mandatory=$True)]
		[string]
		$AccessToken,

		[Parameter(Mandatory=$True)]
		[string]
		$TenantApiHost,

		[Parameter(Mandatory=$True)]
		[string]
		$EndpointId,

		[Parameter(Mandatory=$False)]
		[boolean]
		$DisableTamperProtect = $True,

		[Parameter()]
        [switch]
        $Force
	)
	BEGIN {}
	PROCESS {
		if ( $DisableTamperProtect ) {
			# This is defaulted to true.  If you run a remove without disabling tamper protect, you lose access to control the endpoint
			# so if you don't have the current password documented, you lose access to update/uninstall/etc. the endpoint
			Write-Verbose "Disabling Tamper Protect"
			Disable-SophosTamperProtection -TenantId $TenantId -AccessToken $AccessToken -TenantApiHost $TenantApiHost -EndpointId $EndpointId -RegeneratePassword $False
		}

		$Bearer = "Bearer {0}" -f $AccessToken
		$AuthHeaders = @{
			Authorization = $Bearer
			"X-Tenant-ID" = $TenantId
		}

		$TenantUri = "{0}/endpoint/v1/endpoints" -f $TenantApiHost

		$DeleteUri = "{0}/{1}" -f $TenantUri, $EndpointId

		$TamperProtectBody = @{} | ConvertTo-JSON

		if ($Force -or $PSCmdlet.ShouldProcess("Confirm delete endpoint id $EndpoingId")) {
			$TenantReturn = Invoke-RestMethod -Headers $AuthHeaders -Uri $DeleteUri -Method DELETE -Body $TamperProtectBody -ContentType "application/json"
			$TenantReturn
		}
	} # PROCESS

	END {}
} # Function Disable-SophosTamperProtection

#endregion functions

#region export
Export-ModuleMember -Function Get-SophosAccessToken
Export-ModuleMember -Function Get-SophosPartnerId
Export-ModuleMember -Function Get-SophosTenant
Export-ModuleMember -Function Get-SophosEndpoint
Export-ModuleMember -Function Get-SophosEndpointTamperProtection
Export-ModuleMember -Function Enable-SophosTamperProtection
Export-ModuleMember -Function Disable-SophosTamperProtection
Export-ModuleMember -Function Invoke-SophosEndpointUpdateCheck
Export-ModuleMember -Function Invoke-SophosEndpointScan
Export-ModuleMember -Function Remove-SophosEndpoint
#endregion export
