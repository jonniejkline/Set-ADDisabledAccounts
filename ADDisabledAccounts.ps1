# Connect to MS Graph using the Reporting API App
    function Get-Token {
        if (($null -eq $Script:tokenTime) -or (((Get-Date) - $Script:tokenTime).Minutes -gt 45)){
            $TenantId = Get-Secret -Vault Global -Name "REDACTED" -AsPlainText
            $ClientId = Get-Secret -Vault Global -Name "REDACTED" -AsPlainText
            $ClientSecret = Get-Secret -Vault Global -Name "REDACTED" -AsPlainText

            $Body = @{
                Grant_Type      = "client_credentials"
                Scope           = "https://graph.microsoft.com/.default"
                Client_Id       = $ClientId
                Client_Secret   = $ClientSecret
            }
            $Connection = Invoke-RestMethod -Uri https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token -Method POST -Body $Body

            $Token = ConvertTo-SecureString "$($Connection.access_token)" -AsPlainText -Force

            $graph = Connect-MgGraph -AccessToken $Token 

            if($graph){Add-LogMessage "Connected to Graph API";$Script:tokenTime = (Get-Date)}
        }
    }
    # Generate a log message and append it to the log file
    function Add-LogMessage {
        param (
            [string]$Message
        )
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "$timestamp - $Message`n"

        $isWritten = $false
        do {
            try {
                [System.IO.File]::AppendAllText($logFilePath,$logMessage)
                $isWritten = $true
            } catch {}
        } until ( $isWritten )
        Write-Output $logMessage
    }
    # Compares input FileDateTime to current date and determines expiration status of the account
    function Get-IsExpired {
        param (
            [Long]$AccountExpires
        )
        if(($AccountExpires -eq 9223372036854775807) -or ($AccountExpires -eq 0) -or (([datetime]::FromFileTime($AccountExpires)) -ge $Script:date)){
            return @{
                'Expired'   = $false
            }
        } elseif (([datetime]::FromFileTime($AccountExpires)) -gt ($Script:date.AddDays(-30))) {
            return @{
                'Expired'   = $true
                'Action'    = "Disable"
                'Date'      = ([datetime]::FromFileTime($AccountExpires))
            }
        } else {
            return @{
                'Expired'   = $true
                'Action'    = "Delete"
                'Date'      = ([datetime]::FromFileTime($AccountExpires))
            }
        }
    }
    # Compares last login activity of account with current date to determine inactivity status
    function Get-IsInactive {
        param (
            [string]$UserPrincipalName,
            [datetime]$Created
        )
        Get-Token
        $user = Get-MgUser -Filter "UserPrincipalName eq '$($UserPrincipalName)'" -Property SignInActivity,CreatedDateTime
        $userInfo = @($user.SignInActivity.LastSignInDateTime,$user.SignInActivity.LastNonInteractiveSignInDateTime,$user.CreatedDateTime,$Created)
        if ((($userInfo | Measure-Latest) -ge ($Script:date.AddDays(-45))) -or ($null -eq ($userInfo | Measure-Latest))) {
            return @{
                'Inactive'  = $false
            }
        } elseif (($userInfo | Measure-Latest) -gt ($Script:date.AddDays(-95))) {
            return @{
                'Inactive'  = $true
                'Action'    = "Disable"
                'Date'      = ($userInfo | Measure-Latest)
            }
        } else {
            return @{
                'Inactive'  = $true
                'Action'    = "Delete"
                'Date'      = ($userInfo | Measure-Latest)
            }
        }
    }
    # Return the most recent date of the pipeline values
    function Measure-Latest {
        BEGIN { $latest = $null }
        PROCESS {
                if (($_ -ne $null) -and (($null -eq $latest) -or ($_ -gt $latest))) {
                    $latest = $_ 
                }
        }
        END { $latest }
    }

    # Get all user accounts from AD with required properties
    $adUsers = Get-ADUser -Filter 'extensionAttribute15 -eq "User" -and UserPrincipalName -like "*Redacted"' -Properties AccountExpires,whenCreated | Where-Object {$_.DistinguishedName -notlike "*$ExceptionOU*"} | Select-Object UserPrincipalName,AccountExpires,DistinguishedName,whenCreated
    $adUsers | ForEach-Object {
        # Reformats UPNs containing single quotes to avoid errors 
        $upn = $_.UserPrincipalName -replace '''',''''''
        $whenCreated = $_.whenCreated
        $state = Get-IsExpired -AccountExpires $_.AccountExpires
        $dn = $_.DistinguishedName
        Switch ($state) {
            # If expired for 30+ days
            {$_.Expired -eq $true -and $_.Action -eq "Delete"} {
                Remove-ADUser -Identity $dn -Confirm:$false
                Add-LogMessage "[DELETED][Expiry][Account expired on $(($state.Date).ToString("yyyy-MMM-dd")) | $(($date - $state.Date).Days) days] $upn"
            }
            # If expired for 1-30 days
            {$_.Expired -eq $true -and $_.Action -eq "Disable"} {
                Disable-ADAccount -Identity $dn
                Set-ADUser -Identity $dn -Replace @{info="Disabled user for expiry. Account expired $(($date - $state.Date).Days) days ago on $(($state.Date).ToString("yyyy-MMM-dd"))"}
                Move-ADObject -Identity $dn -TargetPath $DisabledOU
                Add-LogMessage "[DISABLED][Expiry][Account expired on $(($state.Date).ToString("yyyy-MMM-dd")) | $(($date - $state.Date).Days) days] $upn"
            }
            # If not expired
            {$_.Expired -eq $false} {
                $state = Get-IsInactive -UserPrincipalName $upn -Created $whenCreated
                Switch ($state) {
                    # If inactive for 95+ days
                    {$_.Inactive -eq $true -and $_.Action -eq "Delete"} {
                        Remove-ADUser -Identity $dn -Confirm:$false
                        Add-LogMessage "[DELETED][Inactivity][Account inactive since $(($state.Date).ToString("yyyy-MMM-dd")) | $(($date - $state.Date).Days) days] $upn"
                    }
                    # If inactive for 45-95 days
                    {$_.Inactive -eq $true -and $_.Action -eq "Disable"} {
                        Disable-ADAccount -Identity $dn
                        Set-ADUser -Identity $dn -Replace @{info="Disabled user for inactivity. Last signin $(($date - $state.Date).Days) days ago on $(($state.Date).ToString("yyyy-MMM-dd"))"}
                        Move-ADObject -Identity $dn -TargetPath $DisabledOU
                        Add-LogMessage "[DISABLED][Inactivity][Account inactive since $(($state.Date).ToString("yyyy-MMM-dd")) | $(($date - $state.Date).Days) days] $upn"
                    }
                    # If not inactive
                    {$_.Inactive -eq $false} {break}
                }
            }
        }
    }
    # Repeat inactivity function for all guest accounts
    $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All -Properties SignInActivity,CreatedDateTime
    $guestUsers | ForEach-Object {
        $userId = $_.Id
        $upn = $_.UserPrincipalName -replace '''',''''''
        $created = $_.CreatedDateTime
        $state = Get-IsInactive -UserPrincipalName $upn -Created $created
        Switch ($state) {
            # If inactive for 95+ days
            {$_.Inactive -eq $true -and $_.Action -eq "Delete"} {
                Remove-MgUser -UserId $userId -Confirm:$false
                Add-LogMessage "[DELETED][Inactivity][Guest inactive since $(($state.Date).ToString("yyyy-MMM-dd")) | $(($date - $state.Date).Days) days] $upn"
            }
            # If inactive for 45-95 days
            {$_.Inactive -eq $true -and $_.Action -eq "Disable"} {
                Update-MgUser -UserId $userId -AccountEnabled:$false
                Add-LogMessage "[DISABLED][Inactivity][Guest inactive since $(($state.Date).ToString("yyyy-MMM-dd")) | $(($date - $state.Date).Days) days] $upn"
            }
            # If not inactive
            {$_.Inactive -eq $false} {break}
        }
    }
END {Add-LogMessage -Message "Operation completed. Elapsed Time: $("{0:HH:mm:ss}" -f ([datetime]((Get-Date) - $startTime).Ticks))"}
