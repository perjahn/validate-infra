Set-StrictMode -v latest
$ErrorActionPreference = "Stop"

[char[]] $environmentSeparators = ",", "`n", "`r"

function Main() {
    if (!$env:EmailReceivers) {
        Log ("Environment variable EmailReceivers not set!") Red
    }
    if (!$env:EmailSender) {
        Log ("Environment variable EmailSender not set!") Red
    }
    if (!$env:SendGridApiKey) {
        Log ("Environment variable SendGridApiKey not set!") Red
    }
    if (!$env:EmailReceivers -or !$env:EmailSender -or !$env:SendGridApiKey) {
        exit 1
    }

    Get-Dependencies

    if ($env:AzureTenantIds -and $env:AzureClientIds -and $env:AzureClientSecrets) {
        [string[]] $tenantIds = $env:AzureTenantIds.Split($environmentSeparators, [StringSplitOptions]::RemoveEmptyEntries)
        [string[]] $clientIds = $env:AzureClientIds.Split($environmentSeparators, [StringSplitOptions]::RemoveEmptyEntries)
        [string[]] $clientSecrets = $env:AzureClientSecrets.Split($environmentSeparators, [StringSplitOptions]::RemoveEmptyEntries)

        [int] $principalCount = ($tenantIds.Count, $clientIds.Count, $clientSecrets.Count | measure -Minimum).Minimum
        Log ("Got " + $principalCount + " service principals.")

        $principals = @()

        for ([int] $i = 0; $i -lt $principalCount; $i++) {
            $principal = New-Object PSObject
            $principal | Add-Member NoteProperty TenantId $tenantIds[$i]
            $principal | Add-Member NoteProperty ClientId $clientIds[$i]
            $principal | Add-Member NoteProperty ClientSecret $clientSecrets[$i]
            $principals += $principal
        }
    }
    else {
        $principals = $null
    }


    [Diagnostics.Stopwatch] $watch = [Diagnostics.Stopwatch]::StartNew()

    [string] $message = Validate-AzureResources $principals

    Log ("Done: " + $watch.Elapsed)


    if ($message.Length -gt 0) {
        [string] $body = "Found unsecured resources.`n`n" + $message

        Send-Email "Security Alert" $body
    }
}

function Validate-AzureResources($principals) {
    $azureResources = @()

    if ($principals) {
        foreach ($principal in $principals) {
            $ss = $principal.clientSecret | ConvertTo-SecureString -Force -AsPlainText
            $creds = New-Object PSCredential -ArgumentList $principal.clientId, $ss

            Log ("Logging in...")
            Connect-AzAccount -ServicePrincipal -Tenant $principal.tenantId -Credential $creds | Out-Null

            $azureResources += @(Get-InsecureAzureResources)
        }
    }
    else {
        $azureResources += @(Get-InsecureAzureResources)
    }


    $storageAccounts = @($azureResources | % { $_.StorageAccounts } | group "SubscriptionName", "ResourceGroupName", "StorageAccountName")
    Log ("Total insecure storage accounts: " + $storageAccounts.Count)

    $webApps = @($azureResources | % { $_.WebApps } | group "SubscriptionName", "ResourceGroup", "Name", "HttpsOnly", "MinTlsVersion")
    Log ("Total insecure web apps: " + $webApps.Count)

    $rules = @($azureResources | % { $_.SqlServerFirewallRules } | group "SubscriptionName", "ResourceGroupName", "ServerName", "StartIpAddress", "EndIpAddress", "FirewallRuleName")
    Log ("Total sqlserver firewall rules: " + $rules.Count)


    [string] $message = ""

    if ($storageAccounts.Count -gt 0) {
        $message += "The following " + $storageAccounts.Count + " storage accounts allow unencrypted http."
        $message += "`nSubscriptionName`tResourceGroupName`tStorageAccountName"
        foreach ($storageAccount in $storageAccounts | Sort-Object "Name") {
            $message += "`n" + ($storageAccount.Values -join "`t")
        }
    }

    if ($storageAccounts.Count -gt 0 -and $webApps.Count -gt 0) {
        $message += "`n`n"
    }

    if ($webApps.Count -gt 0) {
        $message += "The following " + $webApps.Count + " web apps allow broken/unencrypted http."
        $message += "`nSubscriptionName`tResourceGroupName`tWebAppName`tHttpsOnly`tMinTlsVersion"
        foreach ($webApp in $webApps | Sort-Object "Name") {
            $message += "`n" + ($webApp.Values -join "`t")
        }
    }

    if ($webApps.Count -gt 0 -and $rules.Count -gt 0) {
        $message += "`n`n"
    }

    if ($rules.Count -gt 0) {
        $message += "The following " + $rules.Count + " sqlserver firewall rules exists."
        $message += "`nSubscriptionName`tResourceGroupName`tServerName`tStartIpAddress`tEndIpAddress`tFirewallRuleName"
        foreach ($rule in $rules | Sort-Object "Name") {
            $message += "`n" + ($rule.Values -join "`t")
        }
    }

    return $message
}

function Get-InsecureAzureResources() {
    $subscriptions = @(Get-AzSubscription | Sort-Object "Name")
    Log ("Got " + $subscriptions.Count + " subscriptions.")

    $allStorageAccounts = @()
    $allWebApps = @()
    $allRules = @()

    foreach ($subscription in $subscriptions) {
        [string] $subscriptionName = $subscription.Name
        Log ("Selecting subscription: '" + $subscriptionName + "'")
        Select-AzSubscription $subscriptionName | Out-Null

        $storageAccounts = @(Get-InsecureStorageAccounts)
        foreach ($storageAccount in $storageAccounts) {
            $storageAccount | Add-Member NoteProperty "SubscriptionName" $subscriptionName
        }
        $allStorageAccounts += $storageAccounts

        $webApps = @(Get-InsecureWebApps)
        foreach ($webApp in $webApps) {
            $webApp | Add-Member NoteProperty "SubscriptionName" $subscriptionName
        }
        $allWebApps += $webApps

        $rules = @(Get-SqlServerFirewallRules)
        foreach ($rule in $rules) {
            $rule | Add-Member NoteProperty "SubscriptionName" $subscriptionName
        }
        $allRules += $rules
    }

    $azureResources = New-Object PSObject
    $azureResources | Add-Member NoteProperty "StorageAccounts" $allStorageAccounts
    $azureResources | Add-Member NoteProperty "WebApps" $allWebApps
    $azureResources | Add-Member NoteProperty "SqlServerFirewallRules" $allRules

    return $azureResources
}

function Get-InsecureStorageAccounts() {
    Log ("Retrieving storage accounts...") Magenta
    $storageAccounts = @(Get-AzStorageAccount)
    Log ("Got " + $storageAccounts.Count + " storage accounts.") Magenta

    $insecureStorageAccounts = @($storageAccounts | ? { !$_.EnableHttpsTrafficOnly })

    if ($env:ExcludeStorageAccounts) {
        [string[]] $excludeStorageAccounts = $env:ExcludeStorageAccounts.Split($environmentSeparators, [StringSplitOptions]::RemoveEmptyEntries)
        $insecureStorageAccounts = @($insecureStorageAccounts | ? {
                if ($excludeStorageAccounts.Contains($_.StorageAccountName)) {
                    Log ("Excluding: '" + $_.StorageAccountName + "'")
                    $false
                }
                else {
                    $true
                } })
    }

    Log ("Insecure storage accounts: " + $insecureStorageAccounts.Count) Magenta

    return $insecureStorageAccounts
}

function Get-InsecureWebApps() {
    Log ("Retrieving web apps...") Magenta
    $webApps = @(Get-AzWebApp)
    Log ("Got " + $webApps.Count + " web apps.") Magenta

    foreach ($webApp in $webApps) {
        $minTlsVersion = (Get-AzResource -ResourceType "Microsoft.Web/sites/config" -ResourceGroupName $webApp.ResourceGroup -ResourceName ($webApp.Name + "/web") -ApiVersion "2018-02-01").Properties.minTlsVersion

        $webApp | Add-Member NoteProperty "MinTlsVersion" $minTlsVersion
    }

    $insecureWebApps = @($webApps | ? { !$_.HttpsOnly -or $_.minTlsVersion -ne "1.2" })

    if ($env:ExcludeWebApps) {
        [string[]] $excludeWebApps = $env:ExcludeWebApps.Split($environmentSeparators, [StringSplitOptions]::RemoveEmptyEntries)
        $insecureWebApps = @($insecureWebApps | ? {
                if ($excludeWebApps.Contains($_.Name)) {
                    Log ("Excluding: '" + $_.Name + "'")
                    $false
                }
                else {
                    $true
                } })
    }

    Log ("Insecure web apps: " + $insecureWebApps.Count) Magenta

    return $insecureWebApps
}

function Get-SqlServerFirewallRules() {
    Log ("Retrieving sqlserver firewall rules...") Magenta
    $rules = @(Get-AzSqlServer | Get-AzSqlServerFirewallRule | ? { $_ })
    Log ("Got " + $rules.Count + " sqlserver firewall rules.") Magenta

    if ($env:ExcludeSqlServerFirewallRules) {
        [string[]] $excludeSqlServerFirewallRules = $env:ExcludeSqlServerFirewallRules.Split($environmentSeparators, [StringSplitOptions]::RemoveEmptyEntries)

        $exclude = $excludeSqlServerFirewallRules | % {
            [string[]] $tokens = $_.Split(":")
            if ($tokens.Length -ne 3) {
                Log ("Invalid sqlserver exclude rule: '" + $_ + "'") Yellow
                return
            }
            $o = New-Object PSObject
            $o | Add-Member NoteProperty ResourceGroupName $tokens[0]
            $o | Add-Member NoteProperty ServerName $tokens[1]
            $o | Add-Member NoteProperty IPRange $tokens[2]
            $o
        }

        $rules = @($rules | ? {
                [string] $resourcegroupname = $_.ResourceGroupName
                [string] $servername = $_.ServerName
                [string] $iprange = $_.StartIpAddress + "-" + $_.EndIpAddress

                if ($exclude | ? {
                        (!$_.ResourceGroupName -or $_.ResourceGroupName -eq $resourcegroupname) -and
                        (!$_.ServerName -or $_.ServerName -eq $servername) -and
                        (!$_.IPRange -or $_.IPRange -eq $iprange)
                    }) {
                    Log ("Excluding: '" + $_.ResourceGroupName + "', '" + $_.ServerName + "', " + $_.StartIpAddress + "-" + $_.EndIpAddress + ", '" + $_.FirewallRuleName + "'")
                    return $false
                }

                return $true
            })
    }

    Log ("SqlServer firewall rules: " + $rules.Count) Magenta

    return $rules
}

function Send-Email([string] $subject, [string] $body) {
    [string] $emailReceivers = $env:EmailReceivers
    [string] $emailSender = $env:EmailSender
    [string] $sendGridApiKey = $env:SendGridApiKey

    Log ("From:    '" + $emailSender + "'")
    Log ("Subject: '" + $subject + "'")
    Log ("Body:    '" + $body + "'")

    foreach ($recipient in $emailReceivers.Split("`n")) {
        $client = New-Object SendGrid.SendGridClient -ArgumentList $sendGridApiKey
        $from = New-Object SendGrid.Helpers.Mail.EmailAddress -ArgumentList $emailSender
        $to = New-Object SendGrid.Helpers.Mail.EmailAddress -ArgumentList $recipient
        $msg = [SendGrid.Helpers.Mail.MailHelper]::CreateSingleEmail($from, $to, $subject, $body, "")

        Log ("Sending email to: '$recipient'")
        $response = $client.SendEmailAsync($msg)
        $response.GetAwaiter().GetResult() | Out-Null
    }
}

function Get-Dependencies() {
    Write-Output "Current dir: '$((pwd).Path)'"

    Import-Nuget "https://globalcdn.nuget.org/packages/newtonsoft.json.9.0.1.nupkg" "5D96EE51B2AFF592039EEBC2ED203D9F55FDDF9C0882FB34D3F0E078374954A5"

    Import-Nuget "https://globalcdn.nuget.org/packages/sendgrid.9.12.0.nupkg" "E1B10B0C2A99C289227F0D91F5335D08CDA4C3203B492EBC1B0D312B748A3C04"
}

function Import-Nuget([string] $moduleurl, [string] $dllhash) {
    [string] $nugetfile = Split-Path -Leaf $moduleurl
    [int] $end = $nugetfile.IndexOf(".")
    if ($end -lt 0) {
        [string] $shortname = $nugetfile
    }
    else {
        [string] $shortname = $nugetfile.Substring(0, $end)
    }
    [string] $dllfile = "$($shortname).dll"

    if (Test-Path $dllfile) {
        [string] $hash = (Get-FileHash $dllfile).Hash
        if ($hash -eq $dllhash) {
            Write-Output "Using binary that's already downloaded: '$dllfile'"

            [string] $dllpath = Join-Path (pwd).Path $dllfile
            Write-Output "Importing dllfile: '$dllpath'"
            Import-Module $dllpath
            return
        }
        else {
            Write-Output "Deleting binary: '$dllfile' with wrong hash: '$hash'"
            del $dllfile
        }
    }

    Write-Output "Downloading nuget file: '$moduleurl' -> '$nugetfile'"
    Invoke-WebRequest -UseBasicParsing $moduleurl -OutFile $nugetfile

    [string] $zipfile = "$($shortname).zip"

    if (Test-Path $zipfile) {
        Write-Output "Deleting old zipfile: '$zipfile'"
        del $zipfile
    }

    Write-Output "Renaming: '$nugetfile' -> '$zipfile'"
    ren $nugetfile $zipfile

    if (Test-Path $shortname) {
        Write-Output "Deleting old folder: '$shortname'"
        rd -Recurse -Force $shortname
    }

    Write-Output "Extracting: '$zipfile' -> '$shortname'"
    Expand-Archive $zipfile $shortname

    [string] $path = Join-Path $shortname (Join-Path "lib" (Join-Path "netstandard*" "*.dll"))
    Write-Output "Searching path: '$path'"
    if (Test-Path $path) {
        $dllpath = dir $path | Sort-Object FullName -Descending | Select-Object -First 1

        Write-Output "Moving: '$dllpath' -> '$dllfile'"
        move $dllpath $dllfile
    }
    else {
        Write-Error "Didn't find any netstandard dllfile."
        exit 1
    }

    [string] $hash = (Get-FileHash $dllfile).Hash
    if ($hash -ne $dllhash) {
        Write-Error "Couldn't download, wrong hash: '$dllfile': '$hash'"
        exit 1
    }

    [string] $dllpath = Join-Path (pwd).Path $dllfile
    Write-Output "Importing dllfile: '$dllpath'"
    Import-Module $dllpath
}

function Log([string] $message, $color) {
    if ($color) {
        Write-Host $message -f $color
    }
    else {
        Write-Host $message -f Green
    }
}

Main
