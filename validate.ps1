Set-StrictMode -v latest
$ErrorActionPreference = "Stop"

[char[]] $environmentSeparators = ",", "`n", "`r"

function Main()
{
    if (!$env:EmailReceiver)
    {
        Log ("Environment variable EmailReceiver not set!") Red
    }
    if (!$env:EmailSender)
    {
        Log ("Environment variable EmailSender not set!") Red
    }
    if (!$env:EmailUsername)
    {
        Log ("Environment variable EmailUsername not set!") Red
    }
    if (!$env:EmailPassword)
    {
        Log ("Environment variable EmailPassword not set!") Red
    }
    if (!$env:EmailServer)
    {
        Log ("Environment variable EmailServer not set!") Red
    }
    if (!$env:EmailReceiver -or !$env:EmailSender -or !$env:EmailUsername -or !$env:EmailPassword -or !$env:EmailServer)
    {
        exit 1
    }


    if ($env:AzureTenantIds -and $env:AzureClientIds -and $env:AzureClientSecrets)
    {
        [string[]] $tenantIds = $env:AzureTenantIds.Split($environmentSeparators, [StringSplitOptions]::RemoveEmptyEntries)
        [string[]] $clientIds = $env:AzureClientIds.Split($environmentSeparators, [StringSplitOptions]::RemoveEmptyEntries)
        [string[]] $clientSecrets = $env:AzureClientSecrets.Split($environmentSeparators, [StringSplitOptions]::RemoveEmptyEntries)

        [int] $principalCount = ($tenantIds.Count,$clientIds.Count,$clientSecrets.Count | measure -Minimum).Minimum
        Log ("Got " + $principalCount + " service principals.")

        $principals = @()

        for ([int] $i = 0; $i -lt $principalCount; $i++)
        {
            $principal = New-Object PSObject
            $principal | Add-Member NoteProperty TenantId $tenantIds[$i]
            $principal | Add-Member NoteProperty ClientId $clientIds[$i]
            $principal | Add-Member NoteProperty ClientSecret $clientSecrets[$i]
            $principals += $principal
        }
    }
    else
    {
        $principals = $null
    }


    [Diagnostics.Stopwatch] $watch = [Diagnostics.Stopwatch]::StartNew()

    [string] $message = Validate-AzureResources $principals

    Log ("Done: " + $watch.Elapsed)


    if ($message.Length -gt 0)
    {
        [string] $body = "Found unsecured resources.`n`n" + $message

        Send-Email "Security Alert" $body
    }
}

function Validate-AzureResources($principals)
{
    $azureResources = @()

    if ($principals)
    {
        foreach ($principal in $principals)
        {
            $ss = $principal.clientSecret | ConvertTo-SecureString -Force -AsPlainText
            $creds = New-Object PSCredential -ArgumentList $principal.clientId, $ss

            Log ("Logging in...")
            Connect-AzAccount -ServicePrincipal -Tenant $principal.tenantId -Credential $creds | Out-Null

            $azureResources += @(Get-InsecureAzureResources)
        }
    }
    else
    {
        $azureResources += @(Get-InsecureAzureResources)
    }


    $storageAccounts = @($azureResources | % { $_.StorageAccounts } | group "SubscriptionName","ResourceGroupName","StorageAccountName")
    Log ("Total insecure storage accounts: " + $storageAccounts.Count)

    $webApps = @($azureResources | % { $_.WebApps } | group "SubscriptionName","ResourceGroup","Name","HttpsOnly","MinTlsVersion")
    Log ("Total insecure web apps: " + $webApps.Count)

    $rules = @($azureResources | % { $_.SqlServerFirewallRules } | group "SubscriptionName","ResourceGroupName","ServerName","StartIpAddress","EndIpAddress","FirewallRuleName")
    Log ("Total sqlserver firewall rules: " + $rules.Count)


    [string] $message = ""

    if ($storageAccounts.Count -gt 0)
    {
        $message += "The following " + $storageAccounts.Count + " storage accounts allow unencrypted http."
        $message += "`nSubscriptionName`tResourceGroupName`tStorageAccountName"
        foreach ($storageAccount in $storageAccounts | Sort-Object "Name")
        {
            $message += "`n" + ($storageAccount.Values -join "`t")
        }
    }

    if ($storageAccounts.Count -gt 0 -and $webApps.Count -gt 0)
    {
        $message += "`n`n"
    }

    if ($webApps.Count -gt 0)
    {
        $message += "The following " + $webApps.Count + " web apps allow broken/unencrypted http."
        $message += "`nSubscriptionName`tResourceGroupName`tWebAppName`tHttpsOnly`tMinTlsVersion"
        foreach ($webApp in $webApps | Sort-Object "Name")
        {
            $message += "`n" + ($webApp.Values -join "`t")
        }
    }

    if ($webApps.Count -gt 0 -and $rules.Count -gt 0)
    {
        $message += "`n`n"
    }

    if ($rules.Count -gt 0)
    {
        $message += "The following " + $rules.Count + " sqlserver firewall rules exists."
        $message += "`nSubscriptionName`tResourceGroupName`tServerName`tStartIpAddress`tEndIpAddress`tFirewallRuleName"
        foreach ($rule in $rules | Sort-Object "Name")
        {
            $message += "`n" + ($rule.Values -join "`t")
        }
    }

    return $message
}

function Get-InsecureAzureResources()
{
    $subscriptions = @(Get-AzSubscription | Sort-Object "Name")
    Log ("Got " + $subscriptions.Count + " subscriptions.")

    $allStorageAccounts = @()
    $allWebApps = @()
    $allRules = @()

    foreach ($subscription in $subscriptions)
    {
        [string] $subscriptionName = $subscription.Name
        Log ("Selecting subscription: '" + $subscriptionName + "'")
        Select-AzSubscription $subscriptionName | Out-Null

        $storageAccounts = @(Get-InsecureStorageAccounts)
        foreach ($storageAccount in $storageAccounts)
        {
            $storageAccount | Add-Member NoteProperty "SubscriptionName" $subscriptionName
        }
        $allStorageAccounts += $storageAccounts

        $webApps = @(Get-InsecureWebApps)
        foreach ($webApp in $webApps)
        {
            $webApp | Add-Member NoteProperty "SubscriptionName" $subscriptionName
        }
        $allWebApps += $webApps

        $rules= @(Get-SqlServerFirewallRules)
        foreach ($rule in $rules)
        {
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

function Get-InsecureStorageAccounts()
{
    Log ("Retrieving storage accounts...") Magenta
    $storageAccounts = @(Get-AzStorageAccount)
    Log ("Got " + $storageAccounts.Count + " storage accounts.") Magenta

    $insecureStorageAccounts = @($storageAccounts | ? { !$_.EnableHttpsTrafficOnly })

    if ($env:ExcludeStorageAccounts)
    {
        [string[]] $excludeStorageAccounts = $env:ExcludeStorageAccounts.Split($environmentSeparators, [StringSplitOptions]::RemoveEmptyEntries)
        $insecureStorageAccounts = @($insecureStorageAccounts | ? {
            if ($excludeStorageAccounts.Contains($_.StorageAccountName))
            {
                Log ("Excluding: '" + $_.StorageAccountName + "'")
                $false
            }
            else
            {
                $true
            }})
    }

    Log ("Insecure storage accounts: " + $insecureStorageAccounts.Count) Magenta

    return $insecureStorageAccounts
}

function Get-InsecureWebApps()
{
    Log ("Retrieving web apps...") Magenta
    $webApps = @(Get-AzWebApp)
    Log ("Got " + $webApps.Count + " web apps.") Magenta

    foreach ($webApp in $webApps)
    {
        $minTlsVersion = (Get-AzResource -ResourceType "Microsoft.Web/sites/config" -ResourceGroupName $webApp.ResourceGroup -ResourceName ($webApp.Name + "/web") -ApiVersion "2018-02-01").Properties.minTlsVersion

        $webApp | Add-Member NoteProperty "MinTlsVersion" $minTlsVersion
    }

    $insecureWebApps = @($webApps | ? { !$_.HttpsOnly -or $_.minTlsVersion -ne "1.2" })

    if ($env:ExcludeWebApps)
    {
        [string[]] $excludeWebApps = $env:ExcludeWebApps.Split($environmentSeparators, [StringSplitOptions]::RemoveEmptyEntries)
        $insecureWebApps = @($insecureWebApps | ? {
            if ($excludeWebApps.Contains($_.Name))
            {
                Log ("Excluding: '" + $_.Name + "'")
                $false
            }
            else
            {
                $true
            }})
    }

    Log ("Insecure web apps: " + $insecureWebApps.Count) Magenta

    return $insecureWebApps
}

function Get-SqlServerFirewallRules()
{
    Log ("Retrieving sqlserver firewall rules...") Magenta
    $rules = @(Get-AzSqlServer | Get-AzSqlServerFirewallRule | ? { $_ })
    Log ("Got " + $rules.Count + " sqlserver firewall rules.") Magenta

    if ($env:ExcludeSqlServerFirewallRules)
    {
        [string[]] $excludeSqlServerFirewallRules = $env:ExcludeSqlServerFirewallRules.Split($environmentSeparators, [StringSplitOptions]::RemoveEmptyEntries)

        $exclude = $excludeSqlServerFirewallRules | % {
            [string[]] $tokens = $_.Split(":")
            if ($tokens.Length -ne 3)
            {
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
                })
            {
                Log ("Excluding: '" + $_.ResourceGroupName + "', '" + $_.ServerName + "', " + $_.StartIpAddress + "-" + $_.EndIpAddress + ", '" + $_.FirewallRuleName + "'")
                return $false
            }

            return $true
            })
    }

    Log ("SqlServer firewall rules: " + $rules.Count) Magenta

    return $rules
}

function Send-Email([string] $subject, [string] $body)
{
    [string] $emailReceiver = $env:EmailReceiver
    [string] $emailSender = $env:EmailSender
    [string] $emailUsername = $env:EmailUsername
    [string] $emailPassword = $env:EmailPassword
    [string] $smtpServer = $env:EmailServer

    $ss = $emailPassword | ConvertTo-SecureString -Force -AsPlainText
    $creds = New-Object PSCredential -ArgumentList $emailUsername, $ss

    Log ("To:          '" + $emailReceiver + "'")
    Log ("From:        '" + $emailSender + "'")
    Log ("SmtpServer:  '" + $smtpServer + "'")
    Log ("Subject:     '" + $subject + "'")
    Log ("Body:        '" + $body + "'")

    Log ("Sending email.")
    Send-MailMessage -To $emailReceiver -From $emailSender -Subject $subject -Body $body -SmtpServer $smtpServer -UseSsl -Credential $creds
}

function Log([string] $message, $color)
{
    if ($color)
    {
        Write-Host $message -f $color
    }
    else
    {
        Write-Host $message -f Green
    }
}

Main
