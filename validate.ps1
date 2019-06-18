Set-StrictMode -v latest
$ErrorActionPreference = "Stop"

function Main()
{
    if (!$env:EmailReceiver)
    {
        Log ("Environment variable EmailReceiver not set!") Red
        exit 1
    }
    if (!$env:EmailSender)
    {
        Log ("Environment variable EmailSender not set!") Red
        exit 1
    }
    if (!$env:EmailUsername)
    {
        Log ("Environment variable EmailUsername not set!") Red
        exit 1
    }
    if (!$env:EmailPassword)
    {
        Log ("Environment variable EmailPassword not set!") Red
        exit 1
    }


    if ($env:TenantIds -and $env:ClientIds -and $env:ClientSecrets)
    {
        [string[]] $tenantIds = $env:TenantIds.Split(",")
        [string[]] $clientIds = $env:ClientIds.Split(",")
        [string[]] $clientSecrets = $env:ClientSecrets.Split(",")

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

    $webApps = @($azureResources | % { $_.WebApps } | group "SubscriptionName","ResourceGroup","Name")
    Log ("Total insecure web apps: " + $webApps.Count)


    [string] $message = ""

    if ($storageAccounts.Count -gt 0)
    {
        $message += "The following " + $storageAccounts.Count + " storage accounts allow unencrypted http."
        $message += "`nSubscriptionName`tResourceGroupName`tStorageAccountName"
        foreach ($storageAccount in $storageAccounts | sort "Name")
        {
            $message += "`n" + $storageAccount.Values[0] + "`t" + $storageAccount.Values[1] + "`t" + $storageAccount.Values[2]
        }
    }

    if ($storageAccounts.Count -gt 0 -and $webApps.Count -gt 0)
    {
        $message += "`n`n"
    }

    if ($webApps.Count -gt 0)
    {
        $message += "The following " + $webApps.Count + " web apps allow unencrypted http."
        $message += "`nSubscriptionName`tResourceGroupName`tWebAppName"
        foreach ($webApp in $webApps | sort "Name")
        {
            $message += "`n" + $webApp.Values[0] + "`t" + $webApp.Values[1] + "`t" + $webApp.Values[2]
        }
    }

    return $message
}

function Get-InsecureAzureResources()
{
    $subscriptions = @(Get-AzSubscription | sort "Name")
    Log ("Got " + $subscriptions.Count + " subscriptions.")

    $allStorageAccounts = @()
    $allWebApps = @()

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
    }

    $azureResources = New-Object PSObject
    $azureResources | Add-Member NoteProperty "StorageAccounts" $allStorageAccounts
    $azureResources | Add-Member NoteProperty "WebApps" $allWebApps

    return $azureResources
}

function Get-InsecureStorageAccounts()
{
    $storageAccounts = @(Get-AzStorageAccount)
    Log ("Got " + $storageAccounts.Count + " storage accounts.") Magenta

    $insecureStorageAccounts = @($storageAccounts | ? { !$_.EnableHttpsTrafficOnly })

    if ($env:ExcludeStorageAccounts)
    {
        [string[]] $excludeStorageAccounts = $env:ExcludeStorageAccounts.Split(",")
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
    $webApps = @(Get-AzWebApp)
    Log ("Got " + $webApps.Count + " web apps.") Magenta

    $insecureWebApps = @($webApps | ? { !$_.HttpsOnly })

    if ($env:ExcludeWebApps)
    {
        [string[]] $excludeWebApps = $env:ExcludeWebApps.Split(",")
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

function Send-Email([string] $subject, [string] $body)
{
    [string] $emailReceiver = $env:EmailReceiver
    [string] $emailSender = $env:EmailSender
    [string] $emailUsername = $env:EmailUsername
    [string] $emailPassword = $env:EmailPassword
    [string] $smtpServer = "smtp.gmail.com"

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
