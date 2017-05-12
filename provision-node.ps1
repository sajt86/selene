#################################################################################################################################
#  Name        : Configure-WinRM.ps1                                                                                            #
#                                                                                                                               #
#  Description : Configures the WinRM on a local machine                                                                        #
#                                                                                                                               #
#  Arguments   : HostName, specifies the FQDN of machine or domain                                                           #
#################################################################################################################################

param
(
    [Parameter(Mandatory = $true)]
    [string] $HostName,

    [Parameter(Mandatory = $true)]
    [string] $ServerMode
)

#################################################################################################################################
#                                             Helper Functions                                                                  #
#################################################################################################################################

function Delete-WinRMListener
{
    try
    {
        $config = Winrm enumerate winrm/config/listener
        foreach($conf in $config)
        {
            if($conf.Contains("HTTPS"))
            {
                Write-Verbose "HTTPS is already configured. Deleting the exisiting configuration."
    
                winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
                break
            }
        }
    }
    catch
    {
        Write-Verbose -Verbose "Exception while deleting the listener: " + $_.Exception.Message
    }
}

function Configure-WinRMHttpsListener
{
    param([string] $HostName,
          [string] $port)

    # Delete the WinRM Https listener if it is already configured
    Delete-WinRMListener

    # Create a test certificate
    $thumbprint = (Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=" + $hostname } | Select-Object -Last 1).Thumbprint
    if(-not $thumbprint)
    {
	# makecert ocassionally produces negative serial numbers
	# which golang tls/crypto <1.6.1 cannot handle
	# https://github.com/golang/go/issues/8265
        $serial = Get-Random
        .\makecert -r -pe -n CN=$hostname -b 01/01/2012 -e 01/01/2022 -eku 1.3.6.1.5.5.7.3.1 -ss my -sr localmachine -sky exchange -sp "Microsoft RSA SChannel Cryptographic Provider" -sy 12 -# $serial
        $thumbprint=(Get-ChildItem cert:\Localmachine\my | Where-Object { $_.Subject -eq "CN=" + $hostname } | Select-Object -Last 1).Thumbprint

        if(-not $thumbprint)
        {
            throw "Failed to create the test certificate."
        }
    }    

    $response = cmd.exe /c .\winrmconf.cmd $hostname $thumbprint
}

function Add-FirewallException
{
    param([string] $port)

    # Delete an exisitng rule
    netsh advfirewall firewall delete rule name="Windows Remote Management (HTTPS-In)" dir=in protocol=TCP localport=$port

    # Add a new firewall rule
    netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=$port
}


#################################################################################################################################
#                                              Configure WinRM                                                                  #
#################################################################################################################################

$winrmHttpsPort=5986

# The default MaxEnvelopeSizekb on Windows Server is 500 Kb which is very less. It needs to be at 8192 Kb. The small envelop size if not changed
# results in WS-Management service responding with error that the request size exceeded the configured MaxEnvelopeSize quota.
winrm set winrm/config '@{MaxEnvelopeSizekb = "8192"}'

# Configure https listener
Configure-WinRMHttpsListener $HostName $port

# Add firewall exception
Add-FirewallException -port $winrmHttpsPort

#################################################################################################################################
#################################################################################################################################

& .\install-chrome.ps1
& .\install-java.ps1


[System.IO.Directory]::CreateDirectory("C:\Selenium\") 

Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::ExtractToDirectory("SeleniumServerPackage.zip","C:\Selenium")

if($ServerMode -eq "Hub")
{
    #Start up selenium hub
    Start-Process -FilePath "c:\Program Files\Java\jre1.8.0_131\bin\java.exe" -ArgumentList "-jar C:\Selenium\HubPackage\selenium-server-standalone-3.4.0.jar","-role hub"
}
else
{
    Start-Process -FilePath "c:\Program Files\Java\jre1.8.0_131\bin\java.exe" -ArgumentList "-Dwebdriver.ie.driver=C:\Selenium\HubPackage\IEDriverServer.exe","-Dwebdriver.chrome.driver=C:\Selenium\HubPackage\chromedriver.exe","-jar C:\Selenium\HubPackage\selenium-server-standalone-3.4.0.jar","-role node","-hub http://sel-master-0.westeurope.cloudapp.azure.com:4444"
}

#firewall rule
New-NetFirewallRule -DisplayName SeleniumIN -LocalAddress "10.0.0.0/24" -Protocol Any
New-NetFirewallRule -DisplayName SeleniumOUT -LocalAddress "10.0.0.0/24" -Protocol Any -Direction Outbound

#disable ie enhanced security configuration
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
Stop-Process -Name Explorer