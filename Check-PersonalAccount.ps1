Function Check-PersonalAccount {

<#
.SYNOPSIS
    Given an SMTP address(es) will verify if they are associated with both a personal and work Microsoft account
.DESCRIPTION
    For each SMTP address
        Validate it's a fully formed SMTP address
        Accesses the o365 login page (currently https://login.microsoftonline.com)
        Gets all pertinent session data
        Uses the SMTP address in the post to the login form for the o365 login page
        Parses the response to check the following and returns the results
            1. Is this address associated with both a personal and work account?
            2. Is This address federated?
            3. The a federated gateway associated with this SMTP address (if present)
.PARAMETER mail
    The SMTP address to check
.PARAMETER O365LoginPage
    The o365 login page (currently https://login.microsoftonline.com)
.PARAMETER Proxy
    Proxy URL if needed
.PARAMETER UserAgent
    Browser user agent if needed
.EXAMPLE
    PS C:\> Check-PersonalAccount -mail "Jane.Doe@contoso.com","Jane.Doe@microsoft.com"

    mail                   PersonalAccount FederatedAccount FederatedGateway                       
    ----                   --------------- ---------------- ----------------                       
    Jane.Doe@contoso.com             False            False                                        
    Jane.Doe@microsoft.com           False             True https://msft.sts.microsoft.com/adfs/ls/
        
    Description
    -----------
    Will check the following SMTP addresses ("Jane.Doe@contoso.com","Jane.Doe@microsoft.com") verify if a personal account, an federated account, and a federated gateway exists
.NOTES
    AUTHOR: John Mello 
    CREATED : 07/31/2019 
    CREATED BECAUSE: 
        Various non O365 related apps couldn't deal with the "Is this a personal or work account prompt".
        So a method was needed to flag all users who had their corporate email address associated with a personal account
#> 


    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [Alias("email","emailaddress")]
        [string[]]$mail,

        [String]$O365LoginPage = 'https://login.microsoftonline.com',

        [String]$Proxy = '',

        [String]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393'
    )

    Begin {
        #region Functions
        function isEmailAddress($object) {  
            #Taken from Tobias Weltner @ http://powershell.com/cs/media/p/389.aspx
            ($object -as [System.Net.Mail.MailAddress]).Address -eq $object -and $object -ne $null 
        }#Function
        #endregion funtions
        
        #region variables
        #Default splat for all webactions
        $WebSplat = @{
            UseBasicParsing            = $TRUE
            MaximumRedirection         = 1000
            UseDefaultCredentials      = $TRUE
            TimeoutSec                 = 1000
            ErrorAction                = 'Stop'
            Method                     = 'GET'
            Verbose                    = $FALSE
        }#$WebSplat

        #Add other web request info as needed
        if ($Proxy) {
            $WebSplat.add('Proxy', $Proxy)
            $WebSplat.add('ProxyUseDefaultCredentials',$TRUE)
        }#if ($Proxy)
        if ($UserAgent) { $WebSplat.add('UserAgent', $UserAgent) }

        #Regexs for parsing the need form info
        #$FlowTokenRegEx = '"sFT":"(?<FlowToken>.*)","sFTName":"flowToken"'
        #$OGRequestRegEx = '"sCtx":"(?<OrginalRequest>.*)","iProductIcon"'
        #$APICanaryRegEx = '"apiCanary":"(?<apiCanary>.*)","canary"'
        $ConfigRegEx = '\$Config=(?<Config>{.*});'

        #Array of know IfExistsResult results that point to federated address with a personal account
        $DualAccountTest = @("5","6")
        #Array of know IfExistsResult results that point to either just a personal or Federated account
        #0 - Appears This is a federated only account
        #1 - Appears This is a personal only account
        $SingleAccountTest = @("0","1")

        #endregion variables
    }#begin
   Process{
        Foreach ($address in $mail) {
            Write-Verbose "$address : *** STARTING ***"
            Try {
                #Object to return for each entry
                $AddressResults = [PSCustomObject]@{
                    mail = $address
                    PersonalAccount = ''
                    FederatedAccount = ''
                    FederatedGateway = ''
                }#$AddressResults = [PSCustomObject]@
            
                Write-Verbose "$address : Verifying if a fully qualified Email addresses"
                If (-not (isEmailAddress $address)) {
                    Throw "$address email address is not valid"
                } #If (-not (isEmailAddress $address)) 

            
                Write-Verbose "$address : Requesting $O365LoginPage"
                $RedirectToFedGateway = Invoke-WebRequest $O365LoginPage -SessionVariable WebSession @WebSplat
                $CurrentPage = $RedirectToFedGateway.BaseResponse.ResponseUri.Host

                #Add the current session to all subsequent web commands
                $WebSplat.Add('WebSession', $WebSession)

                #Grab config file which will hold all the neccesary info for the login form
                #$FlowTokenResults = [regex]::Match($RedirectToFedGateway.RawContent, $FlowTokenRegEx)
                #$OGRequestrResults = [regex]::Match($RedirectToFedGateway.RawContent, $OGRequestRegEx)
                #$APICanaryResults = [regex]::Match($RedirectToFedGateway.RawContent, $APICanaryRegEx)
                Write-Verbose "$address : Parsing response for the login form info for this session"
                $ConfigResults = [regex]::Match($RedirectToFedGateway.RawContent, $ConfigRegEx)
                $ConfigFile = $ConfigResults.Groups['Config'] | ConvertFrom-Json

                #Login body using info from the current session"
                $LoginFOrm = @{
                    checkPhones                    = 'false'
                    country                        = "US"
                    flowToken                      = $ConfigFile.sFT
                    forceotclogin                  = 'false'
                    isCookieBannerShown            = 'false'
                    isExternalFederationDisallowed = 'false'
                    isFidoSupported                = 'false'
                    isOtherIdpSupported             = 'true'
                    isRemoteNGCSupported           = 'true'
                    originalRequest                = $ConfigFile.sCtx
                    username                       = $address
                }#$LoginFOrm 

                #Convert to JSON since sending it over as a hashtbale didn't work
                $LoginFOrm = $LoginFOrm | ConvertTo-Json -ErrorAction Stop

                $WebSplat.Add('Body', $LoginFOrm )
                $WebSplat.Method = 'POST'

                #Get the redirection URL to post the form to
                $Sumbit = $ConfigFile.urlGetCredentialType 

                Write-Verbose "$address : Submiting login form for this address"
                $SubmitForm = Invoke-WebRequest -Uri $Sumbit @WebSplat
                Write-Verbose "$address : Parsing login form response"

                if ($SubmitForm.StatusCode -eq 200) {
                    #TODO could be cleaned up and better research into what the various response info is
                    $FormData = $SubmitForm.Content | ConvertFrom-Json -ErrorAction Stop
                    #Check if a personal account
                    if ($FormData.IfExistsResult -in $DualAccountTest) {
                        $AddressResults.PersonalAccount = $TRUE
                    }#if ($FormData.IfExistsResult -in $PersonalAccountTest)
                    Elseif ($FormData.IfExistsResult -in $SingleAccountTest)  {
                        $AddressResults.PersonalAccount = $False
                    }#Else
                    Else {
                        Write-Warning "$address : Unhandled IfExistsResult code returned - $($FormData.IfExistsResult)"
                        $AddressResults.PersonalAccount = "UNKNOWN"
                    }#Else

                    #Check if there is a federated gateway URL
                    if ($FormData.Credentials.FederationRedirectUrl) {
                        $AddressResults.FederatedGateway = ($FormData.Credentials.FederationRedirectUrl -split "\?")[0]
                        $AddressResults.FederatedAccount = $True
                    }#if ($FormData.Credentials.FederationRedirectUrl)
                    Else {
                        $AddressResults.FederatedAccount = $False
                    }#Else

                }#if ($SubmitForm.StatusCode -eq 200)
                Else {
                    Write-Warning "$address : 200 HTTP response not recieved (actual:$($SubmitForm.StatusCode))"
                    $AddressResults.PersonalAccount = "UNKNOWN"
                    $AddressResults.FederatedGateway = "UNKNOWN"
                }#Else

            }#Try
            Catch {
                Write-Warning "$address : Issue accessing URL ($O365LoginPage). Full error below:"
                $_
                $AddressResults.PersonalAccount = "ERROR"
                $AddressResults.FederatedGateway = "ERROR"
            }#Catch

            #Clean WebSplat for resue
            #Remove the websession and body from tthe splat
            $WebSplat.remove('WebSession')
            $WebSplat.remove('Body')
            #reset the method to 'GET"
            $WebSplat.Method = 'Get'
            #Clear the websession variable
            Clear-Variable WebSession -ErrorAction Stop

            #return Results to the pipeline
            $AddressResults
            Write-Verbose "$address : *** END ***"
        }#Foreach ($address in $mail)
    }#Process

    End{} #End
}#Function Check-PersonalAccount
