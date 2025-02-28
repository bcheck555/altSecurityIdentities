#X509:<I>C=US,O=U.S.Government,OU=DoD,OU=PKI,CN=DOD ID CA-70<SR>efcdab

$servers = 'dc01','dc02','dc03'
#Filter SYSTEM log for Kerberos KDC ID 39 from the past 24 hours
$xmlQuery = @'
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center'] and (EventID=39) and TimeCreated[timediff(@SystemTime) &lt;= 86400000]]]</Select>
  </Query>
</QueryList>
'@

#pull the events from all servers
foreach ($server in $servers) {
    if ((Get-WinEvent -ErrorAction SilentlyContinue -ComputerName $server -FilterXml $xmlQuery).count -eq 0) {
        Write-Host "No Records found for $server."
    } else {
        #grab events
        $messages = Get-WinEvent -ComputerName $server -FilterXml $xmlQuery
        #process events
        foreach ($message in $messages) {
            #convert to xml
            [xml]$event = $message.ToXml()
            #create the object
            $event.Event.EventData.Data | foreach-object -Begin {
                $property = @{}
                } -Process {
                $property.add($_.name,$_.'#text')
                } -end {
                 $object = New-Object -TypeName PSObject -Property $property
                }
            $account = $object.AccountName
            $issuer = $object.Issuer
            #reverse serial
            $reverseSerial = $object.SerialNumber -split '(..)' -ne ''
            $reverseSerial = $reverseSerial[-1..-$reverseSerial.Length] -join ''
            #create altsecid
            $altSecurityIdentities = "X509:<I>C=US,O=U.S. Government,OU=DoD,OU=PKI,CN=$issuer<SR>$reverseSerial"
            #Output
            $server
            $account
            $issuer
            $object.SerialNumber
            $altSecurityIdentities
            Write-Host ""
            #FixIt
            #Get-ADUser -Filter 'SAMAccountName -eq $account' | Set-ADUser -Replace @{'altSecurityIdentities'=$altSecurityIdentities}
        }
    }
}
