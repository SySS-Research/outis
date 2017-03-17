function Transport-Dns-Open {
    <#
        .SYNOPSIS
        connects using DNS as protocol
        .PARAMETER Zone
        DNS zone to use for the connection
        .PARAMETER DnsServer
        host of the dns server to use
        .PARAMETER timeout
        timeout in seconds for each DNS query
        .PARAMETER retries
        retries for each failed query
    #>
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $Zone,

        [Parameter(Mandatory=$false)]
        [String]
        $DnsServer = "",

        [Parameter(Mandatory=$false)]
        [Int32]
        $timeout = 2,

        [Parameter(Mandatory=$false)]
        [Int32]
        $retries = 0
    )

    $connection = New-Object -TypeName PSObject -Property @{
       'zone' = $Zone
       'dnsServer' = $DnsServer
       'dnstype' = $NULL
       'timeout' = $timeout
       'retries' = $retries
       'sendqueue' = $NULL
       'readqueue' = $NULL
       'requestid' = Get-Random
    }
    $dnstypefound=$false

    foreach ($type in @('TXT','CNAME','MX','AAAA','A')) {
        $connection.dnstype = $type
        $res = Transport-Dns-Intern-SendQuery -Connection $connection -Content 'pingquery'

        $res = New-Object String($res,0,$res.Length)
        Write-Host $res
        if ($res -eq "pong") {
            $dnstypefound=$true
            Write-Output "Connection with DNS type $($connection.dnstype) possible"
            #break # TODO: break
        }
    }

    if(!$dnstypefound) {
        Write-Output 'Error: failed to find dnstype'
        exit(1)
    } else {
        Write-Output "Connection with DNS type $($connection.dnstype) possible"
    }

    return $connection

}

function Transport-Dns-Intern-SendQuery {
    <#
        .SYNOPSIS
        sends a single DNS query and records the result
        .PARAMETER Connection
        DNS connection details
        .PARAMETER Content
        data to send using the connection
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]
        $Connection,

        [Parameter(Mandatory=$true)]
        [String]
        $Content
    )

    if (($Content.Length -gt 250) -or ($Content.Length -lt 1)) {
        return $NULL
    }

    $res=$NULL
    $timeoutstr=""
    if ($Connection.timeout -ne 2) {
        $timeoutstr=" -timeout=$($Connection.timeout)"
    }

    $r=$Connection.requestid++
    $data=Transport-Dns-Intern-ConvertToHostname($Content)
    $data="$($data).r$($r).$($Connection.zone)."

    for ($t=0; $t -le $Connection.retries; $t++) {
        $command="nslookup -type=$($Connection.dnstype)$($timeoutstr) $($data) $($Connection.dnsServer)"
        Write-Host $command
        $c=[string](IEX $command 2>&1)
        Write-Host ">>>>" $c "<<<<"

        if ($Connection.dnstype -eq 'TXT') {
            if ($c.Contains('"')) {
                $res = [Convert]::FromBase64String($c.Split('"')[1])
                break
            }
        } elseif ($Connection.dnstype -eq "MX") {
            if ($c.Contains('mail')) {
                # TODO: does not work yet !!!
                $res = ([string](($c[($c.IndexOf("mail exchanger = ") + 17)..$c.Length] -join '').split("`n")[0])).replace($Connection.zone,"").replace(".","").replace("`n","").replace(" ","").Trim()
                $res = Transport-Dns-Intern-ConvertHexToByteArray($res)
                break
            }
        }

        # TODO: break this loop if answer
    }

    # TODO: parsing, everything
    return $res
}


function Transport-Dns-Intern-ConvertToHostname($data) {
    return ([System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($data)).split("-") -join "")
}

function Transport-Dns-Intern-ConvertHexToByteArray($hex) {
    # TODO: does not work yet !!!
    $bytes = New-Object byte[$hex.Length / 2];
    for ($i=0; i<$hex.Length; i += 2) {
        bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
    }
    return bytes
}

function Transport-Dns-Close([PSObject] $obj) {
    # TODO: ...
}


function Transport-Dns-Receive([PSObject] $obj, [Int32] $bytestoread) {
    # TODO: ...
}

function Transport-Dns-Send([PSObject] $obj, $data) {
    # TODO: ...
}

$DNSZONE = "zfs.sy.gs"
$DNSSERVER = "10.201.1.83"
$TIMEOUT = $NULL
$RETRIES = $NULL

Transport-Dns-Open -Zone "$($DNSZONE)" -DnsServer "$($DNSSERVER)"
