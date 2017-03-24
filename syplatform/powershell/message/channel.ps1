

function Channel-Open() {
    $sendqueue = New-Object System.Collections.Generic.Queue[byte]
    $state = "RESERVED"

    return New-Object -TypeName PSObject -Property @{
       'sendqueue' = $sendqueue
       'state' = $state
    }
}

function Channel-isReserved([PSObject] $channel) {
    return ($channel.state -eq "RESERVED")
}

function Channel-setOpen([PSObject] $channel) {
    $channel.state = "OPEN"
}

function Channel-isOpen([PSObject] $channel) {
    return ($channel.state -eq "OPEN")
}

function Channel-setClosed([PSObject] $channel) {
    $channel.state = "CLOSED"
}

function Channel-isClosed([PSObject] $channel) {
    return ($channel.state -eq "CLOSED")
}

function Channel-Write([PSObject] $channel, [byte[]] $data, [UInt32] $length = $NULL) {
    if (!(Channel-isOpen $channel)) {
        Write-Host "ERROR: cannot write to not open channel"
        return
    }

    $copylen = $length
    if ($length -eq $NULL) {
        $copylen = $data.Length
    }

    for($i=0; $i -lt $copylen; ++$i) {
        $channel.sendqueue.Enqueue($data[$i])
    }
}

function Channel-ReadToSend([PSObject] $channel, [UInt32] $bytestoread) {
    # TODO: blocking if no data?
    $readlen = $bytestoread
    if ($channel.sendqueue.Count -lt $bytestoread) {
        $readlen = $channel.sendqueue.Count;
    }

    $bytes = New-Object byte[]($readlen);
    for ($i=0; $i -lt $readlen; ++$i) {
        $bytes[$i] = $channel.sendqueue.Dequeue();
    }
    return $bytes
}

function Channel-HasDataToSend([PSObject] $channel) {
    return ($channel.sendqueue.Count -gt 0)
}
