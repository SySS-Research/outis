$Source = @"
public class DnsStream : System.IO.Stream {

  private System.Collections.Queue receivequeue = null;

  private System.Management.Automation.PSObject dnsconnection;
  private System.Management.Automation.ScriptBlock sendqueryfunction;

  public DnsStream(System.Management.Automation.PSObject dnsconnection,
      System.Management.Automation.ScriptBlock sendqueryfunction) : base() {
    this.dnsconnection = dnsconnection;
    this.sendqueryfunction = sendqueryfunction;
    this.receivequeue = System.Collections.Queue.Synchronized( new System.Collections.Queue() );
  }

  public override bool CanRead {
    get { return true; }
  }

  public override bool CanSeek {
    get { return false; }
  }

  public override bool CanWrite {
    get { return true; }
  }

  public override void Flush() {
  }

  public override long Length {
    get {
      System.Console.WriteLine("DnsStream.Length called");
      return 0;
    }
  }

  public override long Position {
    get {
        System.Console.WriteLine("DnsStream.Position.get called");
        return 0;
    }
    set {
        System.Console.WriteLine("DnsStream.Position.set called");
        return;
    }
  }

  public override void SetLength(long value) {
    System.Console.WriteLine("DnsStream.SetLength called");
    return;
  }

  public override int Read(byte[] buffer, int offset, int count) {
    if (receivequeue.Count == 0) {
        this.sendqueryfunction.Invoke(this.dnsconnection, null, 0, 0, receivequeue);
    }
    if (receivequeue.Count < count) {
        count = receivequeue.Count;
    }
    for (int i=0; i<count; ++i) {
        buffer[offset+i] = (byte) receivequeue.Dequeue();
    }
    return count;
  }

  public bool HasData() {
    return receivequeue.Count > 0;
  }

  public int ReadSync(byte[] buffer, int offset, int count) {
    while (receivequeue.Count == 0);
    if (receivequeue.Count < count) {
        count = receivequeue.Count;
    }
    for (int i=0; i<count; ++i) {
        buffer[offset+i] = (byte) receivequeue.Dequeue();
    }
    return count;
  }

  public override void Write(byte[] buffer, int offset, int count) {
    this.sendqueryfunction.Invoke(this.dnsconnection, buffer, offset, count, receivequeue);
  }

  public override long Seek(long offset, System.IO.SeekOrigin loc) {
    System.Console.WriteLine("DnsStream.Seek called");
    return -1;
  }
}
"@

Add-Type -TypeDefinition $Source

$COMMAND_NODATA = [System.Text.Encoding]::UTF8.GetBytes("NOD")
$COMMAND_ENDOFCONNECTION = [System.Text.Encoding]::UTF8.GetBytes("EOC")
$COMMAND_PING = [System.Text.Encoding]::UTF8.GetBytes("PIN")
$COMMAND_PONG = [System.Text.Encoding]::UTF8.GetBytes("PON")


function Transport-Dns-Open {
    <#
        .SYNOPSIS
        connects using DNS as protocol
        .PARAMETER Zone
        DNS zone to use for the connection
        .PARAMETER DnsServer
        host of the dns server to use
        .PARAMETER timeout
        timeout in seconds for each DNS query
        .PARAMETER retries
        retries for each failed query
    #>
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $Zone,

        [Parameter(Mandatory=$false)]
        [String]
        $DnsServer = "",

        [Parameter(Mandatory=$false)]
        [Int32]
        $timeout = 2,

        [Parameter(Mandatory=$false)]
        [Int32]
        $retries = 0
    )

    $connection = New-Object -TypeName PSObject -Property @{
       'zone' = $Zone
       'dnsServer' = $DnsServer
       'dnstype' = $NULL
       'timeout' = $timeout
       'retries' = $retries
       'stream' = $NULL
       'requestid' = Get-Random
    }
    $dnstypefound=$false

    foreach ($type in @('TXT','CNAME','MX','AAAA','A')) {
        $connection.dnstype = $type
        $res = Transport-Dns-Intern-SendQuery -Connection $connection -Content $COMMAND_PING -Commandflag $true

        $leng = $res.Length - 1
        $res = New-Object String($res,1,$leng)
        #Print-Debug "[DNS] testresponse = $($res)"
        if ($res.StartsWith("PON")) { # TODO: replace with $COMMAND_PONG somehow
            $dnstypefound=$true
            #Print-Message "[DNS] Connection with DNS type $($connection.dnstype) possible"
            break
        }
    }

    if(!$dnstypefound) {
        Print-Error "[DNS] failed to find dnstype for connection"
        exit(1)
    } else {
        Print-Message "[DNS] Connection with DNS type $($connection.dnstype) possible"
    }

    $sendqueryfunction = get-content Function:\Transport-Dns-Intern-SendAll

    $dnsstream = New-Object DnsStream($connection, $sendqueryfunction)
    $connection.stream = $dnsstream

    return $connection
}

function Transport-Dns-Intern-SendQuery {
    <#
        .SYNOPSIS
        sends a single DNS query and records the result
        .PARAMETER Connection
        DNS connection details
        .PARAMETER Content
        data to send using the connection
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]
        $Connection,

        [Parameter(Mandatory=$true)]
        [byte[]]
        $Content,

        [Parameter(Mandatory=$false)]
        [bool]
        $Commandflag = $false
    )

    if (($Content.Length -gt 100) -or ($Content.Length -lt 1)) {
        return $NULL
    }

    $data = New-Object byte[]($Content.Length+1)
    if ($Commandflag) {
        $data[0] = [byte] 0x43
    } else {
        $data[0] = [byte] 0x44
    }
    for ($i=0; $i -lt $Content.Length; ++$i) {
	    $data[1+$i] = $Content[$i]
	}

    $res=$NULL
    $timeoutstr=""
    if ($Connection.timeout -ne 2) {
        $timeoutstr=" -timeout=$($Connection.timeout)"
    }

    $r=$Connection.requestid++
    $data=Transport-Dns-Intern-ConvertToHostname($data)
    $data="$($data).r$($r).$($Connection.zone)."
    #Print-Debug "[DNS] request-number =" $r

    for ($t=0; $t -le $Connection.retries; $t++) {
        $command="nslookup -type=$($Connection.dnstype)$($timeoutstr) $($data) $($Connection.dnsServer)"
        Print-Debug "running command: $($command)"
        $c=[string](IEX $command 2>&1)
        Print-Debug "result: >>>> $($c) <<<<"

        if ($Connection.dnstype -eq 'TXT') {
            if ($c.Contains('"')) {
                $res = [Convert]::FromBase64String($c.Split('"')[1])
                break
            }
        } elseif ($Connection.dnstype -eq "CNAME") {
            if ($c.Contains('canonical')) {
                $res = [string](($c[($c.IndexOf("canonical name =") + 17)..$c.Length] -join '').split("`n")[0])
                $res = Transport-Dns-Intern-ConvertFromHostname $res $Connection.zone
                break
            }
        } elseif ($Connection.dnstype -eq "MX") {
            if ($c.Contains('mail')) {
                $res = [string](($c[($c.IndexOf("mail exchanger = ") + 17)..$c.Length] -join '').split("`n")[0])
                $res = Transport-Dns-Intern-ConvertFromHostname $res $Connection.zone
                break
            }
        } elseif ($Connection.dnstype -eq "AAAA") {
            if ($c.Contains('Name') -and $c.Contains('Address')) {
                $res = ([regex]"\s+").Split($c)[-2]
                $res = Transport-Dns-Intern-ConvertFromIPv6 $res
                break
            }
        } elseif ($Connection.dnstype -eq "A") {
            if ($c.Contains('Name') -and $c.Contains('Address')) {
                $res = ([regex]"\s+").Split($c)[-2]
                $res = Transport-Dns-Intern-ConvertFromIP $res
                break
            }
        }

        # TODO: break this loop if answer
    }

    # no success, print error message
    if (!$res) {
        Print-Error "[DNS] no answer received"
        return $NULL
    }

    # command sequence
    if ($res[0] -eq [byte] 0x43) {
        # TODO: command parsing
        #Print-Debug "command received"
        return $res
    } elseif (($res[0] -ge [byte] 0x44) -and ($res[0] -le [byte] 0x44 + 15)) {
        return $res
    } else {
        Print-Error "[DNS] invalid DNS command byte received"
        return $NULL
    }

    # TODO: parsing, everything
    return $res
}

function Transport-Dns-Intern-SendAll {
    <#
        .SYNOPSIS
        send all data as DNS queries and records the results
        .PARAMETER Connection
        DNS connection details
        .PARAMETER Content
        data to send using the connection
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]
        $Connection,

        [Parameter(Mandatory=$true)]
        #TODO: [byte[]] but seems to create problems with null reference?
        $Content,

        [Parameter(Mandatory=$true)]
        [Int32]
        $Offset,

        [Parameter(Mandatory=$true)]
        [Int32]
        $Count,

        [Parameter(Mandatory=$true)]
        [object]
        $Resultqueue
    )

    $Commandflag = $false
    if($Count -lt 1) {
        $Content = $COMMAND_NODATA
        $Offset = 0
        $Count = $Content.Length
        $Commandflag = $true
    }

    if ($Offset + $Count -gt $Content.Length) {
        Print-Error "[DNS] Transport-Dns-Intern-SendAll: wrongly addressed send array"
    }

    $blocksize = 100
    $blockstosend = 0
    while($blockstosend * $blocksize -lt $Count) {
        $blockstosend++
    }

    for($i=0; $i -lt $blockstosend; ++$i) {
        $start = $i * $blocksize + $Offset
        $size = [math]::min($blocksize, $Offset + $Count - $start)
        $bytes = New-Object byte[]($size);
        for($j=0; $j -lt $size; ++$j) {
            $bytes[$j] = $Content[$start + $j]
        }
        $res = Transport-Dns-Intern-SendQuery -Connection $Connection -Content $bytes -Commandflag $Commandflag
        if (($res) -and ($res[0] -ne [byte] 0x43)) { # not a command packet
            $paddingbytes = $res[0] - [byte] 0x44
            $reslen = ($res.Length) - $paddingbytes
            for($j=1; $j -lt $reslen; ++$j) {
                $Resultqueue.Enqueue([byte]$res[$j])
            }
        }
    }
}

function Transport-Dns-Intern-ConvertToHostname([byte[]]$data) {
    $res = ""
    $sdata = ([System.BitConverter]::ToString($data).split("-") -join "")
    for ($i=0;$i -lt $sdata.Length; ++$i) {
        $res += $sdata[$i]
        if ((($i+1) % 60 -eq 0) -and (($i+1) -ne $sdata.Length)) {
            $res += '.'
        }
    }
    return $res
}

function Transport-Dns-Intern-ConvertFromHostname([string]$hostname, [string]$zone) {
    $lidx = $hostname.LastIndexOf($zone)
    $x = $hostname.Substring(0,$lidx)
    if (($x + $zone) -ne $hostname) {
        Print-Error "[DNS] hostname does not end with zone"
        return $NULL
    }

    $x = $x -replace '\.', ''

    return Transport-Dns-Intern-ConvertHexToBytes $x
}

function Transport-Dns-Intern-ConvertHexToBytes([string]$hexstring) {
    $bytes = New-Object byte[]($hexstring.Length / 2);
    for ($i=0; $i -lt $hexstring.Length; $i += 2) {
        $bytes[$i / 2] = [System.Convert]::ToByte($hexstring.Substring($i, 2), 16);
    }
    return $bytes
}

function Transport-Dns-Intern-ConvertFromIPv6([string]$ipv6) {
    $y = ""
    foreach($x in $ipv6.Split(':')) {
        while ($x.Length -lt 4) {
            $x = '0' + $x
        }
        $y += $x
    }
    return Transport-Dns-Intern-ConvertHexToBytes $y
}

function Transport-Dns-Intern-ConvertFromIP([string]$ip) {
    return $ip.Split(".") |%{[Convert]::ToInt32($_)}
}

function Transport-Dns-Close([PSObject] $obj) {
    # TODO: ...
}


function Transport-Dns-Receive([PSObject] $obj, [UInt32] $bytestoread) {
    $bytes = New-Object byte[]($bytestoread);
    $numb = 0
    while ($numb -lt $bytestoread) {
        $numb += $obj.stream.Read($bytes, $numb, $bytestoread-$numb)
    }
    return $bytes
}

function Transport-Dns-Send([PSObject] $obj, [byte[]] $data) {
    $obj.stream.Write($data, 0, $data.Length)
}
