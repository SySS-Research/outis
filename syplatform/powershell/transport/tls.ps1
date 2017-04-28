
function Transport-Tls-Open {
    <#
        .SYNOPSIS
        runs TLS on the socket stream given
        .PARAMETER SocketStream
        socket stream to use, e.g. a TCP connection
        .PARAMETER ServerCertFingerprint
        fingerprint of the server certificate
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.IO.Stream]
        $SocketStream,

        [String]
        $ServerCertFingerprint
    )

    $Callback = {
        param($sender, $cert, $chain, $errors)
        
        $fp = [Convert]::FromBase64String($ServerCertFingerprint)
        $rsa = $cert.PublicKey.Key.ToXmlString($false).ToCharArray()
        $sha = New-Object Security.Cryptography.SHA512Managed
        if( @(Compare-Object $sha.ComputeHash($rsa) $fp -SyncWindow 0).Length -ne 0){
            return $false
        }        
        return $true
    }

    $tlsStream = New-Object System.Net.Security.SslStream $SocketStream,$true,$Callback
    # TODO: catch certificate errors here, else lots of errors
    $tlsStream.AuthenticateAsClient("outis")
    $reader = New-Object System.IO.BinaryReader($tlsStream)
    $writer = New-Object System.IO.BinaryWriter($tlsStream)

    return New-Object -TypeName PSObject -Property @{
       'tlsStream' = $tlsStream
       'reader' = $reader
       'writer' = $writer
    }

}

function Transport-Tls-Close([PSObject] $obj) {
    $obj.reader.Close()
    $obj.writer.Close()
    $obj.tlsStream.Close()
}


function Transport-Tls-Receive([PSObject] $obj, [Int32] $bytestoread) {
    $numb = 0
	$buffer = New-Object byte[]($bytestoread)
	while ($numb -lt $bytestoread) {
		$numb += $obj.reader.Read($buffer, $numb, $bytestoread-$numb)
	}		
	return $buffer
}

function Transport-Tls-Send([PSObject] $obj, [byte[]] $data) {
    $obj.writer.Write($data)
}

