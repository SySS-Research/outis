
function Print-Message($text) {
    if ($LOGFILE) {
        Add-content $LOGFILE -value "[+] [$(Get-Date)] $($text)"
    }
    Write-Host "[+] $($text)"
}

function Print-Error($text) {
    if ($LOGFILE) {
        Add-content $LOGFILE -value "[-] [$(Get-Date)] ERROR: $($text)"
    }
    Write-Host "[-] ERROR: $($text)"
}

$ADDTOSCRIPTS += @"
function Print-Message(`$text) {
    if (`$LOGFILE) {
        Add-content `$LOGFILE -value "[+] [`$(Get-Date)] `$(`$text)"
    }
}
function Print-Error(`$text) {
    if (`$LOGFILE) {
        Add-content `$LOGFILE -value "[-] [`$(Get-Date)] ERROR: `$(`$text)"
    }
}
"@