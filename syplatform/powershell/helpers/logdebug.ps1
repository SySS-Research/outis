
$LOGFILE = "$($env:TEMP)\syssspy.log"

function Print-Debug($text) {
    Add-content $LOGFILE -value "[D] [$(Get-Date)] $($text)"
    Write-Host "[D] $($text)"
}

Print-Debug("DEBUGGING is active, writing to debug file $($LOGFILE)")

$ADDTOSCRIPTS += @"
`$LOGFILE = "$($LOGFILE)"
function Print-Debug(`$text) {
    Add-content `$LOGFILE -value "[D] [`$(Get-Date)] `$(`$text)"
}
"@