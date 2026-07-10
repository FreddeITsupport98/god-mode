$content = Get-Content -Path 'C:\Users\Admin\Documents\GitHub\god-mode\God-Mode-Windows.ps1' -Raw
$errors = $null
[System.Management.Automation.PSParser]::Tokenize($content, [ref]$errors) | Out-Null
if ($errors.Count -eq 0) {
    Write-Host 'SYNTAX OK' -ForegroundColor Green
} else {
    Write-Host ('SYNTAX FAIL (' + $errors.Count + ' errors):') -ForegroundColor Red
    foreach ($e in $errors) {
        Write-Host ('Line ' + $e.Token.StartLine + ': ' + $e.Message) -ForegroundColor Red
    }
}
