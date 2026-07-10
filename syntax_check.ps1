<#
.SYNOPSIS
    Enhanced Auto Syntax Checker & Permission Fixer for OS-Guard project scripts.
.DESCRIPTION
    Scans the project directory for .ps1 files and performs multi-layer validation:
    1. AST parse check (hard syntax errors)
    2. PSParser check (PowerShell 5.1 tokenizer - catches encoding-related parse errors)
    3. Execution test in fresh pwsh + powershell 5.1 subprocesses (runtime/parse issues)
    4. Unicode trap check (em-dash U+2014 breaks PS 5.1 parser)
    5. Regression checks (pipeline precedence, Select-Object -ExpandProperty ... -eq)
    6. Strict-Mode PropertyNotFoundException heuristic (null property access patterns)
    7. Duplicate variable declaration detection
    8. Smart bracket-in-string syntax trap (escaped brackets inside double quotes)
    9. Hardcoded path detection (C:\Users\fb, etc.)
    10. Unsafe cmdlet detection (Invoke-Expression, etc.)
    11. Alias usage detection (select, where, sort, etc.)
    12. Trailing whitespace / mixed line ending checks
    13. Missing -ErrorAction when .Property is accessed (strict-mode null safety)
    14. File encoding / BOM verification (UTF-8 without BOM is a hard ERROR for PS 5.1)
    15. Redirection operator trap check (>>> and <<< inside double-quoted strings)
    16. PowerShell 5.1 reserved operator trap check (! and & inside double-quoted strings)
    17. Unmatched braces/brackets/parentheses (stack-based parser-level check)
    18. Unbalanced quotes (single/double quote mismatch)
    19. Variable interpolation in single-quoted strings ($var inside '...')
    20. UseShellExecute missing when Verb = runAs (elevation loop bug)
    21. Mixed line endings (CRLF vs LF consistency)
    22. Non-ASCII whitespace characters (tabs, non-breaking spaces)
    23. Backtick at end of line (accidental line continuation)
    24. Auto-chmod executable permissions
    Use this as the BASE syntax check script before any deployment.
#>

param([string]$ScanDir = (Split-Path -Parent $PSScriptRoot))

$FailedFiles = @()
$ErrorFiles = @()
$Warnings = @()
$FileFailures = @{}  # key = fileName, value = array of failure messages

function Add-Failure {
    param([string]$FileName, [string]$Message, [string]$Severity = "ERROR")
    if (-not $FileFailures.ContainsKey($FileName)) { $FileFailures[$FileName] = @() }
    $FileFailures[$FileName] += "[$Severity] $Message"
    if ($Severity -eq "ERROR") {
        if ($FailedFiles -notcontains $FileName) { $FailedFiles += $FileName }
        if ($ErrorFiles -notcontains $FileName) { $ErrorFiles += $FileName }
    } else {
        if ($Warnings -notcontains $FileName) { $Warnings += $FileName }
    }
}

Write-Host "[SCAN] Checking PowerShell syntax in: $ScanDir" -ForegroundColor Cyan

$Ps1Files = Get-ChildItem -Path $ScanDir -Filter "*.ps1" -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch '_temp_' }

foreach ($File in $Ps1Files) {
    $Content = Get-Content -Raw -Path $File.FullName -ErrorAction SilentlyContinue
    if (-not $Content) { continue }
    $Lines = Get-Content -Path $File.FullName -ErrorAction SilentlyContinue
    $FileName = $File.Name
    $FilePath = $File.FullName

    # 1. AST parse check
    try {
        $AstTokens = $null
        $AstErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($Content, [ref]$AstTokens, [ref]$AstErrors)
        if ($AstErrors -and $AstErrors.Count -gt 0) {
            Write-Host "[FAIL] $FilePath" -ForegroundColor Red
            foreach ($Err in $AstErrors) {
                Write-Host "  L$($Err.Extent.StartLineNumber): $($Err.Message)" -ForegroundColor DarkRed
                Add-Failure -FileName $FileName -Message "L$($Err.Extent.StartLineNumber): $($Err.Message)" -Severity "ERROR"
            }
            continue
        }
    } catch {
        Write-Host "[ERR]  $FilePath`: $($_.Exception.Message)" -ForegroundColor Red
        Add-Failure -FileName $FileName -Message "AST parse exception: $($_.Exception.Message)" -Severity "ERROR"
        continue
    }

    # 2. PSParser check (PowerShell 5.1 tokenizer)
    # This catches encoding-related parse errors that the AST parser may miss, especially when
    # UTF-8 files without BOM are read by PowerShell 5.1 using the system ANSI code page.
    try {
        $PsParseErrors = $null
        [void][System.Management.Automation.PSParser]::Tokenize($Content, [ref]$PsParseErrors)
        if ($PsParseErrors -and $PsParseErrors.Count -gt 0) {
            Write-Host "[FAIL] $FilePath" -ForegroundColor Red
            foreach ($Err in $PsParseErrors) {
                Write-Host "  L$($Err.Token.StartLine): $($Err.Message)" -ForegroundColor DarkRed
                Add-Failure -FileName $FileName -Message "PSParser L$($Err.Token.StartLine): $($Err.Message)" -Severity "ERROR"
            }
            continue
        }
    } catch {
        Write-Host "[ERR]  $FilePath`: PSParser exception: $($_.Exception.Message)" -ForegroundColor Red
        Add-Failure -FileName $FileName -Message "PSParser exception: $($_.Exception.Message)" -Severity "ERROR"
        continue
    }

    # 3. Execution test: run the script with -HealthCheck in a fresh subprocess
    $AutoElevate = $Content -match 'Verb\s*=\s*"runas"|IsInRole\(\$Role\)'
    if ($Content -match '\[switch\]\$HealthCheck' -and -not $AutoElevate) {
        try {
            $proc = Start-Process -FilePath "pwsh" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $FilePath, "-HealthCheck") -PassThru -WindowStyle Hidden
            $null = $proc | Wait-Process -Timeout 15 -ErrorAction SilentlyContinue
            if ($proc.HasExited -and $proc.ExitCode -ne 0) {
                Write-Host "[EXEC-WARN] $FileName - pwsh execution test returned non-zero ($($proc.ExitCode))." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "pwsh execution test returned non-zero exit code $($proc.ExitCode)" -Severity "WARN"
            } elseif (-not $proc.HasExited) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                Write-Host "[EXEC-WARN] $FileName - pwsh execution test timed out after 15s (likely elevation or interactive)." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "pwsh execution test timed out after 15s" -Severity "WARN"
            }
        } catch {
            Write-Host "[EXEC-WARN] $FileName - pwsh execution test failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Add-Failure -FileName $FileName -Message "pwsh execution test failed: $($_.Exception.Message)" -Severity "WARN"
        }
        try {
            $proc51 = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $FilePath, "-HealthCheck") -PassThru -WindowStyle Hidden
            $null = $proc51 | Wait-Process -Timeout 15 -ErrorAction SilentlyContinue
            if ($proc51.HasExited -and $proc51.ExitCode -ne 0) {
                Write-Host "[EXEC-WARN] $FileName - Windows PowerShell 5.1 execution test returned non-zero ($($proc51.ExitCode))." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "Windows PowerShell 5.1 execution test returned non-zero exit code $($proc51.ExitCode)" -Severity "WARN"
            } elseif (-not $proc51.HasExited) {
                Stop-Process -Id $proc51.Id -Force -ErrorAction SilentlyContinue
                Write-Host "[EXEC-WARN] $FileName - Windows PowerShell 5.1 execution test timed out after 15s." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "Windows PowerShell 5.1 execution test timed out after 15s" -Severity "WARN"
            }
        } catch {
            Write-Host "[EXEC-WARN] $FileName - Windows PowerShell 5.1 execution test failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Add-Failure -FileName $FileName -Message "Windows PowerShell 5.1 execution test failed: $($_.Exception.Message)" -Severity "WARN"
        }
    } elseif ($AutoElevate) {
        Write-Host "[SKIP]   $FileName - execution test (auto-elevation detected)" -ForegroundColor Gray
    }

    # 4. Unicode trap check: em-dash (U+2014) inside double-quoted strings breaks PowerShell 5.1 parser
    $emDashMatches = [regex]::Matches($Content, "\u2014")
    if ($emDashMatches.Count -gt 0) {
        foreach ($m in $emDashMatches) {
            $lineNumber = 1 + ($Content.Substring(0, $m.Index) -split "\r?\n").Count - 1
            Write-Host "[UNICODE-ERR] $FilePath L$lineNumber`: em-dash (U+2014) detected. Replace with double-hyphen '--' to avoid PowerShell 5.1 parse errors." -ForegroundColor Red
            Add-Failure -FileName $FileName -Message "L$lineNumber`: em-dash (U+2014) detected - replace with '--'" -Severity "ERROR"
        }
        continue
    }

    # 5. Regression Check: pipeline precedence bugs (Select-Object -ExpandProperty ... -eq)
    $i = 1
    foreach ($Line in $Lines) {
        $Trimmed = $Line.Trim()
        if ($Trimmed -match '^''.*''$|^".*"$|^\s*#') { $i++; continue }
        if ($Line -match 'Select-Object\s+-ExpandProperty\s+[^\s]+.*\s+-eq\s+\d') {
            $selectPos = $Line.IndexOf('Select-Object')
            $eqPos = $Line.IndexOf('-eq')
            $lastClose = $Line.LastIndexOf(')', $eqPos)
            if ($lastClose -lt $selectPos) {
                Write-Host "[REGRESSION] $FilePath L$i`: Unwrapped -eq after -ExpandProperty may be parsed as a parameter. Wrap the pipeline in parentheses." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "L$i`: Unwrapped -eq after -ExpandProperty - wrap pipeline in parentheses" -Severity "WARN"
            }
        }
        $i++
    }

    # 6. Strict-Mode PropertyNotFoundException heuristic
    # Detect: ($Var.Property -eq ...) or $Var.Property where $Var was assigned from a command that can return null
    $i = 1
    $ScriptVarAssignments = @{}
    foreach ($Line in $Lines) {
        if ($Line -match '\$(\w+)\s*=\s*(Get-ItemProperty|Get-ItemPropertyValue|Get-Process|Get-Service|Get-CimInstance|Get-WmiObject|Select-Object)[^\$]*-ErrorAction\s+SilentlyContinue') {
            $varName = $Matches[1]
            $ScriptVarAssignments[$varName] = $i
        }
        if ($Line -match '\$(\w+)\.\w+\s+-eq\s+') {
            $varName = $Matches[1]
            if ($ScriptVarAssignments.ContainsKey($varName)) {
                if ($Line -notmatch 'Select-Object\s+-ExpandProperty' -and $Line -notmatch '\$null\s+-ne' -and $Line -notmatch 'try\s*\{') {
                    Write-Host "[STRICT-MODE] $FilePath L$i`: Property access on '`$$varName' without null guard. Under Set-StrictMode, this throws PropertyNotFoundException if the command returned `$null`. Use `Select-Object -ExpandProperty` with `-ErrorAction SilentlyContinue` or wrap in null-check." -ForegroundColor Yellow
                    Add-Failure -FileName $FileName -Message "L$i`: Property access on '`$$varName' without null guard - strict-mode crash risk" -Severity "WARN"
                }
            }
        }
        if ($Line -match '\(\$(\w+)\.\w+') {
            $varName = $Matches[1]
            if ($ScriptVarAssignments.ContainsKey($varName)) {
                if ($Line -notmatch 'Select-Object\s+-ExpandProperty' -and $Line -notmatch '\$null\s+-ne' -and $Line -notmatch 'try\s*\{') {
                    Write-Host "[STRICT-MODE] $FilePath L$i`: Property access on '`$$varName' inside parentheses without null guard. Under Set-StrictMode, this throws PropertyNotFoundException if the command returned `$null`." -ForegroundColor Yellow
                    Add-Failure -FileName $FileName -Message "L$i`: Property access on '`$$varName' without null guard - strict-mode crash risk" -Severity "WARN"
                }
            }
        }
        $i++
    }

    # 7. Duplicate variable declaration detection
    $ScriptVarDeclarations = @{}
    $i = 1
    foreach ($Line in $Lines) {
        if ($Line -match '^\s*\$script:(\w+)\s*=') {
            $varName = $Matches[1]
            if ($ScriptVarDeclarations.ContainsKey($varName)) {
                Write-Host "[DUPLICATE] $FilePath L$i`: Duplicate script-scoped variable declaration '`$script:$varName'. First declared at L$($ScriptVarDeclarations[$varName])." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "L$i`: Duplicate script-scoped variable '`$script:$varName' (first at L$($ScriptVarDeclarations[$varName]))" -Severity "WARN"
            } else {
                $ScriptVarDeclarations[$varName] = $i
            }
        }
        $i++
    }

    # 8. Smart bracket-in-string syntax trap
    $i = 1
    foreach ($Line in $Lines) {
        $Trimmed = $Line.Trim()
        if ($Trimmed -match '^\s*#') { $i++; continue }
        # Skip lines that are likely regex definitions (they legitimately contain brackets)
        if ($Line -match '\-match|\[regex\]::') { $i++; continue }
        $dqMatches = [regex]::Matches($Line, '"([^\"]*)"')
        foreach ($m in $dqMatches) {
            $segment = $m.Groups[1].Value
            if ($segment -match '\$\(') { continue }
            if ($segment -match '\$') { continue }
            # Skip known tag strings and UI markers
            if ($segment -match '\[\w+\]|\[SUCCESS\]|\[ERROR\]|\[WARN\]|\[INFO\]|\[FAIL\]|\[OK\]|\[DISABLED\]|\[ENABLED\]|\[PENDING\]|\[UNKNOWN\]|\[EXEC-WARN\]|\[EXEC-ERR\]|\[UNICODE-ERR\]|\[REGRESSION\]|\[STRICT-MODE\]|\[DUPLICATE\]|\[STRING-BRACKET\]|\[HARDCODED-PATH\]|\[SECURITY\]|\[ALIAS\]|\[WHITESPACE\]|\[LINE-ENDING\]|\[ENCODING\]|\[ENCODING-ERR\]|\[ERRORACTION\]|\[ARRAY-UNROLL\]|\[SCAN\]|\[SKIP\]|\[ERR\]') { continue }
            # Skip empty/spaced brackets common in UI output (e.g., "[ ]", "[  ]")
            if ($segment -match '\[\s*\]') { continue }
            # Skip regex character classes inside strings (e.g., [^"], [\w], [\d], [\s], [\r], [\n])
            if ($segment -match '\[[\^\\w\\d\\s\\S\\D\\W\\b\\B\\A\\Z\\z\\c\\x\\u\\p\\P]') { continue }
            if ($segment -match '\[.*\]' -and $segment -notmatch '\$\(') {
                Write-Host "[STRING-BRACKET] $FilePath L$i`: Unescaped brackets inside double-quoted string segment: `"$segment`". Under PowerShell parser, brackets in double-quoted strings can be misinterpreted as array index or type cast. Escape with backtick or use single quotes." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "L$i`: Unescaped brackets in double-quoted string: `"$segment`"" -Severity "WARN"
            }
        }
        $i++
    }

    # 9. Hardcoded path detection
    $i = 1
    foreach ($Line in $Lines) {
        if ($Line -match 'C:\\\\Users\\\\[^\\]+') {
            Write-Host "[HARDCODED-PATH] $FilePath L$i`: Hardcoded user path detected. Use `$env:USERPROFILE or a parameter instead for portability." -ForegroundColor DarkGray
            Add-Failure -FileName $FileName -Message "L$i`: Hardcoded path detected - use environment variables or parameters" -Severity "WARN"
        }
        $i++
    }

    # 10. Unsafe cmdlet detection
    $i = 1
    foreach ($Line in $Lines) {
        # Skip self-referencing lines in this meta-script to avoid flagging our own check patterns
        if ($FileName -eq 'syntax_check.ps1' -and $Line -match "Invoke-Command.*-ScriptBlock|Invoke-Expression") { $i++; continue }
        if ($Line -match '\bInvoke-Expression\b|\bIEX\b|\beval\b|\bInvoke-Command\b.*-ScriptBlock') {
            Write-Host "[SECURITY] $FilePath L$i`: Potentially unsafe cmdlet or expression detected. Review for security implications." -ForegroundColor Magenta
            Add-Failure -FileName $FileName -Message "L$i`: Potentially unsafe cmdlet/expression detected" -Severity "WARN"
        }
        $i++
    }

    # 11. Alias usage detection
    $Aliases = @('select', 'where', 'sort', 'gci', 'ls', 'cat', 'echo', 'cls', 'copy', 'del', 'dir', 'move', 'ren', 'rmdir', 'write')
    $i = 1
    foreach ($Line in $Lines) {
        foreach ($Alias in $Aliases) {
            # Use case-sensitive .NET regex so 'Select-Object' and 'Write-Host' are not flagged as 'select'/'write'
            if ([System.Text.RegularExpressions.Regex]::IsMatch($Line, "(?<![\w\-\$])$Alias(?![\w-])", [System.Text.RegularExpressions.RegexOptions]::None)) {
                Write-Host "[ALIAS] $FilePath L$i`: Alias '$Alias' detected. Use full cmdlet name for clarity and future compatibility." -ForegroundColor DarkGray
                Add-Failure -FileName $FileName -Message "L$i`: Alias '$Alias' - use full cmdlet name" -Severity "WARN"
                break
            }
        }
        $i++
    }

    # 12. Trailing whitespace check
    $i = 1
    foreach ($Line in $Lines) {
        if ($Line -match '\s+$') {
            Write-Host "[WHITESPACE] $FilePath L$i`: Trailing whitespace detected." -ForegroundColor DarkGray
            Add-Failure -FileName $FileName -Message "L$i`: Trailing whitespace" -Severity "WARN"
        }
        $i++
    }

    # 14. Encoding / BOM check
    try {
        $Stream = [System.IO.FileStream]::new($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $Bom = New-Object byte[] 3
        $Read = $Stream.Read($Bom, 0, 3)
        $Stream.Close()
        if ($Read -ge 3 -and $Bom[0] -eq 0xEF -and $Bom[1] -eq 0xBB -and $Bom[2] -eq 0xBF) {
            # UTF-8 BOM - acceptable
        } elseif ($Read -ge 2 -and $Bom[0] -eq 0xFF -and $Bom[1] -eq 0xFE) {
            Write-Host "[ENCODING] $FilePath`: UTF-16 LE (Unicode) encoding detected. Convert to UTF-8 with BOM for best PowerShell compatibility." -ForegroundColor Yellow
            Add-Failure -FileName $FileName -Message "UTF-16 LE encoding - convert to UTF-8 with BOM" -Severity "WARN"
        } elseif ($Read -ge 2 -and $Bom[0] -eq 0xFE -and $Bom[1] -eq 0xFF) {
            Write-Host "[ENCODING] $FilePath`: UTF-16 BE encoding detected. Convert to UTF-8 with BOM for best PowerShell compatibility." -ForegroundColor Yellow
            Add-Failure -FileName $FileName -Message "UTF-16 BE encoding - convert to UTF-8 with BOM" -Severity "WARN"
        } elseif ($Read -ge 3 -and $Bom[0] -eq 0x2B -and $Bom[1] -eq 0x2F -and $Bom[2] -eq 0x76) {
            Write-Host "[ENCODING] $FilePath`: UTF-7 encoding detected. Convert to UTF-8 with BOM for best PowerShell compatibility." -ForegroundColor Yellow
            Add-Failure -FileName $FileName -Message "UTF-7 encoding - convert to UTF-8 with BOM" -Severity "WARN"
        } else {
            # No BOM detected. PowerShell 5.1 defaults to the system's ANSI code page (e.g., Windows-1252)
            # for files without BOM, which corrupts UTF-8 multi-byte characters (e.g., box-drawing chars,
            # smart quotes). This causes the parser to misread the file and produce cascading syntax errors.
            # Check if the file contains any non-ASCII bytes (bytes > 0x7F). If so, a BOM is REQUIRED.
            $FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
            $HasNonAscii = $false
            foreach ($b in $FileBytes) {
                if ($b -gt 0x7F) { $HasNonAscii = $true; break }
            }
            if ($HasNonAscii) {
                Write-Host "[ENCODING-ERR] $FilePath`: UTF-8 without BOM detected, but file contains non-ASCII characters (e.g., box-drawing chars, smart quotes). PowerShell 5.1 reads files without BOM using the system's ANSI code page, which corrupts multi-byte characters and causes cascading parser errors. Add a UTF-8 BOM (0xEF 0xBB 0xBF) to the start of the file." -ForegroundColor Red
                Add-Failure -FileName $FileName -Message "UTF-8 without BOM with non-ASCII chars - add UTF-8 BOM for PowerShell 5.1 compatibility" -Severity "ERROR"
            }
        }
    } catch {
        Write-Host "[ENCODING-ERR] $FilePath`: Could not read encoding: $($_.Exception.Message)" -ForegroundColor DarkGray
    }

    # 13. Missing -ErrorAction on Get-ItemProperty when .Property is accessed later
    $i = 1
    $VarAssignments = @{}
    foreach ($Line in $Lines) {
        if ($Line -match '\$(\w+)\s*=\s*(Get-ItemProperty|Get-ItemPropertyValue)' -and $Line -notmatch '-ErrorAction') {
            $varName = $Matches[1]
            $VarAssignments[$varName] = $i
        }
        $i++
    }
    $i = 1
    foreach ($Line in $Lines) {
        if ($Line -match '\$(\w+)\.\w+') {
            $varName = $Matches[1]
            if ($VarAssignments.ContainsKey($varName)) {
                Write-Host "[ERRORACTION] $FilePath L$i`: Property access on '`$$varName' assigned from Get-ItemProperty without -ErrorAction at L$($VarAssignments[$varName]). Add -ErrorAction SilentlyContinue to avoid strict-mode crashes." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "L$i`: Property access on '`$$varName' without -ErrorAction on Get-ItemProperty (assigned L$($VarAssignments[$varName]))" -Severity "WARN"
                $VarAssignments.Remove($varName)
            }
        }
        $i++
    }

    # 15. Array unrolling check: return @() without comma operator in functions that return arrays
    $i = 1
    $InFunction = $false
    foreach ($Line in $Lines) {
        if ($Line -match '^function\s+\w+') { $InFunction = $true }
        if ($Line -match '^\}\s*$') { $InFunction = $false }
        if ($InFunction -and $Line -match '^\s*return\s+@\(\w+\)\s*$') {
            Write-Host "[ARRAY-UNROLL] $FilePath L$i`: `return @(...)` without comma operator in function. Under Set-StrictMode, PowerShell may unroll the array to a single scalar or null. Use `return ,@(...)` to preserve array type." -ForegroundColor Yellow
            Add-Failure -FileName $FileName -Message ('L' + $i + ': Array unrolling risk - use `return ,@(...)`') -Severity "WARN"
        }
        $i++
    }

    # 16. Redirection operator trap check: >>> and <<< inside double-quoted strings or bare text
    # PowerShell parses >>> and <<< as redirection operators, which causes "Missing file specification after redirection operator".
    $i = 1
    foreach ($Line in $Lines) {
        $Trimmed = $Line.Trim()
        if ($Trimmed -match '^\s*#') { $i++; continue }
        # Skip single-quoted strings (literal, no redirection parsing inside)
        if ($Trimmed -match "^'") { $i++; continue }
        # Detect inside double-quoted strings or bare text
        $dqMatches = [regex]::Matches($Line, '"([^\"]*)"')
        $Found = $false
        foreach ($m in $dqMatches) {
            $segment = $m.Groups[1].Value
            if ($segment -match '>>>|<<<') {
                Write-Host "[REDIRECT-TRAP] $FilePath L$i`: Redirection operator sequence (>>> or <<<) inside double-quoted string segment: `"$segment`". PowerShell parses this as a redirection operator and throws 'Missing file specification after redirection operator'. Replace with `***` or similar safe markers." -ForegroundColor Red
                Add-Failure -FileName $FileName -Message "L$i`: Redirection operator trap (>>> or <<<) inside double-quoted string - replace with ***" -Severity "ERROR"
                $Found = $true
            }
        }
        # Also catch bare text outside quotes (even more dangerous)
        if (-not $Found -and $Line -match '>>>|<<<') {
            Write-Host "[REDIRECT-TRAP] $FilePath L$i`: Redirection operator sequence (>>> or <<<) detected outside single-quoted strings. PowerShell parses this as a redirection operator and throws 'Missing file specification after redirection operator'. Replace with `***` or similar safe markers." -ForegroundColor Red
            Add-Failure -FileName $FileName -Message "L$i`: Redirection operator trap (>>> or <<<) outside single-quoted strings - replace with ***" -Severity "ERROR"
        }
        $i++
    }

    # 17. PowerShell 5.1 reserved operator trap check: ! and & inside double-quoted strings
    # In PowerShell 5.1, `!` and `&` inside double-quoted strings can trigger parser errors
    # when they appear near parentheses or other expression contexts, especially when the file
    # is read with the wrong encoding. Escaping with backtick (e.g., `` `! `` and `` `& ``)
    # makes them safe in all PowerShell versions.
    $i = 1
    foreach ($Line in $Lines) {
        $Trimmed = $Line.Trim()
        if ($Trimmed -match '^\s*#') { $i++; continue }
        # Skip single-quoted strings (literal, no parsing inside)
        if ($Trimmed -match "^'") { $i++; continue }
        $dqMatches = [regex]::Matches($Line, '"([^\"]*)"')
        foreach ($m in $dqMatches) {
            $segment = $m.Groups[1].Value
            # Skip already escaped segments
            if ($segment -match '`!|`&') { continue }
            # Detect ! followed by ( or ) in double-quoted strings
            if ($segment -match '!\s*[\(\)]') {
                Write-Host "[RESERVED-OP] $FilePath L$i`: Unescaped `!` followed by parenthesis inside double-quoted string: `"$segment`". In PowerShell 5.1 this can be parsed as a reserved operator and cause syntax errors. Escape with backtick (`` `! ``) to make it safe." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "L$i`: Unescaped `!` followed by parenthesis in double-quoted string - escape with `` `! ``" -Severity "WARN"
            }
            # Detect bare & inside double-quoted strings (not at start of string, not part of a variable)
            if ($segment -match '(?<!`)&') {
                Write-Host "[RESERVED-OP] $FilePath L$i`: Unescaped `&` inside double-quoted string: `"$segment`". In PowerShell 5.1 `&` is a reserved operator and can cause syntax errors. Escape with backtick (`` `& ``) to make it safe." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "L$i`: Unescaped `&` in double-quoted string - escape with `` `& ``" -Severity "WARN"
            }
        }
        $i++
    }

    # 18. Unmatched braces / brackets / parentheses (stack-based check)
    # This catches the most common parser-level structural errors that AST and PSParser may miss.
    $BraceStack = [System.Collections.Generic.List[pscustomobject]]::new()
    $i = 1
    foreach ($Line in $Lines) {
        $Trimmed = $Line.Trim()
        if ($Trimmed -match '^\s*#') { $i++; continue }
        # Skip single-quoted strings (literal content)
        if ($Trimmed -match "^'") { $i++; continue }
        # Skip here-strings (simplified)
        if ($Trimmed.StartsWith('@') -and ($Trimmed.Length -gt 1) -and ($Trimmed[1] -eq "'" -or $Trimmed[1] -eq '"')) { $i++; continue }
        $InString = $false
        $StringChar = ''
        $Escaping = $false
        $CharArray = $Line.ToCharArray()
        for ($j = 0; $j -lt $CharArray.Length; $j++) {
            $ch = $CharArray[$j]
            if ($Escaping) { $Escaping = $false; continue }
            if ($ch -eq '`') { $Escaping = $true; continue }
            if ($InString -eq $false) {
                if ($ch -eq '"') { $InString = $true; $StringChar = $ch; continue }
                if ($ch -eq "'") { $InString = $true; $StringChar = $ch; continue }
                if ($ch -eq '{') { $BraceStack.Add([pscustomobject]@{ Char = '{'; Line = $i; Col = $j }) }
                if ($ch -eq '[') { $BraceStack.Add([pscustomobject]@{ Char = '['; Line = $i; Col = $j }) }
                if ($ch -eq '(') { $BraceStack.Add([pscustomobject]@{ Char = '('; Line = $i; Col = $j }) }
                if ($ch -eq '}') {
                    if ($BraceStack.Count -eq 0 -or $BraceStack[$BraceStack.Count - 1].Char -ne '{') {
                        Write-Host "[BRACE-MISMATCH] $FilePath L$i`: Unmatched closing brace } . No matching opening brace found." -ForegroundColor Red
                        Add-Failure -FileName $FileName -Message "L$i`: Unmatched closing brace }" -Severity "ERROR"
                    } else { $BraceStack.RemoveAt($BraceStack.Count - 1) }
                }
                if ($ch -eq ']') {
                    if ($BraceStack.Count -eq 0 -or $BraceStack[$BraceStack.Count - 1].Char -ne '[') {
                        Write-Host "[BRACE-MISMATCH] $FilePath L$i`: Unmatched closing bracket ] . No matching opening bracket found." -ForegroundColor Red
                        Add-Failure -FileName $FileName -Message "L$i`: Unmatched closing bracket ]" -Severity "ERROR"
                    } else { $BraceStack.RemoveAt($BraceStack.Count - 1) }
                }
                if ($ch -eq ')') {
                    if ($BraceStack.Count -eq 0 -or $BraceStack[$BraceStack.Count - 1].Char -ne '(') {
                        Write-Host "[BRACE-MISMATCH] $FilePath L$i`: Unmatched closing parenthesis ) . No matching opening parenthesis found." -ForegroundColor Red
                        Add-Failure -FileName $FileName -Message "L$i`: Unmatched closing parenthesis )" -Severity "ERROR"
                    } else { $BraceStack.RemoveAt($BraceStack.Count - 1) }
                }
            }
            else {
                if ($ch -eq $StringChar) { $InString = $false; $StringChar = '' }
            }
        }
        $i++
    }
    foreach ($Open in $BraceStack) {
        $charName = if ($Open.Char -eq '{') { 'brace' } elseif ($Open.Char -eq '[') { 'bracket' } else { 'parenthesis' }
        Write-Host "[BRACE-MISMATCH] $FilePath L$($Open.Line)`: Unmatched opening $charName $Open.Char . No matching closing character found." -ForegroundColor Red
        Add-Failure -FileName $FileName -Message "L$($Open.Line)`: Unmatched opening $charName $Open.Char" -Severity "ERROR"
    }

    # 19. Unbalanced quotes (single/double)
    $i = 1
    foreach ($Line in $Lines) {
        $Trimmed = $Line.Trim()
        if ($Trimmed -match '^\s*#') { $i++; continue }
        $DblCount = 0
        $SngCount = 0
        $Escaping = $false
        $CharArray = $Line.ToCharArray()
        for ($j = 0; $j -lt $CharArray.Length; $j++) {
            $ch = $CharArray[$j]
            if ($Escaping) { $Escaping = $false; continue }
            if ($ch -eq '`') { $Escaping = $true; continue }
            if ($ch -eq '"') { $DblCount++ }
            if ($ch -eq "'") { $SngCount++ }
        }
        # Heuristic: odd count of unescaped quotes on a single line (ignoring here-strings and multiline)
        if ($DblCount % 2 -ne 0 -and $SngCount % 2 -ne 0) {
            # Both odd - likely a multiline string or mixed quotes; only warn if the line looks simple
            if ($DblCount -eq 1 -and $SngCount -eq 1) {
                Write-Host "[QUOTE-MISMATCH] $FilePath L$i`: Single unescaped double quote and single unescaped single quote on the same line. This may indicate a malformed string literal." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "L$i`: Potential quote mismatch (1 double + 1 single unescaped quote)" -Severity "WARN"
            }
        } elseif ($DblCount % 2 -ne 0 -and $SngCount % 2 -eq 0) {
            if ($DblCount -eq 1) {
                Write-Host "[QUOTE-MISMATCH] $FilePath L$i`: Single unescaped double quote on this line. Potential unterminated string literal." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "L$i`: Potential unterminated double-quoted string" -Severity "WARN"
            }
        }
        $i++
    }

    # 20. Variable interpolation in single-quoted strings
    # Single-quoted strings are literal in PowerShell; $variable inside them does NOT expand.
    # This is a common mistake when the user meant double-quoted strings.
    $i = 1
    foreach ($Line in $Lines) {
        $Trimmed = $Line.Trim()
        if ($Trimmed -match '^\s*#') { $i++; continue }
        # Match single-quoted strings that contain $ followed by a word character
        $sqMatches = [regex]::Matches($Line, "'([^']*\$\w+[^']*)'")
        foreach ($m in $sqMatches) {
            Write-Host "[LITERAL-STRING] $FilePath L$i`: Variable reference inside single-quoted string: $m . Variables do NOT expand inside single quotes. Use double quotes if interpolation is intended." -ForegroundColor Yellow
            Add-Failure -FileName $FileName -Message "L$i`: Variable reference inside single-quoted string - use double quotes for interpolation" -Severity "WARN"
        }
        $i++
    }

    # 21. UseShellExecute missing when Verb = runAs
    # In PowerShell 7 / .NET Core, ProcessStartInfo.UseShellExecute defaults to $false.
    # When UseShellExecute = $false, the Verb property is completely ignored, so UAC elevation never happens.
    # This causes an infinite auto-elevation loop (the exact bug we fixed in OS-Guard).
    $i = 1
    foreach ($Line in $Lines) {
        $Trimmed = $Line.Trim()
        if ($Trimmed -match '^\s*#') { $i++; continue }
        if ($Line -match 'Verb\s*=\s*"runAs"' -or $Line -match "Verb\s*=\s*'runAs'") {
            # Check if UseShellExecute = $true appears anywhere in the same file (simplified: within 20 lines)
            $FoundUseShell = $false
            $start = [Math]::Max(0, $i - 20)
            $end = [Math]::Min($Lines.Count - 1, $i + 20)
            for ($k = $start; $k -le $end; $k++) {
                if ($Lines[$k] -match 'UseShellExecute\s*=\s*\$true') { $FoundUseShell = $true; break }
            }
            if (-not $FoundUseShell) {
                Write-Host "[ELEVATION-LOOP] $FilePath L$i`: Verb = runAs detected without UseShellExecute = true in the same scope. In PowerShell 7 / .NET Core, UseShellExecute defaults to false, and the Verb is ignored. This causes an infinite auto-elevation loop. Add ProcessInfo.UseShellExecute = true before setting the Verb." -ForegroundColor Red
                Add-Failure -FileName $FileName -Message "L$i`: UseShellExecute = true missing before Verb = runAs - elevation loop bug" -Severity "ERROR"
            }
        }
        $i++
    }

    # 22. Mixed line endings (CRLF vs LF consistency)
    # Files with mixed line endings can cause line-number misalignment between editors and parsers.
    $CrlfCount = ($Content -split '\r\n').Count - 1
    $LfOnlyCount = ([regex]::Matches($Content, '(?<!\r)\n')).Count
    if ($CrlfCount -gt 0 -and $LfOnlyCount -gt 0) {
        Write-Host "[LINE-ENDING] $FilePath`: Mixed line endings detected (both CRLF and LF-only). This causes line-number misalignment between editors and parsers. Standardize to CRLF for Windows PowerShell scripts." -ForegroundColor Yellow
        Add-Failure -FileName $FileName -Message "Mixed line endings (CRLF + LF) - standardize to CRLF" -Severity "WARN"
    }

    # 23. Non-ASCII whitespace characters (tabs, non-breaking spaces)
    # Tab characters and non-breaking spaces (U+00A0) can cause indentation issues and parser confusion.
    $i = 1
    foreach ($Line in $Lines) {
        if ($Line -match '\t') {
            Write-Host "[WHITESPACE-TAB] $FilePath L$i`: Tab character detected. Use spaces for indentation to avoid cross-editor alignment issues." -ForegroundColor Yellow
            Add-Failure -FileName $FileName -Message "L$i`: Tab character - use spaces for indentation" -Severity "WARN"
        }
        if ($Line -match '\u00A0') {
            Write-Host "[WHITESPACE-NBSP] $FilePath L$i`: Non-breaking space (U+00A0) detected. This looks like a normal space but is not recognized as whitespace by some parsers. Replace with a regular space (U+0020)." -ForegroundColor Red
            Add-Failure -FileName $FileName -Message "L$i`: Non-breaking space (U+00A0) - replace with regular space" -Severity "ERROR"
        }
        $i++
    }

    # 24. Backtick at end of line (accidental line continuation)
    # A backtick (`) at the end of a line causes PowerShell to continue the command on the next line.
    # This is often accidental (e.g., from copy-paste) and can cause cascading syntax errors.
    $i = 1
    foreach ($Line in $Lines) {
        $Trimmed = $Line.TrimEnd()
        if ($Trimmed -match '`$') {
            # Allow intentional line continuations (e.g., after pipe, comma, or parameter)
            $Clean = $Trimmed -replace '\s+`$', ''
            if ($Clean -notmatch '[\|,;]$' -and $Clean -notmatch '\w+\s+=$') {
                Write-Host "[BACKTICK-EOL] $FilePath L$i`: Backtick at end of line without clear continuation context (pipe, comma, or assignment). This may be an accidental line continuation causing parser confusion." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "L$i`: Backtick at end of line - accidental line continuation?" -Severity "WARN"
            }
        }
        $i++
    }

    # 25. OrderedDictionary ContainsKey method trap
    # [ordered]@{} creates a System.Collections.Specialized.OrderedDictionary, which does NOT have a ContainsKey method.
    # Calling .ContainsKey() on such variables causes: "Method invocation failed because [System.Collections.Specialized.OrderedDictionary] does not contain a method named 'ContainsKey'."
    # Regular hashtables (@{}) DO have ContainsKey, but [ordered]@{} does NOT. This is a common trap when switching from regular hashtables to ordered ones.
    $i = 1
    $OrderedVars = @()
    foreach ($Line in $Lines) {
        $Trimmed = $Line.Trim()
        if ($Trimmed -match '^\s*#') { $i++; continue }
        # Detect variable assignments to [ordered]@{} or [ordered]@(...)
        # Match $VarName = [ordered]@... (with optional scope prefixes like $global:, $script:)
        $OrderedMatch = [regex]::Match($Trimmed, '(?i)\$(?:global:|script:)?(\w+)\s*=\s*\[ordered\]@')
        if ($OrderedMatch.Success) {
            $OrderedVars += $OrderedMatch.Groups[1].Value
        }
        # Detect .ContainsKey() calls on those variables
        foreach ($VarName in $OrderedVars) {
            # Match $VarName.ContainsKey( or $global:VarName.ContainsKey( etc.
            if ($Trimmed -match "(?i)\`$(?:global:|script:)?$VarName\.ContainsKey\(") {
                Write-Host "[ORDERED-CONTAINSKEY] $FilePath L$i`: Variable `$$VarName is assigned to [ordered]@{} (OrderedDictionary) but later uses .ContainsKey(), which does NOT exist on OrderedDictionary. Use `if (`$$VarName[`"Key`"] -ne `$null)` or `if (`$$VarName[`"Key`"] -eq `$true)` instead." -ForegroundColor Red
                Add-Failure -FileName $FileName -Message "L$i`: .ContainsKey() used on [ordered]@{} variable `$$VarName - OrderedDictionary does not have this method" -Severity "ERROR"
            }
        }
        $i++
    }

    if ($FileFailures.ContainsKey($FileName)) {
        # Already reported failures for this file
    } else {
        Write-Host "[OK]   $FileName" -ForegroundColor Green
    }
}

# 26. Auto-chmod: ensure all .ps1 scripts are executable (not blocked by execution policy or ACL issues)
foreach ($File in $Ps1Files) {
    try {
        $Acl = Get-Acl -Path $File.FullName -ErrorAction SilentlyContinue
        if ($Acl) {
            $UsersSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
            $ReadExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
            $AllowRule = New-Object System.Security.AccessControl.FileSystemAccessRule($UsersSid, $ReadExecute, "None", "None", "Allow")
            $Acl.AddAccessRule($AllowRule)
            Set-Acl -Path $File.FullName -AclObject $Acl -ErrorAction SilentlyContinue
        }
    } catch {}
}

Write-Host "`n=====================================================" -ForegroundColor DarkGray
Write-Host " SYNTAX CHECK SUMMARY " -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor DarkGray
$ErrorCount = $ErrorFiles.Count
$WarnCount = $Warnings.Count
$PassCount = $Ps1Files.Count - $ErrorCount
Write-Host "Total checked: $($Ps1Files.Count)" -ForegroundColor Gray
Write-Host "Passed:        $PassCount" -ForegroundColor Green
Write-Host "Warnings:      $WarnCount" -ForegroundColor Yellow
Write-Host "Failed:        $ErrorCount" -ForegroundColor Red

if ($ErrorCount -gt 0) {
    Write-Host "`nFAIL SUMMARY ($ErrorCount)" -ForegroundColor Red -BackgroundColor Black
    foreach ($File in $ErrorFiles) {
        Write-Host "  $File" -ForegroundColor Red
        foreach ($Msg in $FileFailures[$File] | Where-Object { $_ -match '^\[ERROR\]' }) {
            Write-Host "    $Msg" -ForegroundColor DarkRed
        }
    }
    exit 1
} else {
    Write-Host "`n[SUCCESS] ALL SYNTAX CHECKS PASSED!" -ForegroundColor Green
    if ($WarnCount -gt 0) {
        Write-Host ('(' + $WarnCount + ' file(s) had warnings - review above for details)') -ForegroundColor Yellow
    }
    exit 0
}
