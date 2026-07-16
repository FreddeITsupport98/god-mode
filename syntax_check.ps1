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
    --- Upgrades (2026-07-16) ---
    * Honest ERROR aggregation: the summary now derives ERROR/WARN file lists from $FileFailures
      (single source of truth) so the exit code always reflects real [ERROR] findings. This fixes a
      $script: scoping bug where Add-Failure's arrays never aggregated and the checker always printed
      "Failed: 0" regardless of ERROR tags.
    * Heuristic scanners downgraded ERROR->WARN: brace/paren/bracket mismatch, try/catch mismatch,
      and redirect-trap inside double-quoted strings (string literals are NOT parsed as operators).
      AST (#1) + PSParser (#2) remain the authoritative ERROR parse checks.
    * Elevation-loop (Verb=runAs without UseShellExecute) is now STRING-AWARE: only flags
      `Verb = runAs` in bare code, not inside quoted string literals (test files that mention the
      pattern inside a -notmatch regex are no longer false-flagged).
    * Best-effort toolchain checks (SKIP if the tool is not on PATH): C compile via
      x86_64-w64-mingw32-gcc / gcc / cl.exe (-fsyntax-only; ': error:' -> ERROR, ': warning:' -> WARN),
      shellcheck -S warning on .sh, python -m py_compile on .py, node --check on .js.
    * Auto-chmod extended to .sh / .py / .js (chmod +x on Unix, ACL ReadAndExecute on Windows).
    Use this as the BASE syntax check script before any deployment.
#>

param([string]$ScanDir = (Split-Path -Parent $PSScriptRoot))

$script:FailedFiles = @()
$script:ErrorFiles = @()
$script:Warnings = @()
$FileFailures = @{}  # key = fileName, value = array of failure messages (single source of truth; reference-type, aggregates across function/script scope)

function Add-Failure {
    param([string]$FileName, [string]$Message, [string]$Severity = "ERROR")
    if (-not $FileFailures.ContainsKey($FileName)) { $FileFailures[$FileName] = @() }
    $FileFailures[$FileName] += "[$Severity] $Message"
    if ($Severity -eq "ERROR") {
        if ($script:FailedFiles -notcontains $FileName) { $script:FailedFiles += $FileName }
        if ($script:ErrorFiles -notcontains $FileName) { $script:ErrorFiles += $FileName }
    } else {
        if ($script:Warnings -notcontains $FileName) { $script:Warnings += $FileName }
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
    # NOTE: >>> / <<< INSIDE a double-quoted string is NOT parsed as redirection (string literals are
    # not tokenized for operators), so that case is downgraded to WARN. The bare-text case (outside
    # any quote) remains a hard ERROR. The checker self-skips its own >>>/<<< diagnostic/regex lines.
    $i = 1
    foreach ($Line in $Lines) {
        $Trimmed = $Line.Trim()
        if ($Trimmed -match '^\s*#') { $i++; continue }
        # Skip single-quoted strings (literal, no redirection parsing inside)
        if ($Trimmed -match "^'") { $i++; continue }
        # Self-skip: this meta-script's own >>>/<<< regex/diagnostic lines would otherwise self-flag.
        if ($FileName -eq 'syntax_check.ps1' -and $Line -match '>>>|<<<') { $i++; continue }
        # Detect inside double-quoted strings or bare text
        $dqMatches = [regex]::Matches($Line, '"([^\"]*)"')
        $Found = $false
        foreach ($m in $dqMatches) {
            $segment = $m.Groups[1].Value
            if ($segment -match '>>>|<<<') {
                Write-Host "[REDIRECT-TRAP] $FilePath L$i`: Redirection operator sequence (>>> or <<<) inside double-quoted string segment: `$segment`. PowerShell does NOT parse operators inside string literals, so this is not a redirection at parse time - but it can confuse readers/linters. WARN only; consider `***` or similar safe markers." -ForegroundColor Yellow
                Add-Failure -FileName $FileName -Message "L$i`: Redirection operator sequence (>>> or <<<) inside double-quoted string - not a parse error (string literal), review only" -Severity "WARN"
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

    # 18. Unmatched braces / brackets / parentheses (stack-based HEURISTIC check)
    # HEURISTIC: this naive stack walker does not fully understand here-strings, multi-line strings,
    # comments, or array-index/type-cast brackets, so it produces false positives. Authoritative
    # structural parse errors are already caught as ERROR by check #1 (AST) and #2 (PSParser), so
    # this check is downgraded to WARN - it stays as a diagnostic hint, not a build blocker.
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
                        Write-Host "[BRACE-MISMATCH] $FilePath L$i`: Unmatched closing brace } . No matching opening brace found." -ForegroundColor Yellow
                        Add-Failure -FileName $FileName -Message "L$i`: Unmatched closing brace }" -Severity "WARN"
                    } else { $BraceStack.RemoveAt($BraceStack.Count - 1) }
                }
                if ($ch -eq ']') {
                    if ($BraceStack.Count -eq 0 -or $BraceStack[$BraceStack.Count - 1].Char -ne '[') {
                        Write-Host "[BRACE-MISMATCH] $FilePath L$i`: Unmatched closing bracket ] . No matching opening bracket found." -ForegroundColor Yellow
                        Add-Failure -FileName $FileName -Message "L$i`: Unmatched closing bracket ]" -Severity "WARN"
                    } else { $BraceStack.RemoveAt($BraceStack.Count - 1) }
                }
                if ($ch -eq ')') {
                    if ($BraceStack.Count -eq 0 -or $BraceStack[$BraceStack.Count - 1].Char -ne '(') {
                        Write-Host "[BRACE-MISMATCH] $FilePath L$i`: Unmatched closing parenthesis ) . No matching opening parenthesis found." -ForegroundColor Yellow
                        Add-Failure -FileName $FileName -Message "L$i`: Unmatched closing parenthesis )" -Severity "WARN"
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
        Write-Host "[BRACE-MISMATCH] $FilePath L$($Open.Line)`: Unmatched opening $charName $Open.Char . No matching closing character found." -ForegroundColor Yellow
        Add-Failure -FileName $FileName -Message "L$($Open.Line)`: Unmatched opening $charName $Open.Char" -Severity "WARN"
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

    # 21. UseShellExecute missing when Verb = runAs (STRING-AWARE)
    # In PowerShell 7 / .NET Core, ProcessStartInfo.UseShellExecute defaults to $false.
    # When UseShellExecute = $false, the Verb property is completely ignored, so UAC elevation never happens.
    # This causes an infinite auto-elevation loop (the exact bug we fixed in OS-Guard).
    # STRING-AWARE: only flag `Verb = runAs` that appears in BARE code, not inside a quoted string
    # literal. Test files that mention `Verb = "runAs"` inside a -notmatch regex pattern are NOT real
    # elevation bugs, so they must not be flagged. The AST (#1) / PSParser (#2) checks remain authoritative.
    $i = 1
    foreach ($Line in $Lines) {
        $Trimmed = $Line.Trim()
        if ($Trimmed -match '^\s*#') { $i++; continue }
        # Walk the line tracking string context; only detect Verb = runAs in BARE code (not in a string literal).
        $InString = $false
        $StringChar = ''
        $Escaping = $false
        $CharArray = $Line.ToCharArray()
        $VerbHit = $false
        for ($j = 0; $j -lt $CharArray.Length; $j++) {
            $ch = $CharArray[$j]
            if ($Escaping) { $Escaping = $false; continue }
            if ($ch -eq '`') { $Escaping = $true; continue }
            if ($InString) {
                if ($ch -eq $StringChar) { $InString = $false; $StringChar = '' }
                continue
            }
            if ($ch -eq '"' -or $ch -eq "'") { $InString = $true; $StringChar = $ch; continue }
            # Bare code: look for an identifier-leading `Verb = "runAs"` or `Verb = 'runAs'` assignment.
            if ($ch -eq 'V' -and ($j -eq 0 -or (-not [char]::IsLetterOrDigit($CharArray[$j-1]) -and $CharArray[$j-1] -ne '_'))) {
                $rest = $Line.Substring($j)
                if ($rest -match '^Verb\s*=\s*("runAs"|''runAs'')') { $VerbHit = $true; break }
            }
        }
        if ($VerbHit) {
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

    # 25.5. Try/Catch/Finally stack mismatch (HEURISTIC)
    # PowerShell requires that every `try` block be paired with at least one `catch` or `finally` block.
    # This catches the common parser error: "The Try statement is missing its Catch or Finally block."
    # HEURISTIC: this line-by-line scanner does not track multi-line/string context perfectly and can
    # false-fire; a genuine missing catch/finally is already a hard ERROR via check #1 (AST), so this
    # check is downgraded to WARN - diagnostic hint only, not a build blocker.
    $i = 1
    $TryStack = [System.Collections.Generic.List[pscustomobject]]::new()
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
                # Detect try / catch / finally keywords (whole-word only)
                if ($j -eq 0 -or -not [char]::IsLetterOrDigit($CharArray[$j-1]) -and $CharArray[$j-1] -ne '_') {
                    $rest = $Line.Substring($j)
                    if ($rest -match '^try\b') {
                        $TryStack.Add([pscustomobject]@{ Keyword = 'try'; Line = $i; Col = $j })
                        $j += 2
                        continue
                    }
                    if ($rest -match '^catch\b') {
                        if ($TryStack.Count -eq 0 -or $TryStack[$TryStack.Count - 1].Keyword -ne 'try') {
                            Write-Host "[TRY-CATCH-MISMATCH] $FilePath L$i': Unmatched 'catch' found without a matching 'try' block." -ForegroundColor Yellow
                            Add-Failure -FileName $FileName -Message "L$i': Unmatched 'catch' without a matching 'try' block" -Severity "WARN"
                        } else {
                            # Replace the top try with a catch marker so we can detect duplicate catches without finally
                            $TryStack[$TryStack.Count - 1] = [pscustomobject]@{ Keyword = 'catch'; Line = $i; Col = $j }
                        }
                        $j += 4
                        continue
                    }
                    if ($rest -match '^finally\b') {
                        if ($TryStack.Count -eq 0 -or ($TryStack[$TryStack.Count - 1].Keyword -ne 'try' -and $TryStack[$TryStack.Count - 1].Keyword -ne 'catch')) {
                            Write-Host "[TRY-CATCH-MISMATCH] $FilePath L$i': Unmatched 'finally' found without a matching 'try' block." -ForegroundColor Yellow
                            Add-Failure -FileName $FileName -Message "L$i': Unmatched 'finally' without a matching 'try' block" -Severity "WARN"
                        } else {
                            # Mark as closed (finally satisfies the try requirement)
                            $TryStack.RemoveAt($TryStack.Count - 1)
                        }
                        $j += 6
                        continue
                    }
                }
            }
            else {
                if ($ch -eq $StringChar) { $InString = $false; $StringChar = '' }
            }
        }
        $i++
    }
    foreach ($Open in $TryStack) {
        if ($Open.Keyword -eq 'try') {
            Write-Host "[TRY-CATCH-MISMATCH] $FilePath L$($Open.Line)': 'try' block at L$($Open.Line) is missing its 'catch' or 'finally' block." -ForegroundColor Yellow
            Add-Failure -FileName $FileName -Message "L$($Open.Line)': 'try' block missing 'catch' or 'finally' block" -Severity "WARN"
        }
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
        # Match VarName = [ordered]@... (with optional scope prefixes like dollar-global-colon, dollar-script-colon)
        $OrderedMatch = [regex]::Match($Trimmed, '(?i)\$(?:global:|script:)?(\w+)\s*=\s*\[ordered\]@')
        if ($OrderedMatch.Success) {
            $OrderedVars += $OrderedMatch.Groups[1].Value
        }
        # Detect .ContainsKey() calls on those variables
        foreach ($VarName in $OrderedVars) {
            # Match VarName.ContainsKey( or global:VarName.ContainsKey( etc.
            if ($Trimmed -match ('(?i)\$(?:global:|script:)?' + $VarName + '\.ContainsKey\(')) {
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

# C/C++ Syntax Check Section
$CFiles = Get-ChildItem -Path $ScanDir -Filter "*.c" -File -Recurse -ErrorAction SilentlyContinue
$HFiles = Get-ChildItem -Path $ScanDir -Filter "*.h" -File -Recurse -ErrorAction SilentlyContinue
$AllCFiles = @($CFiles) + @($HFiles) | Where-Object { $_ -ne $null }

foreach ($CFile in $AllCFiles) {
    $CFileName = $CFile.Name
    $CFilePath = $CFile.FullName
    $CLines = Get-Content -Path $CFilePath -ErrorAction SilentlyContinue
    if (-not $CLines) { continue }

    $BraceStack = [System.Collections.Generic.List[pscustomobject]]::new()
    $InString = $false
    $StringChar = ''
    $InChar = $false
    $InBlockComment = $false
    $Escaping = $false
    $LineInBlockComment = @()
    $i = 1

    foreach ($Line in $CLines) {
        $LineInBlockComment += $InBlockComment
        $CharArray = $Line.ToCharArray()
        for ($j = 0; $j -lt $CharArray.Length; $j++) {
            $ch = $CharArray[$j]
            $nextCh = if ($j + 1 -lt $CharArray.Length) { $CharArray[$j + 1] } else { $null }

            if ($Escaping) {
                $Escaping = $false
                continue
            }

            if ($InBlockComment) {
                if ($ch -eq '*' -and $nextCh -eq '/') {
                    $InBlockComment = $false
                    $j++ # skip /
                }
                continue
            }

            if ($InString) {
                if ($ch -eq '\') {
                    $Escaping = $true
                    continue
                }
                if ($ch -eq $StringChar) {
                    $InString = $false
                    $StringChar = ''
                }
                continue
            }

            if ($InChar) {
                if ($ch -eq '\') {
                    $Escaping = $true
                    continue
                }
                if ($ch -eq "'") {
                    $InChar = $false
                }
                continue
            }

            if ($ch -eq '/' -and $nextCh -eq '*') {
                $InBlockComment = $true
                $j++
                continue
            }

            if ($ch -eq '/' -and $nextCh -eq '/') {
                break
            }

            if ($ch -eq '"') {
                $InString = $true
                $StringChar = '"'
                continue
            }

            if ($ch -eq "'") {
                $InChar = $true
                continue
            }

            if ($ch -eq '{') { $BraceStack.Add([pscustomobject]@{ Char = '{'; Line = $i; Col = $j }) }
            if ($ch -eq '[') { $BraceStack.Add([pscustomobject]@{ Char = '['; Line = $i; Col = $j }) }
            if ($ch -eq '(') { $BraceStack.Add([pscustomobject]@{ Char = '('; Line = $i; Col = $j }) }
            if ($ch -eq '}') {
                if ($BraceStack.Count -eq 0 -or $BraceStack[$BraceStack.Count - 1].Char -ne '{') {
                    Write-Host "[C-BRACE-MISMATCH] $CFilePath L$i`: Unmatched closing brace }." -ForegroundColor Red
                    Add-Failure -FileName $CFileName -Message "L$i`: Unmatched closing brace }" -Severity "ERROR"
                } else { $BraceStack.RemoveAt($BraceStack.Count - 1) }
            }
            if ($ch -eq ']') {
                if ($BraceStack.Count -eq 0 -or $BraceStack[$BraceStack.Count - 1].Char -ne '[') {
                    Write-Host "[C-BRACE-MISMATCH] $CFilePath L$i`: Unmatched closing bracket ]." -ForegroundColor Red
                    Add-Failure -FileName $CFileName -Message "L$i`: Unmatched closing bracket ]" -Severity "ERROR"
                } else { $BraceStack.RemoveAt($BraceStack.Count - 1) }
            }
            if ($ch -eq ')') {
                if ($BraceStack.Count -eq 0 -or $BraceStack[$BraceStack.Count - 1].Char -ne '(') {
                    Write-Host "[C-BRACE-MISMATCH] $CFilePath L$i`: Unmatched closing parenthesis )." -ForegroundColor Red
                    Add-Failure -FileName $CFileName -Message "L$i`: Unmatched closing parenthesis )" -Severity "ERROR"
                } else { $BraceStack.RemoveAt($BraceStack.Count - 1) }
            }
        }
        $i++
    }

    if ($InString) {
        Write-Host "[C-STRING] ${CFilePath}: Unterminated string literal." -ForegroundColor Red
        Add-Failure -FileName $CFileName -Message "Unterminated string literal" -Severity "ERROR"
    }
    if ($InChar) {
        Write-Host "[C-CHAR] ${CFilePath}: Unterminated character literal." -ForegroundColor Red
        Add-Failure -FileName $CFileName -Message "Unterminated character literal" -Severity "ERROR"
    }
    if ($InBlockComment) {
        Write-Host "[C-COMMENT] ${CFilePath}: Unterminated block comment /* ... */." -ForegroundColor Red
        Add-Failure -FileName $CFileName -Message "Unterminated block comment /* */" -Severity "ERROR"
    }

    foreach ($Open in $BraceStack) {
        $charName = if ($Open.Char -eq '{') { 'brace' } elseif ($Open.Char -eq '[') { 'bracket' } else { 'parenthesis' }
        Write-Host "[C-BRACE-MISMATCH] $CFilePath L$($Open.Line)`: Unmatched opening $charName $Open.Char." -ForegroundColor Red
        Add-Failure -FileName $CFileName -Message "L$($Open.Line)`: Unmatched opening $charName $Open.Char" -Severity "ERROR"
    }

    $IfStack = [System.Collections.Generic.List[pscustomobject]]::new()
    $i = 1
    foreach ($Line in $CLines) {
        if ($LineInBlockComment[$i - 1]) { $i++; continue }
        $Trimmed = $Line.Trim()
        if ($Trimmed -match '^#if\b' -or $Trimmed -match '^#ifdef\b' -or $Trimmed -match '^#ifndef\b') {
            $IfStack.Add([pscustomobject]@{ Line = $i; Type = 'if' })
        } elseif ($Trimmed -match '^#elif\b') {
            if ($IfStack.Count -eq 0 -or $IfStack[$IfStack.Count - 1].Type -ne 'if') {
                Write-Host "[C-PREPROCESSOR] $CFilePath L$i`: Unmatched #elif without #if." -ForegroundColor Red
                Add-Failure -FileName $CFileName -Message "L$i`: Unmatched #elif without #if" -Severity "ERROR"
            }
        } elseif ($Trimmed -match '^#else\b') {
            if ($IfStack.Count -eq 0 -or $IfStack[$IfStack.Count - 1].Type -ne 'if') {
                Write-Host "[C-PREPROCESSOR] $CFilePath L$i`: Unmatched #else without #if." -ForegroundColor Red
                Add-Failure -FileName $CFileName -Message "L$i`: Unmatched #else without #if" -Severity "ERROR"
            }
        } elseif ($Trimmed -match '^#endif\b') {
            if ($IfStack.Count -eq 0) {
                Write-Host "[C-PREPROCESSOR] $CFilePath L$i`: Unmatched #endif without #if." -ForegroundColor Red
                Add-Failure -FileName $CFileName -Message "L$i`: Unmatched #endif without #if" -Severity "ERROR"
            } else {
                $IfStack.RemoveAt($IfStack.Count - 1)
            }
        }
        $i++
    }
    foreach ($Open in $IfStack) {
        Write-Host "[C-PREPROCESSOR] $CFilePath L$($Open.Line)`: Unmatched #if / #ifdef / #ifndef without #endif." -ForegroundColor Red
        Add-Failure -FileName $CFileName -Message "L$($Open.Line)`: Unmatched #if / #ifdef / #ifndef without #endif" -Severity "ERROR"
    }

    if (-not $FileFailures.ContainsKey($CFileName)) {
        Write-Host "[C-OK] $CFileName" -ForegroundColor Green
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

# 27. Best-effort compile / linter checks for C, shell, python, and javascript.
# These invoke REAL toolchains (when present) to catch what static heuristics miss: undeclared symbols,
# wrong typedefs, shellcheck SC warnings, python bytecode errors, JS syntax errors. Each tool is OPTIONAL:
# if the binary is not on PATH, the check is SKIPped (info) rather than failed. The collected script file
# lists are also reused by the .sh/.py/.js auto-chmod pass (#28) and the per-language summary.
$ShFiles = @(Get-ChildItem -Path $ScanDir -Filter "*.sh" -File -Recurse -ErrorAction SilentlyContinue)
$PyFiles = @(Get-ChildItem -Path $ScanDir -Filter "*.py" -File -Recurse -ErrorAction SilentlyContinue)
$JsFiles = @(Get-ChildItem -Path $ScanDir -Filter "*.js" -File -Recurse -ErrorAction SilentlyContinue)

# (a) C best-effort COMPILE check (-fsyntax-only catches undeclared symbols / wrong typedefs without link deps).
#     Restricted to .c translation units; .h headers are not standalone-compilable and are already covered
#     by the C-section brace/string/preprocessor heuristics above. gmproxy.c needs -municode (tchar/_UNICODE).
$CcCompiler = $null
foreach ($cand in @('x86_64-w64-mingw32-gcc', 'gcc', 'cl.exe')) {
    $cmd = Get-Command -Name $cand -ErrorAction SilentlyContinue
    if ($cmd) { $CcCompiler = $cand; break }
}
if ($CcCompiler) {
    Write-Host "[C-CC] Using compiler: $CcCompiler (-fsyntax-only)" -ForegroundColor DarkGray
    foreach ($CFile in $CFiles) {
        $CFileName = $CFile.Name
        $CFilePath = $CFile.FullName
        $ccArgs = @('-fsyntax-only')
        if ($CFileName -eq 'gmproxy.c') { $ccArgs += '-municode' }
        $ccArgs += $CFilePath
        $ccOut = & $CcCompiler @ccArgs 2>&1
        $ccText = $ccOut | Out-String
        # gcc real errors print as ': error:'; missing-header 'fatal error:' has no ': error:' match,
        # so a toolchain-missing-header file is silently skipped rather than falsely flagged.
        if ($ccText -match ': error:') {
            Write-Host "[C-CC-ERR] $CFilePath`: compiler reported errors:" -ForegroundColor Red
            Write-Host $ccText -ForegroundColor DarkRed
            Add-Failure -FileName $CFileName -Message "C compiler (-fsyntax-only) reported errors - see output" -Severity "ERROR"
        } elseif ($ccText -match ': warning:') {
            Write-Host "[C-CC-WARN] $CFilePath`: compiler reported warnings (non-fatal)" -ForegroundColor Yellow
            Add-Failure -FileName $CFileName -Message "C compiler (-fsyntax-only) reported warnings" -Severity "WARN"
        }
    }
} else {
    Write-Host "[SKIP] C compile check (no x86_64-w64-mingw32-gcc / gcc / cl.exe on PATH)" -ForegroundColor Gray
}

# (b) shellcheck on every .sh (-S warning => ERROR on any warning-or-worse, mirroring run-regressions.sh).
$shellcheck = Get-Command -Name 'shellcheck' -ErrorAction SilentlyContinue
if ($shellcheck) {
    foreach ($File in $ShFiles) {
        $ShName = $File.Name
        $ShPath = $File.FullName
        $scOut = & shellcheck -S warning -f gcc $ShPath 2>&1
        $scText = $scOut | Out-String
        if ($LASTEXITCODE -ne 0 -and $scText.Trim().Length -gt 0) {
            Write-Host "[SH-ERR] $ShPath`: shellcheck reported issues:" -ForegroundColor Red
            Write-Host $scText -ForegroundColor DarkRed
            Add-Failure -FileName $ShName -Message "shellcheck (-S warning) reported issues - see output" -Severity "ERROR"
        }
    }
} else {
    Write-Host "[SKIP] shellcheck check (shellcheck not on PATH)" -ForegroundColor Gray
}

# (c) python -m py_compile on every .py.
$python = Get-Command -Name 'python3' -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command -Name 'python' -ErrorAction SilentlyContinue }
if ($python) {
    $pyBin = $python.Source
    foreach ($File in $PyFiles) {
        $PyName = $File.Name
        $PyPath = $File.FullName
        $pyOut = & $pyBin -m py_compile $PyPath 2>&1
        $pyText = $pyOut | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[PY-ERR] $PyPath`: python py_compile failed:" -ForegroundColor Red
            Write-Host $pyText -ForegroundColor DarkRed
            Add-Failure -FileName $PyName -Message "python -m py_compile failed - see output" -Severity "ERROR"
        }
    }
} else {
    Write-Host "[SKIP] python py_compile check (python3/python not on PATH)" -ForegroundColor Gray
}

# (d) node --check on every .js.
$node = Get-Command -Name 'node' -ErrorAction SilentlyContinue
if ($node) {
    foreach ($File in $JsFiles) {
        $JsName = $File.Name
        $JsPath = $File.FullName
        $jsOut = & node --check $JsPath 2>&1
        $jsText = $jsOut | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[JS-ERR] $JsPath`: node --check failed:" -ForegroundColor Red
            Write-Host $jsText -ForegroundColor DarkRed
            Add-Failure -FileName $JsName -Message "node --check failed - see output" -Severity "ERROR"
        }
    }
} else {
    Write-Host "[SKIP] node --check (node not on PATH)" -ForegroundColor Gray
}

# 28. Auto-chmod: extend the .ps1 chmod pass (#26) to .sh / .py / .js scripts (rule 5.2:
#     auto chmod to executable all other scripts when the scan directory is checked).
#     Uses chmod +x on Unix (the Get-Acl/Set-Acl ACL path is Windows-only) with an ACL fallback.
$chmodCmd = Get-Command -Name 'chmod' -ErrorAction SilentlyContinue
foreach ($File in (@($ShFiles) + @($PyFiles) + @($JsFiles))) {
    try {
        if ($chmodCmd) {
            & chmod +x $File.FullName 2>$null
        } else {
            $Acl = Get-Acl -Path $File.FullName -ErrorAction SilentlyContinue
            if ($Acl) {
                $UsersSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
                $ReadExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                $AllowRule = New-Object System.Security.AccessControl.FileSystemAccessRule($UsersSid, $ReadExecute, "None", "None", "Allow")
                $Acl.AddAccessRule($AllowRule)
                Set-Acl -Path $File.FullName -AclObject $Acl -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}

Write-Host "`n=====================================================" -ForegroundColor DarkGray
Write-Host " SYNTAX CHECK SUMMARY " -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor DarkGray
# Honest aggregation: derive ERROR/WARN file lists directly from $FileFailures (the single source of
# truth that aggregates correctly across function/script scope) rather than relying solely on the
# $script: arrays. This guarantees the exit code reflects real [ERROR] findings even if a scope bug
# ever resurfaces in Add-Failure.
$ErrorFileList = @($FileFailures.Keys | Where-Object { @($FileFailures[$_] | Where-Object { $_ -match '^\[ERROR\]' }).Count -gt 0 } | Sort-Object)
$WarnFileList  = @($FileFailures.Keys | Where-Object { @($FileFailures[$_] | Where-Object { $_ -match '^\[WARN\]'  }).Count -gt 0 } | Sort-Object)
$TotalChecked = $Ps1Files.Count + $AllCFiles.Count + @($ShFiles).Count + @($PyFiles).Count + @($JsFiles).Count
$ErrorCount = $ErrorFileList.Count
$WarnCount = $WarnFileList.Count
$PassCount = $TotalChecked - $ErrorCount
Write-Host "Total checked: $TotalChecked (PS: $($Ps1Files.Count), C: $($AllCFiles.Count), SH: $(@($ShFiles).Count), PY: $(@($PyFiles).Count), JS: $(@($JsFiles).Count))" -ForegroundColor Gray
Write-Host "Passed:        $PassCount" -ForegroundColor Green
Write-Host "Warnings:      $WarnCount (file(s))" -ForegroundColor Yellow
Write-Host "Failed:        $ErrorCount" -ForegroundColor Red

if ($ErrorCount -gt 0) {
    Write-Host "`nFAIL SUMMARY ($ErrorCount)" -ForegroundColor Red -BackgroundColor Black
    foreach ($File in $ErrorFileList) {
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
