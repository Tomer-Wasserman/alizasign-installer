# =====================================================
#  Claude Portal - Free Agent
#  Local RTL viewer for Claude Cowork sessions.
#  Read-only: never writes to Claude's files.
#  (c) Tomer Wasserman / TW Law
# =====================================================

$ErrorActionPreference = 'Stop'

# =====================================================
#  VERSION & AUTO-UPDATE CONFIG
#  ---------------------------------------------------
#  The updater fetches a small public JSON from your GitHub repo and, if a newer
#  version is published, downloads the new files, verifies each one's SHA-256 AND
#  the .ps1's Authenticode signature (pinned to your certificate), then swaps them
#  in. If GitHub is unreachable the app just continues with the current version.
# =====================================================
$script:AppVersion = '1.0.1'
# Update source: Tomer-Wasserman/alizasign-installer, subfolder 'claude-portal'.
# Branch-agnostic: we try 'main' first, then 'master', so the default branch name
# does not matter. The repo must be PUBLIC for raw access without a token.
$script:UpdateBases = @(
    'https://raw.githubusercontent.com/Tomer-Wasserman/alizasign-installer/main/claude-portal',
    'https://raw.githubusercontent.com/Tomer-Wasserman/alizasign-installer/master/claude-portal'
)
# The update is only trusted if the new .ps1 is Authenticode-signed by a certificate
# whose Subject contains this string (defense against a hijacked repo serving bad code).
$script:UpdateExpectedSigner = 'Tomer Wasserman'

# Clipboard + SendKeys require an STA thread. powershell.exe -File is usually STA,
# but relaunch ourselves under -STA if not, so injection never fails on apartment state.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Write-Host "Relaunching under STA..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList @('-NoProfile','-STA','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing   # for placing screenshots on the clipboard
# UI Automation - lets us find and focus the composer element directly.
$script:UIA = $true
try {
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
} catch { $script:UIA = $false }

# --- Win32 helpers for focusing the Claude window ---
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, IntPtr ProcessId);
    [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
    [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, IntPtr dwExtraInfo);

    public struct RECT { public int Left, Top, Right, Bottom; }

    // ---- Hardware-level input injection (SendInput) ----
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, IntPtr dwExtraInfo);
    [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)]
    public struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Explicit)]
    public struct INPUTUNION { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT { public uint type; public INPUTUNION u; }

    // Type a string by injecting Unicode key events - no clipboard, no keyboard layout.
    public static void TypeUnicode(string s) {
        const uint KEYEVENTF_KEYUP = 0x0002, KEYEVENTF_UNICODE = 0x0004;
        var list = new System.Collections.Generic.List<INPUT>();
        foreach (char c in s) {
            INPUT d = new INPUT(); d.type = 1; d.u.ki.wScan = c; d.u.ki.dwFlags = KEYEVENTF_UNICODE;
            INPUT u = new INPUT(); u.type = 1; u.u.ki.wScan = c; u.u.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
            list.Add(d); list.Add(u);
        }
        if (list.Count > 0) { INPUT[] arr = list.ToArray(); SendInput((uint)arr.Length, arr, Marshal.SizeOf(typeof(INPUT))); }
    }
    // Press a virtual key (down+up), e.g. Enter, optionally with Shift held.
    public static void PressKey(byte vk, bool shift) {
        const uint UP = 0x0002; const byte VK_SHIFT = 0x10;
        if (shift) keybd_event(VK_SHIFT, 0, 0, IntPtr.Zero);
        keybd_event(vk, 0, 0, IntPtr.Zero);
        keybd_event(vk, 0, UP, IntPtr.Zero);
        if (shift) keybd_event(VK_SHIFT, 0, UP, IntPtr.Zero);
    }
    // Ctrl + <key>, e.g. Ctrl+V (vk 0x56) to paste.
    public static void CtrlKey(byte vk) {
        const byte VK_CONTROL = 0x11; const uint UP = 0x0002;
        keybd_event(VK_CONTROL, 0, 0, IntPtr.Zero);
        keybd_event(vk, 0, 0, IntPtr.Zero);
        keybd_event(vk, 0, UP, IntPtr.Zero);
        keybd_event(VK_CONTROL, 0, UP, IntPtr.Zero);
    }

    // Click a point (screen coords) to give the composer caret focus.
    public static void ClickAt(int x, int y) {
        SetCursorPos(x, y);
        System.Threading.Thread.Sleep(40);
        mouse_event(0x0002, 0, 0, 0, IntPtr.Zero); // LEFTDOWN
        mouse_event(0x0004, 0, 0, 0, IntPtr.Zero); // LEFTUP
    }
    public static RECT GetRect(IntPtr hWnd) { RECT r; GetWindowRect(hWnd, out r); return r; }

    // Bypass Windows' foreground-lock by briefly attaching our input thread to the
    // current foreground window's thread, which lets SetForegroundWindow succeed.
    public static bool ForceForeground(IntPtr hWnd) {
        IntPtr fg = GetForegroundWindow();
        uint fgThread  = GetWindowThreadProcessId(fg, IntPtr.Zero);
        uint myThread  = GetCurrentThreadId();
        ShowWindow(hWnd, 9); // SW_RESTORE
        bool ok;
        if (fgThread != myThread) {
            AttachThreadInput(fgThread, myThread, true);
            BringWindowToTop(hWnd);
            ok = SetForegroundWindow(hWnd);
            AttachThreadInput(fgThread, myThread, false);
        } else {
            BringWindowToTop(hWnd);
            ok = SetForegroundWindow(hWnd);
        }
        return ok;
    }

    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
    // Like ForceForeground, but PRESERVES the window's size/state (does not un-maximize).
    // Used to return focus to the portal without shrinking it from full-screen.
    public static bool ForceForegroundKeep(IntPtr hWnd) {
        IntPtr fg = GetForegroundWindow();
        uint fgThread = GetWindowThreadProcessId(fg, IntPtr.Zero);
        uint myThread = GetCurrentThreadId();
        if (IsIconic(hWnd)) ShowWindow(hWnd, 9); // restore only if it was minimized
        bool ok;
        if (fgThread != myThread) {
            AttachThreadInput(fgThread, myThread, true);
            BringWindowToTop(hWnd);
            ok = SetForegroundWindow(hWnd);
            AttachThreadInput(fgThread, myThread, false);
        } else {
            BringWindowToTop(hWnd);
            ok = SetForegroundWindow(hWnd);
        }
        return ok;
    }
}
"@

try { [Win32]::SetProcessDPIAware() | Out-Null } catch { }

# When the server runs hidden (no console), a Write-Host + Read-Host error would hang
# invisibly. Show a visible message box instead so startup failures are never silent.
function Fail([string]$msg) {
    Write-Host $msg -ForegroundColor Red
    try { [System.Windows.Forms.MessageBox]::Show($msg, 'Claude Cowork Portal', 'OK', 'Error') | Out-Null } catch { }
    exit 1
}

# Find the composer text element via UI Automation. Returns the element or $null.
# Electron/Chromium builds its accessibility tree lazily: the first FromHandle call
# "wakes" it, so we retry a few times with short delays until the tree appears.
function Find-Composer([IntPtr]$hwnd) {
    if (-not $script:UIA) { return $null }
    try {
        $scope = [System.Windows.Automation.TreeScope]::Descendants
        $ctp = [System.Windows.Automation.AutomationElement]::ControlTypeProperty
        $cond = New-Object System.Windows.Automation.OrCondition(
            (New-Object System.Windows.Automation.PropertyCondition($ctp, [System.Windows.Automation.ControlType]::Edit)),
            (New-Object System.Windows.Automation.PropertyCondition($ctp, [System.Windows.Automation.ControlType]::Document))
        )
        $win = [Win32]::GetRect($hwnd)
        $winArea = [double]([Math]::Max(1, ($win.Right - $win.Left))) * [double]([Math]::Max(1, ($win.Bottom - $win.Top)))
        for ($attempt = 0; $attempt -lt 5; $attempt++) {
            $root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
            if ($root) {
                $els = $root.FindAll($scope, $cond)
                if ($els.Count -gt 0) {
                    $best = $null; $bestBottom = [double]::NegativeInfinity
                    foreach ($e in $els) {
                        try {
                            if (-not $e.Current.IsEnabled) { continue }
                            $r = $e.Current.BoundingRectangle
                            if ($r.Width -le 0 -or $r.Height -le 0) { continue }
                            $ctName = $e.Current.ControlType.ProgrammaticName
                            Write-Host ("    cand: " + $ctName + "  " + [int]$r.X + "," + [int]$r.Y + " " + [int]$r.Width + "x" + [int]$r.Height) -ForegroundColor DarkGray
                            # Skip the page-root document: anything covering most of the window.
                            if (($r.Width * $r.Height) -gt ($winArea * 0.5)) { continue }
                            # Skip implausibly tall boxes (the composer is short).
                            if ($r.Height -gt 400) { continue }
                            if ($r.Bottom -gt $bestBottom) { $bestBottom = $r.Bottom; $best = $e }
                        } catch { }
                    }
                    if ($best) { return $best }
                }
            }
            Start-Sleep -Milliseconds 350   # let Chromium build the a11y tree, then retry
        }
    } catch { }
    return $null
}

function Find-ClaudeWindow {
    # Main window of the Claude desktop app (the Cowork host)
    # The Claude DESKTOP app only - never a browser (the portal page title contains
    # "Claude Portal", so a title match would wrongly grab the browser and inject there).
    $browsers = 'chrome','msedge','firefox','brave','opera','arc','vivaldi','iexplore','safari'
    $cands = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle -and
        ($_.ProcessName -notin $browsers) -and
        ($_.MainWindowTitle -notlike '*Claude Portal*') -and
        ($_.ProcessName -like '*claude*' -or $_.ProcessName -like '*cowork*' -or $_.MainWindowTitle -like '*Claude*')
    }
    if (-not $cands) { return $null }
    # The main chat window has the shortest title (not a child dialog).
    return ($cands | Sort-Object { $_.MainWindowTitle.Length } | Select-Object -First 1)
}

# Send Escape to Cowork to stop generation, then return focus to the portal.
function Send-Stop {
    $prevFg = [Win32]::GetForegroundWindow()
    $proc = Find-ClaudeWindow
    if (-not $proc) { return 'window-not-found' }
    $hwnd = $proc.MainWindowHandle
    [Win32]::ForceForeground($hwnd) | Out-Null
    Start-Sleep -Milliseconds 200
    [Win32]::PressKey([byte]0x1B, $false)   # Esc
    Start-Sleep -Milliseconds 120
    if ($prevFg -ne [IntPtr]::Zero -and $prevFg -ne $hwnd -and [Win32]::GetForegroundWindow() -ne $prevFg) {
        [Win32]::ForceForegroundKeep($prevFg) | Out-Null
    }
    return 'ok'
}

# Find a Cowork button whose accessible name matches one of the patterns and invoke it.
# Scans ALL top-level windows of the process (dialogs can live outside the main window).
function Invoke-NamedButton([int]$procId, [IntPtr]$hwnd, [string[]]$patterns) {
    if (-not $script:UIA) { return $false }
    try {
        $roots = @()
        try {
            $pidCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $procId)
            foreach ($w in [System.Windows.Automation.AutomationElement]::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children, $pidCond)) { $roots += $w }
        } catch { }
        if ($roots.Count -eq 0) {
            $r0 = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
            if ($r0) { $roots += $r0 }
        }
        $ctp = [System.Windows.Automation.AutomationElement]::ControlTypeProperty
        # AskUserQuestion options and dialog choices are not always plain Buttons -
        # scan the clickable control types too.
        $types = @(
            [System.Windows.Automation.ControlType]::Button,
            [System.Windows.Automation.ControlType]::Hyperlink,
            [System.Windows.Automation.ControlType]::ListItem,
            [System.Windows.Automation.ControlType]::RadioButton,
            [System.Windows.Automation.ControlType]::CheckBox,
            [System.Windows.Automation.ControlType]::MenuItem,
            [System.Windows.Automation.ControlType]::Custom
        )
        $tconds = @(); foreach ($t in $types) { $tconds += (New-Object System.Windows.Automation.PropertyCondition($ctp, $t)) }
        $cond = New-Object System.Windows.Automation.OrCondition([System.Windows.Automation.Condition[]]$tconds)
        $btns = @()
        foreach ($root in $roots) {
            try { foreach ($b in $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)) { $btns += $b } } catch { }
        }
        foreach ($pat in $patterns) {
            foreach ($b in $btns) {
                try {
                    if (-not $b.Current.IsEnabled) { continue }
                    if ($b.Current.Name -match $pat) {
                        $ip = $null
                        if ($b.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$ip)) {
                            $ip.Invoke(); Write-Host ("  invoked: '" + $b.Current.Name + "'") -ForegroundColor DarkGray; return $true
                        }
                        $sp = $null
                        if ($b.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$sp)) {
                            $sp.Select(); Write-Host ("  selected: '" + $b.Current.Name + "'") -ForegroundColor DarkGray; return $true
                        }
                        $tp = $null
                        if ($b.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$tp)) {
                            $tp.Toggle(); Write-Host ("  toggled: '" + $b.Current.Name + "'") -ForegroundColor DarkGray; return $true
                        }
                        # Last resort: click the element's center point.
                        try {
                            $br = $b.Current.BoundingRectangle
                            if ($br.Width -gt 0 -and $br.Height -gt 0) {
                                [Win32]::ClickAt([int]($br.X + $br.Width/2), [int]($br.Y + $br.Height/2))
                                Write-Host ("  clicked-at: '" + $b.Current.Name + "'") -ForegroundColor DarkGray; return $true
                            }
                        } catch { }
                    }
                } catch { }
            }
        }
        # Remember what WAS available so /api/action can report it for debugging.
        $avail = @()
        foreach ($b in $btns) { try { $n = $b.Current.Name; if ($n -and ($avail -notcontains $n)) { $avail += $n } } catch { } }
        $script:LastButtons = $avail
        Write-Host "  no matching control. Available:" -ForegroundColor Yellow
        foreach ($n in $avail) { Write-Host ("    '" + $n + "'") -ForegroundColor DarkGray }
    } catch { }
    return $false
}

# Bring Cowork forward, invoke a named native button (new chat / add folder / any
# label sent from the portal, e.g. an AskUserQuestion option or a dialog's Allow), return focus.
function Do-Action([string]$target, [string]$rawPattern) {
    $prevFg = [Win32]::GetForegroundWindow()
    $proc = Find-ClaudeWindow
    if (-not $proc) { return 'window-not-found' }
    $hwnd = $proc.MainWindowHandle
    [Win32]::ForceForeground($hwnd) | Out-Null
    Start-Sleep -Milliseconds 250
    $patterns = switch ($target) {
        'newchat'   { @('(?i)new chat','(?i)new conversation','(?i)new task','(?i)^new$') }
        'addfolder' { @('(?i)add folder','(?i)add files','(?i)attach folder','(?i)^add$','(?i)folder') }
        default     { @() }
    }
    if ($rawPattern) {
        $escp = [regex]::Escape($rawPattern)
        # exact match first, then partial (accessible names sometimes append hints like "Enter")
        $patterns = @(('(?i)^' + $escp + '$'), ('(?i)' + $escp))
    }
    $ok = Invoke-NamedButton ([int]$proc.Id) $hwnd $patterns
    Start-Sleep -Milliseconds 150
    if ($prevFg -ne [IntPtr]::Zero -and $prevFg -ne $hwnd -and [Win32]::GetForegroundWindow() -ne $prevFg) {
        [Win32]::ForceForegroundKeep($prevFg) | Out-Null
    }
    if ($ok) { return 'ok' } else { return 'button-not-found' }
}

# --- Approval-dialog watcher ---
# The UIA scan over Electron's accessibility tree takes seconds, so it must NOT
# run on the (single-threaded) HTTP loop. A background runspace rescans every
# few seconds and publishes the result to a synchronized cache; /api/prompt
# just returns the cached JSON instantly.
$script:PromptCache = [hashtable]::Synchronized(@{ json = '{"found":false}' })
$script:PromptWatcher = $null
function Start-PromptWatcher {
    $sb = {
        param($cache)
        try { Add-Type -AssemblyName UIAutomationClient; Add-Type -AssemblyName UIAutomationTypes } catch { }
        function EscJ([string]$s) {
            if ($null -eq $s) { return '' }
            $s = $s.Replace('\', '\\').Replace('"', '\"')
            return $s.Replace("`r", '').Replace("`n", '\n').Replace("`t", '\t')
        }
        $browsers = 'chrome','msedge','firefox','brave','opera','arc','vivaldi','iexplore','safari'
        while ($true) {
            $json = '{"found":false}'
            try {
                # Include EVERY Claude/Cowork process - even those with an empty window
                # title (permission dialogs such as the web-fetch prompt are often hosted
                # in a separate child-process window whose title is blank, which the old
                # title-required filter excluded entirely).
                $cands = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                    ($_.ProcessName -like '*claude*' -or $_.ProcessName -like '*cowork*') -or
                    ($_.MainWindowHandle -ne 0 -and $_.MainWindowTitle -and
                     ($_.ProcessName -notin $browsers) -and
                     ($_.MainWindowTitle -notlike '*Claude Portal*') -and
                     ($_.MainWindowTitle -like '*Claude*'))
                }
                # Scan ALL top-level windows of every candidate process (by PID), so a
                # dialog hosted in its own (possibly title-less) window is still seen.
                $roots = @()
                $seenPids = @{}
                foreach ($cp in @($cands)) {
                    if ($seenPids.ContainsKey($cp.Id)) { continue }
                    $seenPids[$cp.Id] = $true
                    try {
                        $pidCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, [int]$cp.Id)
                        foreach ($w in [System.Windows.Automation.AutomationElement]::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children, $pidCond)) { $roots += $w }
                    } catch { }
                }
                foreach ($root in $roots) {
                    if ($json -ne '{"found":false}') { break }
                    try {
                        $ctp = [System.Windows.Automation.AutomationElement]::ControlTypeProperty
                        $bcond = New-Object System.Windows.Automation.PropertyCondition($ctp, [System.Windows.Automation.ControlType]::Button)
                        $btns = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $bcond)
                        $strong  = '(?i)^(allow|approve|accept|grant|confirm|always allow|allow once|allow always|continue|connect|authorize|enable|yes\b)'
                        $dismiss = '(?i)^(deny|decline|cancel|reject|no\b|don.t|later|not now|dismiss)'
                        # Collect every enabled approve / dismiss button with its rectangle.
                        $approves = @(); $denies = @()
                        foreach ($b in $btns) {
                            try {
                                if (-not $b.Current.IsEnabled) { continue }
                                $nm = $b.Current.Name; if (-not $nm) { continue }
                                $r = $b.Current.BoundingRectangle
                                if ($r.Width -le 0 -or $r.Height -le 0) { continue }
                                if ($nm -match $strong)  { $approves += [pscustomobject]@{ n=$nm; r=$r } }
                                elseif ($nm -match $dismiss) { $denies += [pscustomobject]@{ n=$nm; r=$r } }
                            } catch { }
                        }
                        # A real dialog = an approve button with a dismiss button on the
                        # SAME row (similar Y, close X). Geometry avoids the full-window
                        # modal backdrop that broke the ancestor-walk approach.
                        $pair = $null
                        foreach ($a in $approves) {
                            foreach ($d in $denies) {
                                $dy = [Math]::Abs(($a.r.Y + $a.r.Height/2) - ($d.r.Y + $d.r.Height/2))
                                $dx = [Math]::Abs($a.r.X - $d.r.X)
                                if ($dy -le 40 -and $dx -le 900) { $pair = [pscustomobject]@{ a=$a; d=$d }; break }
                            }
                            if ($pair) { break }
                        }
                        if ($pair) {
                            $rowY = $pair.a.r.Y + $pair.a.r.Height/2
                            # ALL action buttons on the dialog's button row (handles N-button
                            # dialogs like "Allow once / Allow all for website / Deny"), left-to-right.
                            $rowBtns = @()
                            foreach ($x in ($approves + $denies)) {
                                $cy = $x.r.Y + $x.r.Height/2
                                if ([Math]::Abs($cy - $rowY) -le 40) { $rowBtns += $x }
                            }
                            $rowBtns = $rowBtns | Sort-Object { $_.r.X }
                            $minX = ($rowBtns | ForEach-Object { $_.r.X } | Measure-Object -Minimum).Minimum
                            $maxXr = ($rowBtns | ForEach-Object { $_.r.X + $_.r.Width } | Measure-Object -Maximum).Maximum
                            $loX = $minX - 360
                            $hiX = $maxXr + 60
                            # Collect Text controls sitting just ABOVE the button row (the
                            # dialog message), within a ~220px band and horizontal span.
                            $tcond = New-Object System.Windows.Automation.PropertyCondition($ctp, [System.Windows.Automation.ControlType]::Text)
                            $noise = '(?i)^(write a message|send a message|opus|sonnet|haiku|fable|claude\b.*\d|used a tool|tomer|max\b|stop\b)'
                            $texts = @()
                            foreach ($t in $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tcond)) {
                                try {
                                    $n = $t.Current.Name; if (-not $n -or $n.Trim().Length -eq 0) { continue }
                                    if ($n -match $noise) { continue }   # strip chat chrome / composer / model label
                                    $tr = $t.Current.BoundingRectangle
                                    $ty = $tr.Y + $tr.Height/2
                                    if ($ty -lt $rowY -and $ty -ge ($rowY - 170) -and $tr.X -ge ($loX - 40) -and $tr.X -le $hiX) {
                                        if ($texts -notcontains $n) { $texts += $n }
                                    }
                                } catch { }
                            }
                            # List every action button (all approves + denies on the row),
                            # in visual left-to-right order, so multi-option dialogs show fully.
                            $bnames = @()
                            foreach ($x in $rowBtns) { if ($bnames -notcontains $x.n) { $bnames += $x.n } }
                            if ($bnames.Count -eq 0) { $bnames = @($pair.a.n, $pair.d.n) }
                            $msg = ($texts -join ' '); if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '…' }
                            $bjson = (($bnames | Select-Object -First 6 | ForEach-Object { '"' + (EscJ $_) + '"' }) -join ',')
                            $json = '{"found":true,"text":"' + (EscJ $msg) + '","buttons":[' + $bjson + ']}'
                        }
                    } catch { }
                }
            } catch { }
            $cache['json'] = $json
            Start-Sleep -Milliseconds 2000
        }
    }
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($sb).AddArgument($script:PromptCache)
    [void]$ps.BeginInvoke()
    $script:PromptWatcher = $ps
}

# --- Fallback: bring window to foreground and type (flickers, but very reliable) ---
function Send-Foreground([string]$text, [bool]$submit) {
    try {
        $proc = Find-ClaudeWindow
        if (-not $proc) { return 'window-not-found' }
        # NOTE: we deliberately do NOT touch the clipboard here - the text is TYPED,
        # so there is no need to overwrite the user's clipboard / Win+V history.
        $hwnd = $proc.MainWindowHandle
        # Remember if Cowork was minimized/hidden before we pulled it forward. On a
        # multi-monitor setup just restoring focus to the portal leaves Cowork sitting
        # visible on the other screen, so if it started minimized we re-minimize it.
        $wasIconic = $false
        try { $wasIconic = [Win32]::IsIconic($hwnd) } catch { }
        [Win32]::ForceForeground($hwnd) | Out-Null
        Start-Sleep -Milliseconds 300
        # Retry once if Windows still hasn't handed over focus
        if ([Win32]::GetForegroundWindow() -ne $hwnd) {
            [Win32]::ForceForeground($hwnd) | Out-Null
            Start-Sleep -Milliseconds 250
            if ([Win32]::GetForegroundWindow() -ne $hwnd) { return 'focus-failed' }
        }
        # Give the composer caret focus. Prefer UI Automation: locate the element,
        # click its exact center (from UIA bounds), and SetFocus. Fall back to a
        # bottom-center click only if UIA never exposes the tree.
        $el = Find-Composer $hwnd
        $method = ''
        if ($el) {
            try {
                $b = $el.Current.BoundingRectangle
                $cx = [int]($b.X + $b.Width / 2)
                $cy = [int]($b.Y + $b.Height / 2)
                [Win32]::ClickAt($cx, $cy)
                Start-Sleep -Milliseconds 80
                try { $el.SetFocus() } catch { }
                $method = "UIA (" + [int]$b.X + "," + [int]$b.Y + " " + [int]$b.Width + "x" + [int]$b.Height + ")"
            } catch { $method = 'UIA-bounds-error' }
        } else {
            $r = [Win32]::GetRect($hwnd)
            $cx = [int](($r.Left + $r.Right) / 2)
            $cy = [int]($r.Bottom - 70)
            [Win32]::ClickAt($cx, $cy)
            $method = 'click-fallback (UIA empty)'
        }
        Write-Host ("  composer focus: " + $method) -ForegroundColor DarkGray
        # Give the composer extra time to gain focus before typing. A too-short
        # settle is the main cause of the random "only half the message typed"
        # bug: the first keystrokes fire while the editor is still focusing and
        # React drops them. Settle, then re-assert focus right before typing.
        Start-Sleep -Milliseconds 380
        if ($el) { try { $el.SetFocus(); Start-Sleep -Milliseconds 90 } catch { } }
        # Inject the text as real Unicode keystrokes. Split on newlines and use
        # Shift+Enter between lines so a multi-line message doesn't submit early.
        $VK_RETURN = [byte]0x0D
        $lines = $text -replace "`r`n", "`n" -split "`n"
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i].Length -gt 0) { [Win32]::TypeUnicode($lines[$i]) }
            if ($i -lt $lines.Count - 1) { [Win32]::PressKey($VK_RETURN, $true); Start-Sleep -Milliseconds 45 }
        }
        # Let the editor settle so focus is stable before we press Enter to send.
        Start-Sleep -Milliseconds 350
        if ($submit) { [Win32]::PressKey($VK_RETURN, $false) }
        Write-Host "  (typed via SendInput; text also on clipboard as backup)" -ForegroundColor DarkGray
        # If Cowork was minimized before, tuck it back so it doesn't linger on a
        # second monitor. SW_MINIMIZE (6) also hands activation to the window behind
        # it (the portal); the dispatcher then re-asserts portal focus.
        if ($wasIconic) { Start-Sleep -Milliseconds 120; try { [Win32]::ShowWindow($hwnd, 6) | Out-Null } catch { } }
        return 'ok'
    } catch {
        Write-Host ("  send error: " + $_.Exception.Message) -ForegroundColor Red
        return ('error: ' + $_.Exception.Message)
    }
}

# Find the Send button via UIA (a Button near the composer, bottom-right of the window).
function Find-SendButton([IntPtr]$hwnd) {
    if (-not $script:UIA) { return $null }
    try {
        $root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
        if (-not $root) { return $null }
        $scope = [System.Windows.Automation.TreeScope]::Descendants
        $ctp = [System.Windows.Automation.AutomationElement]::ControlTypeProperty
        $cond = New-Object System.Windows.Automation.PropertyCondition($ctp, [System.Windows.Automation.ControlType]::Button)
        $btns = $root.FindAll($scope, $cond)
        # SAFETY: only ever return a button EXPLICITLY named like "send". Never guess by
        # position - a positional guess once hit the thumbs-down/feedback button, opened
        # the "Give negative feedback" dialog, and risked submitting the whole conversation
        # to Anthropic. Any non-send button is ignored; if no named send button exists the
        # caller falls back to focusing the composer and pressing Enter (always safe).
        $deny = '(?i)(feedback|report|thumbs|dislike|like\b|good response|bad response|submit|cancel|close|stop|copy|retry|regenerate|share|delete|new chat|new task|menu|settings|attach|upload)'
        foreach ($b in $btns) {
            try {
                if (-not $b.Current.IsEnabled) { continue }
                $r = $b.Current.BoundingRectangle
                if ($r.Width -le 0 -or $r.Height -le 0) { continue }
                $name = $b.Current.Name
                if (-not $name) { continue }
                if ($name -match $deny) { continue }
                if ($name -match '(?i)^\s*send(\s*message)?\s*$' -or $name -match '(?i)\bsend message\b') {
                    Write-Host ("    send button: '" + $name + "'") -ForegroundColor DarkGray
                    return $b
                }
            } catch { }
        }
        Write-Host "    no explicitly-named send button - will submit via Enter" -ForegroundColor DarkGray
        return $null
    } catch { return $null }
}

# --- Primary: try TRUE BACKGROUND (no foreground); fall back to foreground+Enter;
#     in every case, return focus to whatever window was in front (the portal). ---
function Send-Background([string]$text, [bool]$submit, $files) {
    $prevFg = [Win32]::GetForegroundWindow()   # the portal/browser the user clicked Send in
    try {
        $proc = Find-ClaudeWindow
        if (-not $proc) { return 'window-not-found' }
        $hwnd = $proc.MainWindowHandle
        # If Cowork started minimized, re-minimize it after sending (multi-monitor fix).
        $wasIconic = $false
        try { $wasIconic = [Win32]::IsIconic($hwnd) } catch { }

        # --- File attachment path (screenshots / PDFs / any files, one or many) ---
        # Attaching needs to paste into the composer, which requires foreground focus.
        # A single image goes on the clipboard as a bitmap; everything else (and any
        # multi-file selection) goes as a CF_HDROP file list - one paste attaches all.
        if ($files -and $files.Count -gt 0) {
            try {
                if ($files.Count -eq 1 -and $files[0].type -like 'image/*') {
                    $bytes = [Convert]::FromBase64String($files[0].b64)
                    $ms = New-Object System.IO.MemoryStream(,$bytes)
                    $img = [System.Drawing.Image]::FromStream($ms)
                    [System.Windows.Forms.Clipboard]::SetImage($img)
                    Write-Host "  image placed on clipboard" -ForegroundColor DarkGray
                } else {
                    $dir = Join-Path $env:TEMP 'ClaudePortal'
                    New-Item -ItemType Directory -Force -Path $dir | Out-Null
                    $col = New-Object System.Collections.Specialized.StringCollection
                    foreach ($f in $files) {
                        $bytes = [Convert]::FromBase64String($f.b64)
                        $safe = if ($f.name) { [System.IO.Path]::GetFileName($f.name) } else { ('attachment_' + [Guid]::NewGuid().ToString('N').Substring(0,6) + '.bin') }
                        $fp = Join-Path $dir $safe
                        [System.IO.File]::WriteAllBytes($fp, $bytes)
                        [void]$col.Add($fp)
                    }
                    [System.Windows.Forms.Clipboard]::SetFileDropList($col)
                    Write-Host ("  " + $col.Count + " file(s) placed on clipboard") -ForegroundColor DarkGray
                }
            } catch { Write-Host ("  file decode failed: " + $_.Exception.Message) -ForegroundColor Red; return 'file-decode-failed' }

            [Win32]::ForceForeground($hwnd) | Out-Null
            Start-Sleep -Milliseconds 250
            $elc = Find-Composer $hwnd
            if ($elc) {
                try {
                    $bb = $elc.Current.BoundingRectangle
                    [Win32]::ClickAt([int]($bb.X + $bb.Width/2), [int]($bb.Y + $bb.Height/2))
                    Start-Sleep -Milliseconds 60
                    try { $elc.SetFocus() } catch { }
                } catch { }
            }
            [Win32]::CtrlKey(0x56)              # Ctrl+V -> paste the file
            Start-Sleep -Milliseconds 700       # let Cowork attach/upload the file
            if ($text -and $text.Trim().Length -gt 0) {
                $lns = $text -replace "`r`n", "`n" -split "`n"
                for ($k = 0; $k -lt $lns.Count; $k++) {
                    if ($lns[$k].Length -gt 0) { [Win32]::TypeUnicode($lns[$k]) }
                    if ($k -lt $lns.Count - 1) { [Win32]::PressKey([byte]0x0D, $true); Start-Sleep -Milliseconds 30 }
                }
                Start-Sleep -Milliseconds 150
            }
            if ($submit) { [Win32]::PressKey([byte]0x0D, $false) }
            Start-Sleep -Milliseconds 120
            if ($wasIconic) { try { [Win32]::ShowWindow($hwnd, 6) | Out-Null } catch { } }
            if ($prevFg -ne [IntPtr]::Zero -and $prevFg -ne $hwnd -and [Win32]::GetForegroundWindow() -ne $prevFg) {
                [Win32]::ForceForegroundKeep($prevFg) | Out-Null
            }
            return 'ok'
        }

        [System.Windows.Forms.Clipboard]::SetText($text)   # backup so user can Ctrl+V
        $el = Find-Composer $hwnd
        if (-not $el) {
            # UIA didn't expose the composer (its a11y tree can be slow/asleep).
            # Fall back to the reliable geometric method: foreground + click the
            # composer area + type. Then return focus to the portal.
            Write-Host "  composer not found via UIA - falling back to foreground+type" -ForegroundColor Yellow
            $fg = Send-Foreground $text $submit
            if ($prevFg -ne [IntPtr]::Zero -and $prevFg -ne $hwnd -and [Win32]::GetForegroundWindow() -ne $prevFg) {
                [Win32]::ForceForegroundKeep($prevFg) | Out-Null
            }
            return $fg
        }

        # 1) Put the text in the box via ValuePattern - no focus / no foreground.
        $vp = $null; $set = $false
        if ($el.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vp)) {
            try { $vp.SetValue($text); $set = $true; Write-Host "  ValuePattern.SetValue ok (background)" -ForegroundColor DarkGray }
            catch { Write-Host ("  SetValue failed: " + $_.Exception.Message) -ForegroundColor Red }
        } else {
            Write-Host "  composer exposes no ValuePattern" -ForegroundColor Yellow
        }

        $submitted = $false
        if ($submit) {
            # 2a) Try to submit in the background by invoking the Send button.
            $btn = Find-SendButton $hwnd
            if ($btn) {
                $ip = $null
                if ($btn.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$ip)) {
                    try { $ip.Invoke(); $submitted = $true; Write-Host "  send button invoked (background)" -ForegroundColor DarkGray }
                    catch { Write-Host ("  invoke failed: " + $_.Exception.Message) -ForegroundColor Red }
                }
            }
            # 2b) Fallback: foreground the window and press Enter (text is already in the box).
            if (-not $submitted) {
                Write-Host "  background submit unavailable - falling back to foreground+Enter" -ForegroundColor Yellow
                [Win32]::ForceForeground($hwnd) | Out-Null
                Start-Sleep -Milliseconds 250
                $el2 = Find-Composer $hwnd
                if ($el2) {
                    try {
                        $b = $el2.Current.BoundingRectangle
                        [Win32]::ClickAt([int]($b.X + $b.Width/2), [int]($b.Y + $b.Height/2))
                        Start-Sleep -Milliseconds 60
                        try { $el2.SetFocus() } catch { }
                    } catch { }
                }
                # If SetValue didn't work, type the text now (window is foreground).
                if (-not $set) {
                    $lines = $text -replace "`r`n", "`n" -split "`n"
                    for ($i = 0; $i -lt $lines.Count; $i++) {
                        if ($lines[$i].Length -gt 0) { [Win32]::TypeUnicode($lines[$i]) }
                        if ($i -lt $lines.Count - 1) { [Win32]::PressKey([byte]0x0D, $true); Start-Sleep -Milliseconds 30 }
                    }
                    Start-Sleep -Milliseconds 150
                }
                [Win32]::PressKey([byte]0x0D, $false)   # Enter -> submit
                $submitted = $true
            }
        }

        # 3) Return focus to the portal/browser so Claude doesn't stay in front.
        #    Use the state-preserving variant so a maximized portal stays maximized.
        Start-Sleep -Milliseconds 120
        if ($wasIconic) { try { [Win32]::ShowWindow($hwnd, 6) | Out-Null } catch { } }
        if ($prevFg -ne [IntPtr]::Zero -and $prevFg -ne $hwnd -and [Win32]::GetForegroundWindow() -ne $prevFg) {
            [Win32]::ForceForegroundKeep($prevFg) | Out-Null
            Write-Host "  focus returned to portal" -ForegroundColor DarkGray
        }

        if (-not $set -and -not $submitted) { return 'setvalue-unsupported' }
        return 'ok'
    } catch {
        Write-Host ("  bg send error: " + $_.Exception.Message) -ForegroundColor Red
        try { if ($prevFg -ne [IntPtr]::Zero) { [Win32]::ForceForegroundKeep($prevFg) | Out-Null } } catch { }
        return ('error: ' + $_.Exception.Message)
    }
}

# Dispatcher. Files go through the background/paste path. Plain TEXT is TYPED via
# real keystrokes (Send-Foreground) - typing fires the input events that Cowork's
# React composer needs, so the Send button enables and the message actually sends.
# (ValuePattern.SetValue fills the DOM but React ignores it -> "copied but not sent".)
function Send-ToCowork([string]$text, [bool]$submit, $files) {
    if ($files -and $files.Count -gt 0) { return (Send-Background $text $submit $files) }
    $prevFg = [Win32]::GetForegroundWindow()
    $r = Send-Foreground $text $submit
    try { if ($prevFg -ne [IntPtr]::Zero -and [Win32]::GetForegroundWindow() -ne $prevFg) { [Win32]::ForceForegroundKeep($prevFg) | Out-Null } } catch { }
    return $r
}

# --- Locate Claude session storage (MSIX virtualized path) ---
$pkg = Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory -Filter 'Claude_*' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $pkg) { Fail "Claude Desktop is not installed (Claude package not found). Install Claude Desktop and try again." }
$sessRoot = Join-Path $pkg.FullName 'LocalCache\Roaming\Claude\local-agent-mode-sessions'
if (-not (Test-Path $sessRoot)) { Fail ("Claude session folder not found:`n" + $sessRoot + "`n`nOpen Claude Desktop at least once, then try again.") }

$htmlPath = Join-Path $PSScriptRoot 'ClaudePortal.html'
if (-not (Test-Path $htmlPath)) { Fail "ClaudePortal.html is missing (it must sit next to the server script)." }

# --- Auto-update: pull a newer SIGNED build from GitHub if one is published ---
# Returns $true if an update was applied (and a fresh instance was launched), so the
# caller should exit. Fully offline-safe: any failure leaves the current build running.
function Invoke-UpdateCheck {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    # Try each candidate base (main / master) until version.json is found.
    $mani = $null; $base = $null
    foreach ($b in $script:UpdateBases) {
        if ($b -match 'OWNER/REPO') { continue }
        try {
            $mani = Invoke-RestMethod -Uri ($b + '/version.json') -TimeoutSec 5 -ErrorAction Stop
            if ($mani -and $mani.version) { $base = $b; break }
        } catch { }
    }
    if (-not $base -or -not $mani -or -not $mani.version) {
        Write-Host "  update check skipped (offline, repo empty, or version.json not yet published)" -ForegroundColor DarkGray
        return $false
    }
    try { $remote = [version]$mani.version } catch { return $false }
    try { $local = [version]$script:AppVersion } catch { $local = [version]'0.0.0' }
    if ($remote -le $local) { Write-Host ("  up to date (v" + $script:AppVersion + ")") -ForegroundColor DarkGray; return $false }

    Write-Host ("`n  *** Update available: v" + $script:AppVersion + " -> v" + $mani.version + " ***") -ForegroundColor Yellow
    $stage = Join-Path $env:TEMP ('ClaudePortalUpdate_' + [Guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    try {
        $ProgressPreference = 'SilentlyContinue'
        foreach ($f in $mani.files) {
            $name = $f.name; $sha = ($f.sha256 + '').ToLower()
            $dest = Join-Path $stage $name
            Invoke-WebRequest -Uri ($base + '/' + $name) -OutFile $dest -TimeoutSec 30 -ErrorAction Stop
            if ($sha) {
                $got = (Get-FileHash $dest -Algorithm SHA256).Hash.ToLower()
                if ($got -ne $sha) { throw ("SHA-256 mismatch for " + $name) }
            }
            # Pin executable code to YOUR certificate: a hijacked repo cannot push an
            # unsigned or differently-signed .ps1.
            if ($name -like '*.ps1') {
                $sig = Get-AuthenticodeSignature -FilePath $dest
                if ($sig.Status -ne 'Valid') { throw ("downloaded " + $name + " is not validly signed (" + $sig.Status + ")") }
                if (($sig.SignerCertificate.Subject + '') -notmatch [regex]::Escape($script:UpdateExpectedSigner)) {
                    throw ("downloaded " + $name + " was signed by an unexpected certificate")
                }
            }
        }
        # Everything verified - swap the files in.
        foreach ($f in $mani.files) {
            Copy-Item -Path (Join-Path $stage $f.name) -Destination (Join-Path $PSScriptRoot $f.name) -Force
        }
        Write-Host ("  update installed (v" + $mani.version + ") - relaunching...") -ForegroundColor Green
        Start-Sleep -Milliseconds 400
        Start-Process powershell -ArgumentList @('-NoProfile','-STA','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
        return $true
    } catch {
        Write-Host ("  update FAILED - keeping current version. Reason: " + $_.Exception.Message) -ForegroundColor Red
        return $false
    } finally {
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}
if (Invoke-UpdateCheck) { exit }   # a newer build was installed and launched; let it take over

# Clean up leftover attachment temp files from previous runs.
$tmpAtt = Join-Path $env:TEMP 'ClaudePortal'
if (Test-Path $tmpAtt) {
    Get-ChildItem $tmpAtt -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-2) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

# --- Session index: id -> audit.jsonl path + title ---
$script:SessionMap = @{}
$script:LastButtons = @()

function Get-SessionMeta($auditDir) {
    # Reads the sibling metadata file <parent>\<dirname>.json once and returns both
    # the human title and whether the conversation is pinned/favorited in Cowork.
    $title = (Split-Path $auditDir -Leaf)
    $pinned = $false
    $meta = Join-Path (Split-Path $auditDir -Parent) ((Split-Path $auditDir -Leaf) + '.json')
    if (Test-Path $meta) {
        try {
            $sr = New-Object System.IO.StreamReader($meta, [System.Text.Encoding]::UTF8)
            $head = New-Object char[] 16384
            $n = $sr.Read($head, 0, 16384)
            $sr.Close()
            $txt = -join $head[0..($n-1)]
            foreach ($key in @('title', 'name', 'summary')) {
                $m = [regex]::Match($txt, '"' + $key + '"\s*:\s*"((?:[^"\\]|\\.)*)"')
                if ($m.Success -and $m.Groups[1].Value.Trim()) {
                    try { $title = (ConvertFrom-Json ('{"t":"' + $m.Groups[1].Value + '"}')).t } catch { $title = $m.Groups[1].Value }
                    break
                }
            }
            # Pin/favorite flag - Cowork's exact key isn't documented, so accept any of
            # the common spellings set to a truthy value (best-effort, never throws).
            if ([regex]::IsMatch($txt, '"(pinned|isPinned|favorite|isFavorite|starred|isStarred)"\s*:\s*true') -or
                [regex]::IsMatch($txt, '"(pinnedAt|favoritedAt)"\s*:\s*"[^"]+"')) { $pinned = $true }
        } catch { }
    }
    return @{ title = $title; pinned = $pinned }
}

$script:SessCache = $null
$script:SessCacheTs = [datetime]::MinValue
function Get-SessionsJson {
    $now = Get-Date
    # The recursive directory scan is slow; serve a cached copy for 5 seconds
    # so multiple portal tabs don't stack scans on the single-threaded loop.
    if ($script:SessCache -and (($now - $script:SessCacheTs).TotalSeconds -lt 5)) { return $script:SessCache }
    $list = @()
    $audits = Get-ChildItem $sessRoot -Recurse -Filter 'audit.jsonl' -Depth 4 -File -ErrorAction SilentlyContinue
    foreach ($a in ($audits | Sort-Object LastWriteTime -Descending | Select-Object -First 30)) {
        $dir = Split-Path $a.FullName -Parent
        $id = Split-Path $dir -Leaf
        $script:SessionMap[$id] = $a.FullName
        $sm = Get-SessionMeta $dir
        $list += [pscustomobject]@{
            id        = $id
            title     = $sm.title
            pinned    = [bool]$sm.pinned
            lastWrite = $a.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            size      = $a.Length
            active    = (($now - $a.LastWriteTime).TotalSeconds -lt 90)
        }
    }
    $script:SessCache = (ConvertTo-Json @($list) -Depth 4)
    $script:SessCacheTs = $now
    return $script:SessCache
}

# --- Kill any previous portal instances so we always rebind the same port ---
# NOTE: HttpListener ports are owned by http.sys (PID 4), so port scanning can
# NOT find the owning PowerShell. Instead each instance records its PID in a
# file, and the next instance kills whoever is listed there.
$pidFile = Join-Path $env:TEMP 'ClaudePortal.pids'
try {
    if (Test-Path $pidFile) {
        $killed = $false
        foreach ($opid in (Get-Content $pidFile -ErrorAction SilentlyContinue)) {
            if ($opid -match '^\d+$' -and [int]$opid -ne $PID) {
                $op = Get-Process -Id ([int]$opid) -ErrorAction SilentlyContinue
                if ($op -and ($op.ProcessName -like 'powershell*')) {
                    Write-Host ("  closing previous portal instance (PID " + $op.Id + ")") -ForegroundColor DarkGray
                    Stop-Process -Id $op.Id -Force -ErrorAction SilentlyContinue
                    $killed = $true
                }
            }
        }
        if ($killed) { Start-Sleep -Milliseconds 700 }   # let http.sys release the port
    }
} catch { }
try { Set-Content -Path $pidFile -Value $PID } catch { }

# --- HTTP server ---
$listener = New-Object System.Net.HttpListener
$port = $null
foreach ($p in 8377..8384) {
    try {
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://localhost:$p/")
        $listener.Start()
        $port = $p
        break
    } catch { }
}
if (-not $port) { Fail "No free port in range 8377-8384. Close other instances and try again." }

$url = "http://localhost:$port/"
Write-Host ""
Write-Host "  Claude Portal - Free Agent" -ForegroundColor Cyan
Write-Host "  Watching: $sessRoot"
Write-Host "  Portal:   $url" -ForegroundColor Green
Write-Host "  Close this window (or Ctrl+C) to stop."
Write-Host ""
Start-Process $url
Start-PromptWatcher   # background dialog scanner (keeps /api/prompt instant)

function Send-Bytes($resp, [byte[]]$bytes, $contentType) {
    $resp.ContentType = $contentType
    $resp.ContentLength64 = $bytes.Length
    $resp.OutputStream.Write($bytes, 0, $bytes.Length)
    $resp.OutputStream.Close()
}
function Send-Text($resp, [string]$text, $contentType) {
    Send-Bytes $resp ([System.Text.Encoding]::UTF8.GetBytes($text)) ($contentType + '; charset=utf-8')
}

$MaxInitialBytes = 8MB
$MaxChunk = 2MB

# --- System tray icon + right-click menu (replaces a taskbar window) ---
$script:RunKeyPath   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$script:RunKeyName   = 'ClaudePortal'
$script:LauncherPath = Join-Path $PSScriptRoot 'ClaudePortalHidden.vbs'
function Test-AutoStart {
    try { return [bool]((Get-ItemProperty -Path $script:RunKeyPath -Name $script:RunKeyName -ErrorAction SilentlyContinue).$($script:RunKeyName)) } catch { return $false }
}
function Set-AutoStart([bool]$on) {
    try {
        if ($on) { Set-ItemProperty -Path $script:RunKeyPath -Name $script:RunKeyName -Value ('wscript.exe "' + $script:LauncherPath + '"') }
        else     { Remove-ItemProperty -Path $script:RunKeyPath -Name $script:RunKeyName -ErrorAction SilentlyContinue }
    } catch { }
}
function New-PortalIcon {
    # Draw the "Stargate" portal icon in GDI+ (no external .ico file needed).
    try {
        $bmp = [System.Drawing.Bitmap]::new(32,32)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.Clear([System.Drawing.Color]::Transparent)
        $gp = [System.Drawing.Drawing2D.GraphicsPath]::new()
        $gp.AddEllipse(6,6,20,20)
        $pgb = [System.Drawing.Drawing2D.PathGradientBrush]::new($gp)
        $pgb.CenterColor = [System.Drawing.Color]::FromArgb(255,190,242,255)
        $pgb.SurroundColors = ,([System.Drawing.Color]::FromArgb(255,10,46,66))
        $g.FillEllipse($pgb,6,6,20,20)
        $pen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255,38,201,226), [single]3.2)
        $g.DrawEllipse($pen,3,3,26,26)
        $dotB = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255,150,236,255))
        foreach ($p in @(@(16,2.5),@(27.5,10.5),@(23,26),@(9,26),@(4.5,10.5))) {
            $g.FillEllipse($dotB, [single]($p[0]-1.7), [single]($p[1]-1.7), [single]3.4, [single]3.4)
        }
        $g.Dispose()
        return [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
    } catch { return [System.Drawing.SystemIcons]::Application }
}

$script:Notify = $null
try {
    $script:Notify = New-Object System.Windows.Forms.NotifyIcon
    $script:Notify.Icon = (New-PortalIcon)
    $script:Notify.Text = 'Claude Cowork Portal'
    $menu = New-Object System.Windows.Forms.ContextMenuStrip

    $miOpen = $menu.Items.Add('Open Portal')
    $miOpen.add_Click({ Start-Process $url }.GetNewClosure())

    $miUpd = $menu.Items.Add('Check for updates')
    $miUpd.add_Click({
        if (Invoke-UpdateCheck) { try { $script:Notify.Visible = $false } catch {}; try { $listener.Stop() } catch {}; exit }
        else { try { $script:Notify.ShowBalloonTip(3000, 'Claude Cowork Portal', 'You are running the latest version.', [System.Windows.Forms.ToolTipIcon]::Info) } catch {} }
    }.GetNewClosure())

    $miAuto = New-Object System.Windows.Forms.ToolStripMenuItem('Start with Windows')
    $miAuto.CheckOnClick = $true
    $miAuto.Checked = (Test-AutoStart)
    $miAuto.add_Click({ Set-AutoStart($miAuto.Checked) }.GetNewClosure())
    [void]$menu.Items.Add($miAuto)

    [void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

    $miQuit = $menu.Items.Add('Quit Claude Portal')
    $miQuit.add_Click({ try { $script:Notify.Visible = $false; $script:Notify.Dispose() } catch {}; try { Remove-Item $pidFile -Force -ErrorAction SilentlyContinue } catch {}; try { $listener.Stop() } catch {}; exit }.GetNewClosure())

    $script:Notify.ContextMenuStrip = $menu
    $script:Notify.add_MouseClick({ param($s,$e) if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) { Start-Process $url } }.GetNewClosure())
    $script:Notify.Visible = $true
} catch { Write-Host ("  tray icon unavailable: " + $_.Exception.Message) -ForegroundColor Yellow }

# Hide the console window so only the tray icon remains (skip for a diagnostic run,
# or if the tray icon failed to appear - never leave the user with no window at all).
if ($script:Notify -and $script:Notify.Visible -and $env:CLAUDEPORTAL_VISIBLE -ne '1') {
    try { [Win32]::ShowWindow([Win32]::GetConsoleWindow(), 0) | Out-Null } catch { }   # 0 = SW_HIDE
}

$asyncCtx = $null
while ($listener.IsListening) {
    try {
        if ($null -eq $asyncCtx) { $asyncCtx = $listener.BeginGetContext($null, $null) }
        if (-not $asyncCtx.AsyncWaitHandle.WaitOne(100)) { [System.Windows.Forms.Application]::DoEvents(); continue }
        $ctx = $listener.EndGetContext($asyncCtx); $asyncCtx = $null
        $req = $ctx.Request
        $resp = $ctx.Response
        $path = $req.Url.AbsolutePath
        if ($path -notin @('/api/stream','/api/prompt','/api/sessions')) { Write-Host ("  " + $req.HttpMethod + " " + $path) -ForegroundColor DarkGray }

        if ($path -eq '/') {
            Send-Bytes $resp ([System.IO.File]::ReadAllBytes($htmlPath)) 'text/html; charset=utf-8'
        }
        elseif ($path -eq '/api/sessions') {
            Send-Text $resp (Get-SessionsJson) 'application/json'
        }
        elseif ($path -eq '/api/stop' -and $req.HttpMethod -eq 'POST') {
            $r = Send-Stop
            Send-Text $resp ('{"status":"' + $r + '"}') 'application/json'
        }
        elseif ($path -eq '/api/shutdown' -and $req.HttpMethod -eq 'POST') {
            # Cleanly stop the (hidden) server from inside the portal.
            Send-Text $resp '{"status":"ok"}' 'application/json'
            Start-Sleep -Milliseconds 250
            try { if ($script:Notify) { $script:Notify.Visible = $false; $script:Notify.Dispose() } } catch { }
            try { $listener.Stop() } catch { }
            try { Remove-Item (Join-Path $env:TEMP 'ClaudePortal.pids') -Force -ErrorAction SilentlyContinue } catch { }
            exit 0
        }
        elseif ($path -eq '/api/action' -and $req.HttpMethod -eq 'POST') {
            $reader = New-Object System.IO.StreamReader($req.InputStream, [System.Text.Encoding]::UTF8)
            $body = $reader.ReadToEnd(); $reader.Close()
            $target = ''; $pattern = ''
            try { $jb = ConvertFrom-Json $body; $target = $jb.target; $pattern = $jb.pattern } catch { }
            $script:LastButtons = @()
            $r = Do-Action $target $pattern
            if ($r -eq 'button-not-found' -and $script:LastButtons.Count -gt 0) {
                $bl = (ConvertTo-Json @($script:LastButtons | Select-Object -First 40) -Compress)
                Send-Text $resp ('{"status":"' + $r + '","available":' + $bl + '}') 'application/json'
            } else {
                Send-Text $resp ('{"status":"' + $r + '"}') 'application/json'
            }
        }
        elseif ($path -eq '/api/prompt') {
            Send-Text $resp ($script:PromptCache['json']) 'application/json'
        }
        elseif ($path -eq '/api/send' -and $req.HttpMethod -eq 'POST') {
            $reader = New-Object System.IO.StreamReader($req.InputStream, [System.Text.Encoding]::UTF8)
            $body = $reader.ReadToEnd(); $reader.Close()
            $text = $null; $submit = $true; $files = @()
            try {
                $j = ConvertFrom-Json $body
                $text = $j.text
                if ($null -ne $j.submit) { $submit = [bool]$j.submit }
                if ($j.files) {
                    foreach ($f in $j.files) {
                        $files += [pscustomobject]@{
                            b64  = ($f.data -replace '^data:[^,]+,', '')   # strip data-URL prefix
                            name = $f.name
                            type = $f.type
                        }
                    }
                }
            } catch { }
            if ([string]::IsNullOrEmpty($text) -and $files.Count -eq 0) {
                $resp.StatusCode = 400; Send-Text $resp '{"status":"empty"}' 'application/json'
            } else {
                $r = Send-ToCowork $text $submit $files
                Send-Text $resp ('{"status":"' + $r + '"}') 'application/json'
            }
        }
        elseif ($path -eq '/api/stream') {
            $id = $req.QueryString['id']
            $from = [long]($req.QueryString['from'])
            if (-not $script:SessionMap.ContainsKey($id)) { [void](Get-SessionsJson) }
            if (-not $script:SessionMap.ContainsKey($id)) {
                $resp.StatusCode = 404; Send-Text $resp 'unknown session' 'text/plain'
            } else {
                $file = $script:SessionMap[$id]
                $fs = [System.IO.File]::Open($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                try {
                    $len = $fs.Length
                    # First request on a big file: start near the end
                    if ($from -eq 0 -and $len -gt $MaxInitialBytes) { $from = $len - $MaxInitialBytes }
                    if ($from -gt $len) { $from = 0 }  # file was rotated/truncated
                    $count = [Math]::Min($len - $from, $MaxChunk)
                    $bytes = New-Object byte[] $count
                    if ($count -gt 0) {
                        [void]$fs.Seek($from, [System.IO.SeekOrigin]::Begin)
                        $read = $fs.Read($bytes, 0, $count)
                        if ($read -lt $count) { $bytes = $bytes[0..($read-1)] }
                    }
                    $resp.Headers.Add('X-To', [string]($from + $bytes.Length))
                    $resp.Headers.Add('X-File-Length', [string]$len)
                    Send-Bytes $resp $bytes 'application/octet-stream'
                } finally { $fs.Close() }
            }
        }
        else {
            $resp.StatusCode = 404
            Send-Text $resp 'not found' 'text/plain'
        }
    } catch {
        $asyncCtx = $null
        try { $ctx.Response.StatusCode = 500; $ctx.Response.Close() } catch { }
    }
}
if ($script:Notify) { try { $script:Notify.Visible = $false; $script:Notify.Dispose() } catch { } }
# (end of script - this trailing comment shields the code from signature-block edit
# SIG # Begin signature block
# MIImpgYJKoZIhvcNAQcCoIImlzCCJpMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCwvO90joIohykS
# CT895AI2qapGFgitwXlt3RtYNRHh0KCCIDYwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggY7MIIEI6ADAgECAhAe+8IaP9/TEpwV8IWW2hHsMA0GCSqG
# SIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBT
# eXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBD
# QTAeFw0yNjA1MjQxMDAwMzNaFw0yNzA1MjQxMDAwMzJaMGExCzAJBgNVBAYTAklM
# MQ4wDAYDVQQIDAVIYWlmYTEOMAwGA1UEBwwFSGFpZmExGDAWBgNVBAoMD1RvbWVy
# IFdhc3Nlcm1hbjEYMBYGA1UEAwwPVG9tZXIgV2Fzc2VybWFuMIIBojANBgkqhkiG
# 9w0BAQEFAAOCAY8AMIIBigKCAYEAwnKZdT/Ez3jUiCsA4h3HsvEXBfKxIoKvdWna
# dC08VxXoBvdskHxwprpDbN0IOlz74pNsB0u/vGphX1hpE8Z67betQeGkP6Q6v4S/
# 4TixxN1AP7Uy4G26OVqLuFn72XMVl8Pf7grKNIXgGaR3plnYNtDttA2HbrrFu3L4
# 2p6AQ2pmIz+aJgy1iiOsLQnREfjIHUTalsfbZSGEYNuWSzt8rePUYGeCpurXln7L
# P94WLDmAW1kLW6GiBAYyCV9tBt7UZnxUWDSiSohcjy+takuzdUq6lJ7Mmxz+X0/y
# rNbVDRLZqQA6i12/ayKU2q2UDTEoeNQx74ida1twAP+Y1PbmE/Y0ibdDTge4rZym
# NkkG1EtBv81r42qvbzmv5BkYihNQrhCaQWYHDgZtHu4AI+ciGOmPsPonWf/wY6ur
# C510sVj9jG8zKJi6cRZ9vg3UShi5EzOnsZoXQhhBPKo+ku9qFFANlcP59tzO2N8u
# MGVzobJ1Bh66Z30KEjiDP14SWCvlAgMBAAGjggF4MIIBdDAMBgNVHRMBAf8EAjAA
# MD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jY3NjYTIwMjEuY3JsLmNlcnR1bS5w
# bC9jY3NjYTIwMjEuY3JsMHMGCCsGAQUFBwEBBGcwZTAsBggrBgEFBQcwAYYgaHR0
# cDovL2Njc2NhMjAyMS5vY3NwLWNlcnR1bS5jb20wNQYIKwYBBQUHMAKGKWh0dHA6
# Ly9yZXBvc2l0b3J5LmNlcnR1bS5wbC9jY3NjYTIwMjEuY2VyMB8GA1UdIwQYMBaA
# FN10XUwA23ufoHTKsW73PMAywHDNMB0GA1UdDgQWBBSISwXj51Gmf9xiex5S0b60
# o2f0YTBLBgNVHSAERDBCMAgGBmeBDAEEATA2BgsqhGgBhvZ3AgUBBDAnMCUGCCsG
# AQUFBwIBFhlodHRwczovL3d3dy5jZXJ0dW0ucGwvQ1BTMBMGA1UdJQQMMAoGCCsG
# AQUFBwMDMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAcYS/3kQd
# CS3b3tfGg4q5c2c+hQBwCPdXQqUbL/7GiTZuAdYhKp0/SAsnL09XicEeikp+u3+r
# dqzQQ3mhAmg25eHoTbDWmwb237kCgXIWqxxeBA8QNi2mgrFevwdJw9xZUb50lg3h
# vna03AX8NIn3m0Lz54hq8hvVaJeQShQU4keMxFIDrcFJxaeQdZ4c6LmfF4HnVoZL
# n7KfxionwYb3jTlw4OTEAi1Fl7v5bKjTdsAtHxf9WapApnRaIg5rqyCGSzAiuhHM
# YrbD+M3HkgZGuw2EEdh8WPxAVfdRHcnImRkpPt7dFriwoxbIQ685woziJhedOQVC
# 9/oPnH8y6Sezpsdh7ajIGvB0nZl8+X+cNEEclIWCSViZyQDqx9NkI6fClNAtIWvk
# ZvtldtHKIuZ635nKAuHGQEL0gE6Q0Vt86K09ty68uOQ/azXdrzr95MLvliKpgvmJ
# Gcb68DbYEUjrSOss97j0z0p4z3jH9NZ+fGoQEuhJ43gfVmXD2yA6t4Zwvo9n+nSU
# hXJxq+N2DkFgoEuBBq4u5ro0qiKoJH6Dn2vRvdeTupyi1GEN1j/VhLOfZlHBEkNp
# a34QTB/DKLlltJ/fAEZ+FiSpInS5M1EoMHz6EiR0JsP9ZRb6X94OtZQS73isixZI
# TkaNUJH30/u/yFKcE1EqQiUuqMy0m8xLgPkwgga0MIIEnKADAgECAhANx6xXBf8h
# mS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0z
# ODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGP
# NRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1I
# pYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5A
# vftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDRe
# b6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBUR
# Jg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/ao
# fEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQ
# skBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJ
# lIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev
# +7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6B
# aaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IB
# XTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQ
# VvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEE
# AjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9
# vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwb
# SI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTL
# xLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD
# 8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVk
# o43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRa
# Ps+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8
# cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRz
# W6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KC
# LPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau
# 1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPS
# xyZsq8WhbaM2tszWkPZPubdcMIIGuTCCBKGgAwIBAgIRAJmjgAomVTtlq9xuhKaz
# 6jkwDQYJKoZIhvcNAQEMBQAwgYAxCzAJBgNVBAYTAlBMMSIwIAYDVQQKExlVbml6
# ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLEx5DZXJ0dW0gQ2VydGlmaWNh
# dGlvbiBBdXRob3JpdHkxJDAiBgNVBAMTG0NlcnR1bSBUcnVzdGVkIE5ldHdvcmsg
# Q0EgMjAeFw0yMTA1MTkwNTMyMThaFw0zNjA1MTgwNTMyMThaMFYxCzAJBgNVBAYT
# AlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMT
# G0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBDQTCCAiIwDQYJKoZIhvcNAQEBBQAD
# ggIPADCCAgoCggIBAJ0jzwQwIzvBRiznM3M+Y116dbq+XE26vest+L7k5n5TeJkg
# H4Cyk74IL9uP61olRsxsU/WBAElTMNQI/HsE0uCJ3VPLO1UufnY0qDHG7yCnJOvo
# SNbIbMpT+Cci75scCx7UsKK1fcJo4TXetu4du2vEXa09Tx/bndCBfp47zJNsamzU
# yD7J1rcNxOw5g6FJg0ImIv7nCeNn3B6gZG28WAwe0mDqLrvU49chyKIc7gvCjan3
# GH+2eP4mYJASflBTQ3HOs6JGdriSMVoD1lzBJobtYDF4L/GhlLEXWgrVQ9m0pW37
# KuwYqpY42grp/kSYE4BUQrbLgBMNKRvfhQPskDfZ/5GbTCyvlqPN+0OEDmYGKlVk
# OMenDO/xtMrMINRJS5SY+jWCi8PRHAVxO0xdx8m2bWL4/ZQ1dp0/JhUpHEpABMc3
# eKax8GI1F03mSJVV6o/nmmKqDE6TK34eTAgDiBuZJzeEPyR7rq30yOVw2DvetlmW
# ssewAhX+cnSaaBKMEj9O2GgYkPJ16Q5Da1APYO6n/6wpCm1qUOW6Ln1J6tVImDyA
# B5Xs3+JriasaiJ7P5KpXeiVV/HIsW3ej85A6cGaOEpQA2gotiUqZSkoQUjQ9+hPx
# DVb/Lqz0tMjp6RuLSKARsVQgETwoNQZ8jCeKwSQHDkpwFndfCceZ/OfCUqjxAgMB
# AAGjggFVMIIBUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTddF1MANt7n6B0
# yrFu9zzAMsBwzTAfBgNVHSMEGDAWgBS2oVQ5AsOgP46KvPrU+Bym0ToO/TAOBgNV
# HQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwMAYDVR0fBCkwJzAloCOg
# IYYfaHR0cDovL2NybC5jZXJ0dW0ucGwvY3RuY2EyLmNybDBsBggrBgEFBQcBAQRg
# MF4wKAYIKwYBBQUHMAGGHGh0dHA6Ly9zdWJjYS5vY3NwLWNlcnR1bS5jb20wMgYI
# KwYBBQUHMAKGJmh0dHA6Ly9yZXBvc2l0b3J5LmNlcnR1bS5wbC9jdG5jYTIuY2Vy
# MDkGA1UdIAQyMDAwLgYEVR0gADAmMCQGCCsGAQUFBwIBFhhodHRwOi8vd3d3LmNl
# cnR1bS5wbC9DUFMwDQYJKoZIhvcNAQEMBQADggIBAHWIWA/lj1AomlOfEOxD/PQ7
# bcmahmJ9l0Q4SZC+j/v09CD2csX8Yl7pmJQETIMEcy0VErSZePdC/eAvSxhd7488
# x/Cat4ke+AUZZDtfCd8yHZgikGuS8mePCHyAiU2VSXgoQ1MrkMuqxg8S1FALDtHq
# nizYS1bIMOv8znyJjZQESp9RT+6NH024/IqTRsRwSLrYkbFq4VjNn/KV3Xd8dpmy
# QiirZdrONoPSlCRxCIi54vQcqKiFLpeBm5S0IoDtLoIe21kSw5tAnWPazS6sgN2o
# XvFpcVVpMcq0C4x/CLSNe0XckmmGsl9z4UUguAJtf+5gE8GVsEg/ge3jHGTYaZ/M
# yfujE8hOmKBAUkVa7NMxRSB1EdPFpNIpEn/pSHuSL+kWN/2xQBJaDFPr1AX0qLgk
# XmcEi6PFnaw5T17UdIInA58rTu3mefNuzUtse4AgYmxEmJDodf8NbVcU6VdjWtz0
# e58WFZT7tST6EWQmx/OoHPelE77lojq7lpsjhDCzhhp4kfsfszxf9g2hoCtltXhC
# X6NqsqwTT7xe8LgMkH4hVy8L1h2pqGLT2aNCx7h/F95/QvsTeGGjY7dssMzq/rSs
# hFQKLZ8lPb8hFTmiGDJNyHga5hZ59IGynk08mHhBFM/0MLeBzlAQq1utNjQprztZ
# 5vv/NJy8ua9AGbwkMWkOMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDAN
# BgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
# IEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5n
# IFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkw
# MzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVz
# cG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBG
# rC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwB
# SOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/
# 4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3
# K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROU
# INDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3
# w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46Yce
# NA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d
# 2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8x
# ymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+
# AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2b
# Qhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNV
# HRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSME
# GDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGlu
# Z1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBp
# bmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESe
# Y0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FU
# FqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7Y
# MTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0zi
# TN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/
# QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlq
# AcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3
# Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roan
# cJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/
# ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7
# IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdC
# vHlshtjdNXOCIUjsarfNZzGCBcYwggXCAgEBMGowVjELMAkGA1UEBhMCUEwxITAf
# BgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMgUy5BLjEkMCIGA1UEAxMbQ2VydHVt
# IENvZGUgU2lnbmluZyAyMDIxIENBAhAe+8IaP9/TEpwV8IWW2hHsMA0GCWCGSAFl
# AwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJ
# KoZIhvcNAQkEMSIEINDb7kFwkMelCg+VE1HeqP5BNuJbHTpXHuRtymL7aQX1MA0G
# CSqGSIb3DQEBAQUABIIBgAlGX1pS5l0LxAJ0j4rq6BoKB0OMDw/IrgPagucdp0M6
# iK1VUNfl7f8TFJg9iWw1Zx+Ov0hNI4EVJunVo80vIMJg0u5GiiHjllecurRg8T7w
# N+eXvFu4xyMmcjBfvaQiTQRBRtJDfQe8SngQESZEw3pln7oHGNQA4pO7RJoHxtZT
# Bse7RHR9Up6vSFQDtDZWF7L9eXx7b/oBQnUzSVTgTVJ8OhL0MGNYC903P52bABii
# EZIzbYpoR8Il5G/flMGtaaPI2LAw9k7CNh4phhvf0lRNK5/fxHZowUGFGT/yIZf+
# X6Yzb4HoLYya/0G+1dYKV1zbgsn6sW6a/ecdCbowJ3h6b8kZvrd+beIcU+GV34vh
# aI0FylTPJT2HXY4MkoNNpsjCBm81rRZBU2AF2ew0HO9dBwIiISyaBfuAvNCSf+yN
# 8/xGSp4O4aw5+2Ee0bUP4bzoU1xWJGjfgIsv9sAfLAJ49rnrU4v930oJBelw4vH8
# tybKLgTgov+/167hO5eWRKGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEy
# NTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAY
# BgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MTQx
# NzMxNTVaMC8GCSqGSIb3DQEJBDEiBCBoee6oV3vu0O2hEI1jdo7JGr3Ag5IhvEQ0
# qNXDE24NyTANBgkqhkiG9w0BAQEFAASCAgAgG9/yleU2Z2wWRiTRslW68jUMAGp4
# 8z/4hgFcmKlVk5PsmojvJm9/ZE4HMxzuBq8au4KenCLdNdnkdp89/HbQSqDx3LqO
# zykH+L4l/q0B3AVx4431GFoQgRP44iV/oIMI1LQQmJ/eGZnU3qWJPJevkTXmcwAw
# ClxoUCp5YX81eLn9ds81t5BJcAVmVtR7nqYI9VqLgQumSIx1V5WQr7O7oN3vP5Qj
# iF9MaVAiYKsNWtCyLmzAYx0OinAk1d5Ve0bp5/falcHkXnvSpiiRe8yCaDI/jw1r
# hA1B/iQlOA2d0jZmAP4QzDKlZmPDrGR0CTT837w4zk0X2BtYCISGOsFtBtiryYif
# LY1OynxyUnYrnNQcltweydm6U1NzWwx6KulC4vnJ5XB/cY7BmjZnuCOEJ98/RQ+D
# AgoWDWXxnpo9KHgLWfG74pmUib8xfi4Wdfdn+FQ2oBoJdssq8620jClr2d6pTZjH
# i8eLVURJ6Ntj+W5YijVRukxB2+RWsNK2gAM8D+qFtJNWYmqLTmD/D+EOxs5ynuiV
# W7yb4Y5w/IgwsiR/9ODz4jkfncz8iJytc1sjZc9SeA3k9KI6zNasIe2dJMpRDuw9
# PmwRdM55dCkTRq/1HO1vE7qyYoIV8LQxmrtoFTvbrqx+sAgRFgMgMInmB7n9WFtI
# dLM8CiFsJoMl+g==
# SIG # End signature block
