Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "june2025_int2_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42) # Slate 900
$cGray = [System.Drawing.Color]::FromArgb(100, 116, 139) # Slate 500
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240) # Slate 200
$cAxis = [System.Drawing.Color]::FromArgb(71, 85, 105) # Slate 600

# ==============================================================================
# 1. M1 Q1: Parallel lines r and s cut by transversal n (164 deg)
# ==============================================================================
function Render-M1Q1 {
    $outPath = Join-Path $imgDir "m1_q1_light.png"
    $w = 340; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $penArc = New-Object System.Drawing.Pen($cDark, 1.4)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushGray = New-Object System.Drawing.SolidBrush($cGray)
    $fontLabel = New-Object System.Drawing.Font("Arial", 12.0, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Italic)

    # Parallel lines r and s
    $lx = 30.0; $rx = 275.0
    $ry = 115.0; $sy = 215.0
    $g.DrawLine($penLine, [float]$lx, [float]$ry, [float]$rx, [float]$ry)
    $g.DrawLine($penLine, [float]$lx, [float]$sy, [float]$rx, [float]$sy)

    # Transversal line n
    $tx1 = 40.0;  $ty1 = 315.0
    $tx2 = 280.0; $ty2 = 45.0
    $g.DrawLine($penLine, [float]$tx1, [float]$ty1, [float]$tx2, [float]$ty2)

    $m = ($ty2 - $ty1) / ($tx2 - $tx1)
    $ir_x = $tx1 + ($ry - $ty1) / $m
    $is_x = $tx1 + ($sy - $ty1) / $m

    # Line labels
    $g.DrawString("r", $fontLabel, $brushDark, [float]($rx + 12), [float]($ry - 10))
    $g.DrawString("s", $fontLabel, $brushDark, [float]($rx + 12), [float]($sy - 10))
    $g.DrawString("n", $fontLabel, $brushDark, [float]($tx2 + 8), [float]($ty2 - 12))

    # Angle 164 deg at r (top-left obtuse angle)
    $g.DrawArc($penArc, [float]($ir_x - 22), [float]($ry - 22), 44.0, 44.0, 180.0, 132.0)
    $g.DrawString("164°", $fontVal, $brushDark, [float]($ir_x - 48), [float]($ry - 26))

    # Angle x deg at s (top-left obtuse angle)
    $g.DrawArc($penArc, [float]($is_x - 22), [float]($sy - 22), 44.0, 44.0, 180.0, 132.0)
    $g.DrawString("x°", $fontVal, $brushDark, [float]($is_x - 38), [float]($sy - 26))

    # Note
    $note = "Note: Figure not drawn to scale."
    $noteSize = $g.MeasureString($note, $fontNote)
    $g.DrawString($note, $fontNote, $brushGray, [float](($w - $noteSize.Width)/2), [float]($h - 22))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 2. M1 Q18: Line k through (0, 3) and (4, 0)
# ==============================================================================
function Render-M1Q18 {
    $outPath = Join-Path $imgDir "m1_q18_light.png"
    $w = 360; $h = 380
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.8)
    $penLine = New-Object System.Drawing.Pen($cDark, 2.2)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Italic)
    $fontNum = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)

    $cx = 175.0; $cy = 190.0
    $scale = 22.0 # -6 to 6

    # Grid
    for ($i = -6; $i -le 6; $i++) {
        $x = $cx + $i * $scale
        $y = $cy - $i * $scale
        $g.DrawLine($penGrid, [float]$x, [float]($cy - 6 * $scale), [float]$x, [float]($cy + 6 * $scale))
        $g.DrawLine($penGrid, [float]($cx - 6 * $scale), [float]$y, [float]($cx + 6 * $scale), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]($cx - 6.5 * $scale), [float]$cy, [float]($cx + 6.8 * $scale), [float]$cy)
    $g.DrawLine($penAxis, [float]$cx, [float]($cy + 6.5 * $scale), [float]$cx, [float]($cy - 6.8 * $scale))

    # Arrows
    $arrow = 5.0
    $g.DrawLine($penAxis, [float]($cx + 6.8 * $scale), [float]$cy, [float]($cx + 6.8 * $scale - $arrow), [float]($cy - $arrow))
    $g.DrawLine($penAxis, [float]($cx + 6.8 * $scale), [float]$cy, [float]($cx + 6.8 * $scale - $arrow), [float]($cy + $arrow))
    $g.DrawLine($penAxis, [float]$cx, [float]($cy - 6.8 * $scale), [float]($cx - $arrow), [float]($cy - 6.8 * $scale + $arrow))
    $g.DrawLine($penAxis, [float]$cx, [float]($cy - 6.8 * $scale), [float]($cx + $arrow), [float]($cy - 6.8 * $scale + $arrow))

    # Ticks and numbers
    for ($i = -6; $i -le 6; $i += 2) {
        if ($i -ne 0) {
            $x = $cx + $i * $scale
            $y = $cy - $i * $scale
            $nStr = "$i"
            $nSize = $g.MeasureString($nStr, $fontNum)
            $g.DrawString($nStr, $fontNum, $brushDark, [float]($x - $nSize.Width/2), [float]($cy + 4))
            $g.DrawString($nStr, $fontNum, $brushDark, [float]($cx - $nSize.Width - 4), [float]($y - $nSize.Height/2))
        }
    }
    $g.DrawString("O", $fontNum, $brushDark, [float]($cx - 14), [float]($cy + 3))
    $g.DrawString("x", $fontAxis, $brushDark, [float]($cx + 6.9 * $scale), [float]($cy - 16))
    $g.DrawString("y", $fontAxis, $brushDark, [float]($cx - 16), [float]($cy - 7.3 * $scale))

    # Line k: slope -3/4, y = -3/4 x + 3
    # When x = -4 -> y = 6; when x = 6 -> y = -1.5
    $p1x = $cx + (-4.0) * $scale; $p1y = $cy - 6.0 * $scale
    $p2x = $cx + 6.0 * $scale;    $p2y = $cy - (-1.5) * $scale
    $g.DrawLine($penLine, [float]$p1x, [float]$p1y, [float]$p2x, [float]$p2y)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 3. M2 Q7: Game points graph x + y = 49 (from (0, 49) to (49, 0))
# ==============================================================================
function Render-M2Q7 {
    $outPath = Join-Path $imgDir "m2_q7_light.png"
    $w = 360; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.8)
    $penLine = New-Object System.Drawing.Pen($cDark, 2.2)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Italic)
    $fontNum = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)

    $ox = 45.0; $oy = 310.0
    $plotW = 270.0; $plotH = 270.0
    $stepX = $plotW / 10.0 # 0 to 50 in steps of 5
    $stepY = $plotH / 10.0

    # Grid (each 5 units)
    for ($i = 0; $i -le 10; $i++) {
        $x = $ox + $i * $stepX
        $y = $oy - $i * $stepY
        $g.DrawLine($penGrid, [float]$x, [float]$oy, [float]$x, [float]($oy - $plotH))
        $g.DrawLine($penGrid, [float]$ox, [float]$y, [float]($ox + $plotW), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]($ox + $plotW + 15), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, [float]($oy - $plotH - 15))

    # Ticks (0, 5, 10, ..., 50)
    for ($val = 5; $val -le 50; $val += 5) {
        $idx = $val / 5.0
        $x = $ox + $idx * $stepX
        $y = $oy - $idx * $stepY

        $str = "$val"
        $sz = $g.MeasureString($str, $fontNum)
        $g.DrawString($str, $fontNum, $brushDark, [float]($x - $sz.Width/2), [float]($oy + 4))
        $g.DrawString($str, $fontNum, $brushDark, [float]($ox - $sz.Width - 4), [float]($y - $sz.Height/2))
    }
    $g.DrawString("O", $fontNum, $brushDark, [float]($ox - 14), [float]($oy + 2))
    $g.DrawString("x", $fontAxis, $brushDark, [float]($ox + $plotW + 18), [float]($oy - 8))
    $g.DrawString("y", $fontAxis, $brushDark, [float]($ox - 10), [float]($oy - $plotH - 22))

    # Line: from (0, 49) to (49, 0)
    $p1x = $ox; $p1y = $oy - (49.0 / 5.0) * $stepY
    $p2x = $ox + (49.0 / 5.0) * $stepX; $p2y = $oy
    $g.DrawLine($penLine, [float]$p1x, [float]$p1y, [float]$p2x, [float]$p2y)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 4. M2 Q9: Momentum vs Time line chart
# ==============================================================================
function Render-M2Q9 {
    $outPath = Join-Path $imgDir "m2_q9_light.png"
    $w = 360; $h = 380
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penGrid.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.8)
    $penLine = New-Object System.Drawing.Pen($cDark, 2.2)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushDot = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $fontAxis = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Regular)
    $fontNum = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)

    $ox = 55.0; $oy = 310.0
    $plotW = 270.0; $plotH = 264.0
    # X: 0 to 9 (step = plotW / 9)
    # Y: 0 to 11 (step = plotH / 11)
    $stepX = $plotW / 9.0
    $stepY = $plotH / 11.0

    # Grid
    for ($i = 0; $i -le 9; $i++) {
        $x = $ox + $i * $stepX
        $g.DrawLine($penGrid, [float]$x, [float]$oy, [float]$x, [float]($oy - $plotH))
    }
    for ($j = 0; $j -le 11; $j++) {
        $y = $oy - $j * $stepY
        $g.DrawLine($penGrid, [float]$ox, [float]$y, [float]($ox + $plotW), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]($ox + $plotW + 12), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, [float]($oy - $plotH - 12))

    # Ticks & numbers
    for ($i = 1; $i -le 9; $i++) {
        $x = $ox + $i * $stepX
        $str = "$i"
        $sz = $g.MeasureString($str, $fontNum)
        $g.DrawString($str, $fontNum, $brushDark, [float]($x - $sz.Width/2), [float]($oy + 4))
    }
    for ($j = 1; $j -le 11; $j++) {
        $y = $oy - $j * $stepY
        $str = "$j"
        $sz = $g.MeasureString($str, $fontNum)
        $g.DrawString($str, $fontNum, $brushDark, [float]($ox - $sz.Width - 4), [float]($y - $sz.Height/2))
    }
    $g.DrawString("O", $fontNum, $brushDark, [float]($ox - 14), [float]($oy + 3))

    # Axis labels
    $titleX = "Time (seconds)"
    $szX = $g.MeasureString($titleX, $fontAxis)
    $g.DrawString($titleX, $fontAxis, $brushDark, [float]($ox + ($plotW - $szX.Width)/2), [float]($oy + 22))

    $state = $g.Save()
    $g.TranslateTransform(16.0, [float]($oy - $plotH/2))
    $g.RotateTransform(-90.0)
    $szY = $g.MeasureString("Momentum (newton-seconds)", $fontAxis)
    $g.DrawString("Momentum (newton-seconds)", $fontAxis, $brushDark, [float](-$szY.Width/2), [float](-$szY.Height/2))
    $g.Restore($state)

    # Data points: (0, 1), (2, 3), (4, 4), (6, 8), (8, 10)
    $data = @(
        @(0, 1), @(2, 3), @(4, 4), @(6, 8), @(8, 10)
    )

    for ($k = 0; $k -lt $data.Length - 1; $k++) {
        $pA = $data[$k]
        $pB = $data[$k+1]
        $x1 = $ox + $pA[0] * $stepX; $y1 = $oy - $pA[1] * $stepY
        $x2 = $ox + $pB[0] * $stepX; $y2 = $oy - $pB[1] * $stepY
        $g.DrawLine($penLine, [float]$x1, [float]$y1, [float]$x2, [float]$y2)
    }

    $dotR = 3.5
    foreach ($p in $data) {
        $px = $ox + $p[0] * $stepX; $py = $oy - $p[1] * $stepY
        $g.FillEllipse($brushDark, [float]($px - $dotR), [float]($py - $dotR), [float](2*$dotR), [float](2*$dotR))
        $g.FillEllipse($brushDot, [float]($px - $dotR + 1.2), [float]($py - $dotR + 1.2), [float](2*($dotR - 1.2)), [float](2*($dotR - 1.2)))
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 5. M2 Q13: Histogram of Maximum temperature on April 1
# ==============================================================================
function Render-M2Q13 {
    $outPath = Join-Path $imgDir "m2_q13_light.png"
    $w = 400; $h = 280
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.8)
    $penBarBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 1.2)
    $brushBar = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(148, 163, 184)) # Slate 400
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Regular)
    $fontNum = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)

    $ox = 50.0; $oy = 220.0
    $plotW = 320.0; $plotH = 180.0
    # 8 bins: 40-45, 45-50, 50-55, 55-60, 60-65, 65-70, 70-75, 75-80
    $binW = $plotW / 8.0
    $stepY = $plotH / 4.0 # max frequency = 4

    # Bins data:
    # 40-45: 1
    # 45-50: 2
    # 50-55: 3
    # 55-60: 3
    # 60-65: 1
    # 65-70: 0
    # 70-75: 1
    # 75-80: 1
    $counts = @(1, 2, 3, 3, 1, 0, 1, 1)

    for ($i = 0; $i -lt 8; $i++) {
        $c = $counts[$i]
        if ($c -gt 0) {
            $bx = $ox + $i * $binW
            $bh = $c * $stepY
            $by = $oy - $bh
            $g.FillRectangle($brushBar, [float]$bx, [float]$by, [float]$binW, [float]$bh)
            $g.DrawRectangle($penBarBorder, [float]$bx, [float]$by, [float]$binW, [float]$bh)
        }
    }

    # Axes
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]($ox + $plotW + 10), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, [float]($oy - $plotH - 10))

    # Y-axis ticks (0 to 4)
    for ($j = 0; $j -le 4; $j++) {
        $y = $oy - $j * $stepY
        $str = "$j"
        $sz = $g.MeasureString($str, $fontNum)
        $g.DrawString($str, $fontNum, $brushDark, [float]($ox - $sz.Width - 4), [float]($y - $sz.Height/2))
    }

    # X-axis ticks (40, 45, 50, ..., 80)
    for ($k = 0; $k -le 8; $k++) {
        $val = 40 + $k * 5
        $x = $ox + $k * $binW
        $str = "$val"
        $sz = $g.MeasureString($str, $fontNum)
        $g.DrawString($str, $fontNum, $brushDark, [float]($x - $sz.Width/2), [float]($oy + 4))
    }

    # Labels
    $titleX = "Maximum temperature on April 1 (°F)"
    $szX = $g.MeasureString($titleX, $fontAxis)
    $g.DrawString($titleX, $fontAxis, $brushDark, [float]($ox + ($plotW - $szX.Width)/2), [float]($oy + 22))

    $state = $g.Save()
    $g.TranslateTransform(16.0, [float]($oy - $plotH/2))
    $g.RotateTransform(-90.0)
    $szY = $g.MeasureString("Number of years", $fontAxis)
    $g.DrawString("Number of years", $fontAxis, $brushDark, [float](-$szY.Width/2), [float](-$szY.Height/2))
    $g.Restore($state)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 6. M2 Q15: Company A vs Company B (10x + 18y = 900)
# ==============================================================================
function Render-M2Q15 {
    $outPath = Join-Path $imgDir "m2_q15_light.png"
    $w = 380; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.8)
    $penLine = New-Object System.Drawing.Pen($cDark, 2.2)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 10.5, [System.Drawing.FontStyle]::Regular)
    $fontNum = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)

    $ox = 60.0; $oy = 295.0
    $plotW = 280.0; $plotH = 250.0
    $stepX = $plotW / 20.0 # each 5 units
    $stepY = $plotH / 10.0 # each 5 units

    # Grid
    for ($i = 0; $i -le 20; $i++) {
        $x = $ox + $i * $stepX
        $g.DrawLine($penGrid, [float]$x, [float]$oy, [float]$x, [float]($oy - $plotH))
    }
    for ($j = 0; $j -le 10; $j++) {
        $y = $oy - $j * $stepY
        $g.DrawLine($penGrid, [float]$ox, [float]$y, [float]($ox + $plotW), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]($ox + $plotW + 15), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, [float]($oy - $plotH - 15))

    # Ticks & labels
    for ($valX = 10; $valX -le 100; $valX += 10) {
        $x = $ox + ($valX / 5.0) * $stepX
        $str = "$valX"
        $sz = $g.MeasureString($str, $fontNum)
        $g.DrawString($str, $fontNum, $brushDark, [float]($x - $sz.Width/2), [float]($oy + 4))
    }
    for ($valY = 10; $valY -le 50; $valY += 10) {
        $y = $oy - ($valY / 5.0) * $stepY
        $str = "$valY"
        $sz = $g.MeasureString($str, $fontNum)
        $g.DrawString($str, $fontNum, $brushDark, [float]($ox - $sz.Width - 4), [float]($y - $sz.Height/2))
    }
    $g.DrawString("O", $fontNum, $brushDark, [float]($ox - 14), [float]($oy + 3))

    # Titles
    $titleX = "Company A"
    $szX = $g.MeasureString($titleX, $fontAxis)
    $g.DrawString($titleX, $fontAxis, $brushDark, [float]($ox + ($plotW - $szX.Width)/2), [float]($oy + 24))

    $state = $g.Save()
    $g.TranslateTransform(18.0, [float]($oy - $plotH/2))
    $g.RotateTransform(-90.0)
    $szY = $g.MeasureString("Company B", $fontAxis)
    $g.DrawString("Company B", $fontAxis, $brushDark, [float](-$szY.Width/2), [float](-$szY.Height/2))
    $g.Restore($state)

    # Line: 10x + 18y = 900 -> (0, 50) to (90, 0)
    $p1x = $ox; $p1y = $oy - (50.0 / 5.0) * $stepY
    $p2x = $ox + (90.0 / 5.0) * $stepX; $p2y = $oy
    $g.DrawLine($penLine, [float]$p1x, [float]$p1y, [float]$p2x, [float]$p2y)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

Render-M1Q1
Render-M1Q18
Render-M2Q7
Render-M2Q9
Render-M2Q13
Render-M2Q15
Write-Host "All June 2025 · INT 2 light images rendered successfully!"
