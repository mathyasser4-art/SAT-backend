Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "june2025_int1_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42) # Slate 900
$cGray = [System.Drawing.Color]::FromArgb(100, 116, 139) # Slate 500
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240) # Slate 200
$cAxis = [System.Drawing.Color]::FromArgb(71, 85, 105) # Slate 600

# ==============================================================================
# 1. M1 Q1: Parallel lines r and s cut by transversal n
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

    # Parallel lines r (top) and s (bottom)
    $lx = 30.0; $rx = 275.0
    $ry = 115.0; $sy = 215.0
    $g.DrawLine($penLine, [float]$lx, [float]$ry, [float]$rx, [float]$ry)
    $g.DrawLine($penLine, [float]$lx, [float]$sy, [float]$rx, [float]$sy)

    # Transversal line n: positive slope
    $tx1 = 40.0;  $ty1 = 315.0
    $tx2 = 280.0; $ty2 = 45.0
    $g.DrawLine($penLine, [float]$tx1, [float]$ty1, [float]$tx2, [float]$ty2)

    # Intersections
    $m = ($ty2 - $ty1) / ($tx2 - $tx1)
    $ir_x = $tx1 + ($ry - $ty1) / $m
    $is_x = $tx1 + ($sy - $ty1) / $m

    # Line labels
    $g.DrawString("r", $fontLabel, $brushDark, [float]($rx + 12), [float]($ry - 10))
    $g.DrawString("s", $fontLabel, $brushDark, [float]($rx + 12), [float]($sy - 10))
    $g.DrawString("n", $fontLabel, $brushDark, [float]($tx2 + 8), [float]($ty2 - 12))

    # Angle 152 deg at r (top-left obtuse angle: between horizontal left and transversal up-right)
    $g.DrawArc($penArc, [float]($ir_x - 22), [float]($ry - 22), 44.0, 44.0, 180.0, 132.0)
    $g.DrawString("152°", $fontVal, $brushDark, [float]($ir_x - 48), [float]($ry - 26))

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
# 2. M1 Q7: Scatterplot (0 to 10)
# ==============================================================================
function Render-M1Q7 {
    $outPath = Join-Path $imgDir "m1_q7_light.png"
    $w = 360; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penGrid.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.8)
    $penCross = New-Object System.Drawing.Pen($cDark, 1.8)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Italic)
    $fontNum = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)

    $ox = 45.0; $oy = 310.0
    $plotW = 270.0; $plotH = 270.0
    $stepX = $plotW / 10.0
    $stepY = $plotH / 10.0

    # Grid
    for ($i = 0; $i -le 10; $i++) {
        $x = $ox + $i * $stepX
        $y = $oy - $i * $stepY
        $g.DrawLine($penGrid, [float]$x, [float]$oy, [float]$x, [float]($oy - $plotH))
        $g.DrawLine($penGrid, [float]$ox, [float]$y, [float]($ox + $plotW), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]($ox + $plotW + 15), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, [float]($oy - $plotH - 15))

    # Ticks and labels
    for ($i = 0; $i -le 10; $i++) {
        $x = $ox + $i * $stepX
        $y = $oy - $i * $stepY

        if ($i -gt 0) {
            $nStr = "$i"
            $nSize = $g.MeasureString($nStr, $fontNum)
            $g.DrawString($nStr, $fontNum, $brushDark, [float]($x - $nSize.Width/2), [float]($oy + 4))
            $g.DrawString($nStr, $fontNum, $brushDark, [float]($ox - $nSize.Width - 5), [float]($y - $nSize.Height/2))
        }
    }
    $g.DrawString("O", $fontNum, $brushDark, [float]($ox - 14), [float]($oy + 2))
    $g.DrawString("x", $fontAxis, $brushDark, [float]($ox + $plotW/2), [float]($oy + 22))
    $g.DrawString("y", $fontAxis, $brushDark, [float]($ox - 28), [float]($oy - $plotH/2 - 8))

    # Points: (0, 10), (1, 7), (2, 6), (3, 5), (5, 4), (5, 6), (6, 4), (7, 3), (8, 1), (9, 2), (10, 2)
    $pts = @(
        @(0, 10), @(1, 7), @(2, 6), @(3, 5), @(5, 4),
        @(5, 6), @(6, 4), @(7, 3), @(8, 1), @(9, 2), @(10, 2)
    )

    $crossR = 4.0
    foreach ($p in $pts) {
        $px = $ox + $p[0] * $stepX
        $py = $oy - $p[1] * $stepY
        $g.DrawLine($penCross, [float]($px - $crossR), [float]($py - $crossR), [float]($px + $crossR), [float]($py + $crossR))
        $g.DrawLine($penCross, [float]($px - $crossR), [float]($py + $crossR), [float]($px + $crossR), [float]($py - $crossR))
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 3. M1 Q18: Line k with y-intercept (0, 4) and x-intercept (3, 0)
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
    $scale = 22.0 # pixels per unit (-6 to 6)

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

    # Axis arrows
    $arrowSize = 5.0
    $g.DrawLine($penAxis, [float]($cx + 6.8 * $scale), [float]$cy, [float]($cx + 6.8 * $scale - $arrowSize), [float]($cy - $arrowSize))
    $g.DrawLine($penAxis, [float]($cx + 6.8 * $scale), [float]$cy, [float]($cx + 6.8 * $scale - $arrowSize), [float]($cy + $arrowSize))
    $g.DrawLine($penAxis, [float]$cx, [float]($cy - 6.8 * $scale), [float]($cx - $arrowSize), [float]($cy - 6.8 * $scale + $arrowSize))
    $g.DrawLine($penAxis, [float]$cx, [float]($cy - 6.8 * $scale), [float]($cx + $arrowSize), [float]($cy - 6.8 * $scale + $arrowSize))

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

    # Line k: slope -4/3, y = -4/3 x + 4
    # Points: x = -1.5 -> y = 6; x = 6 -> y = -4
    $p1x = $cx + (-1.5) * $scale; $p1y = $cy - 6.0 * $scale
    $p2x = $cx + 6.0 * $scale;    $p2y = $cy - (-4.0) * $scale
    $g.DrawLine($penLine, [float]$p1x, [float]$p1y, [float]$p2x, [float]$p2y)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 4. M2 Q5: Triangle PQR with QR extended to S
# ==============================================================================
function Render-M2Q5 {
    $outPath = Join-Path $imgDir "m2_q5_light.png"
    $w = 380; $h = 260
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushGray = New-Object System.Drawing.SolidBrush($cGray)
    $fontLabel = New-Object System.Drawing.Font("Arial", 12.0, [System.Drawing.FontStyle]::Italic)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Italic)

    # Line S - R - Q
    $Sx = 40.0;  $Sy = 50.0
    $Rx = 160.0; $Ry = 50.0
    $Qx = 280.0; $Qy = 50.0
    $Px = 335.0; $Py = 215.0

    $g.DrawLine($penLine, [float]$Sx, [float]$Sy, [float]$Qx, [float]$Qy) # Segment SQ
    $g.DrawLine($penLine, [float]$Qx, [float]$Qy, [float]$Px, [float]$Py) # Segment QP
    $g.DrawLine($penLine, [float]$Rx, [float]$Ry, [float]$Px, [float]$Py) # Segment RP

    # Labels
    $g.DrawString("S", $fontLabel, $brushDark, [float]($Sx - 18), [float]($Sy - 10))
    $g.DrawString("R", $fontLabel, $brushDark, [float]($Rx - 6), [float]($Ry - 24))
    $g.DrawString("Q", $fontLabel, $brushDark, [float]($Qx - 6), [float]($Qy - 24))
    $g.DrawString("P", $fontLabel, $brushDark, [float]($Px + 8), [float]($Py - 10))

    # Note
    $note = "Note: Figure not drawn to scale."
    $noteSize = $g.MeasureString($note, $fontNote)
    $g.DrawString($note, $fontNote, $brushGray, [float](($w - $noteSize.Width)/2), [float]($h - 20))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 5. M2 Q7: Shares of stock graph: Company A (x) vs Company B (y)
# ==============================================================================
function Render-M2Q7 {
    $outPath = Join-Path $imgDir "m2_q7_light.png"
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
    # X: 0 to 100 in steps of 5 (grid) and 10 (labels)
    # Y: 0 to 50 in steps of 5 (grid) and 10 (labels)
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

    # Arrows
    $arrow = 5.0
    $g.DrawLine($penAxis, [float]($ox + $plotW + 15), [float]$oy, [float]($ox + $plotW + 15 - $arrow), [float]($oy - $arrow))
    $g.DrawLine($penAxis, [float]($ox + $plotW + 15), [float]$oy, [float]($ox + $plotW + 15 - $arrow), [float]($oy + $arrow))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - $plotH - 15), [float]($ox - $arrow), [float]($oy - $plotH - 15 + $arrow))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - $plotH - 15), [float]($ox + $arrow), [float]($oy - $plotH - 15 + $arrow))

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

    # Axis titles
    $titleX = "Company A"
    $szX = $g.MeasureString($titleX, $fontAxis)
    $g.DrawString($titleX, $fontAxis, $brushDark, [float]($ox + ($plotW - $szX.Width)/2), [float]($oy + 24))

    # Vertical title "Company B"
    $state = $g.Save()
    $g.TranslateTransform(18.0, [float]($oy - $plotH/2))
    $g.RotateTransform(-90.0)
    $szY = $g.MeasureString("Company B", $fontAxis)
    $g.DrawString("Company B", $fontAxis, $brushDark, [float](-$szY.Width/2), [float](-$szY.Height/2))
    $g.Restore($state)

    # Line: 9x + 16y = 720 -> (0, 45) to (80, 0)
    $p1x = $ox; $p1y = $oy - (45.0 / 5.0) * $stepY
    $p2x = $ox + (80.0 / 5.0) * $stepX; $p2y = $oy
    $g.DrawLine($penLine, [float]$p1x, [float]$p1y, [float]$p2x, [float]$p2y)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

Render-M1Q1
Render-M1Q7
Render-M1Q18
Render-M2Q5
Render-M2Q7
Write-Host "All June 2025 · INT 1 light images rendered successfully!"
