Add-Type -AssemblyName System.Drawing

$outDir = "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\sep2025_light_images"
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

# Styling Constants
$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)      # Deep slate for text and main lines
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)    # Soft slate grid
$cBlue = [System.Drawing.Color]::FromArgb(37, 99, 235)      # Royal blue for points/curves

$fontSerifItalic = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
$fontSerif = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
$fontSans = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
$fontSansBold = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$fontTable = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
$fontTableItalic = New-Object System.Drawing.Font("Times New Roman", 16, [System.Drawing.FontStyle]::Italic)

# -------------------------------------------------------------
# 1. M1 Q2: Isosceles Triangle (x, y, y)
# -------------------------------------------------------------
function Create-M1-Q2 {
    param($outFile)
    $w = 460; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penDark = New-Object System.Drawing.Pen($cDark, 2.5)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)

    # Triangle points
    $pApex = New-Object System.Drawing.PointF(230, 60)
    $pLeft = New-Object System.Drawing.PointF(60, 320)
    $pRight = New-Object System.Drawing.PointF(400, 320)

    $g.DrawPolygon($penDark, @($pApex, $pLeft, $pRight))

    # Labels
    $g.DrawString("x", $fontSerifItalic, $brushDark, 224, 335)
    $g.DrawString("y", $fontSerifItalic, $brushDark, 120, 175)
    $g.DrawString("y", $fontSerifItalic, $brushDark, 325, 175)

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontSerif, $brushDark, 130, 395)

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# -------------------------------------------------------------
# 2. M1 Q16: Scatterplot Water Temp vs Depth
# -------------------------------------------------------------
function Create-M1-Q16 {
    param($outFile)
    $w = 560; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 75.0; $right = 510.0; $top = 40.0; $bottom = 360.0
    $pW = $right - $left; $pH = $bottom - $top

    function MapX($depth) { return $left + (($depth - 5.0) / 70.0) * $pW }
    function MapY($temp) { return $bottom - (($temp - 10.0) / 14.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    $penGrid.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    for ($d = 10; $d -le 70; $d += 10) {
        $x = MapX $d
        $g.DrawLine($penGrid, [float]$x, [float]$top, [float]$x, [float]$bottom)
    }
    for ($t = 10; $t -le 24; $t += 2) {
        $y = MapY $t
        $g.DrawLine($penGrid, [float]$left, [float]$y, [float]$right, [float]$y)
    }

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float]$left, [float]($bottom + 10), [float]$left, [float]($top - 20))
    $g.DrawLine($penAxis, [float]($left - 10), [float]$bottom, [float]($right + 25), [float]$bottom)

    $brushDark = New-Object System.Drawing.SolidBrush($cDark)

    # Ticks & Tick Labels
    $penTick = New-Object System.Drawing.Pen($cDark, 1.5)
    for ($d = 10; $d -le 70; $d += 10) {
        $x = MapX $d
        $g.DrawLine($penTick, [float]$x, [float]$bottom, [float]$x, [float]($bottom + 5))
        $g.DrawString("$d", $fontSans, $brushDark, [float]($x - 8), [float]($bottom + 8))
    }
    for ($t = 10; $t -le 24; $t += 2) {
        $y = MapY $t
        $g.DrawLine($penTick, [float]($left - 5), [float]$y, [float]$left, [float]$y)
        $g.DrawString("$t", $fontSans, $brushDark, [float]($left - 26), [float]($y - 8))
    }

    # Axis Titles
    $g.DrawString("Depth (meters)", $fontSansBold, $brushDark, 230, 400)
    
    # Rotated Y-axis title
    $state = $g.Save()
    $g.TranslateTransform(20, 240)
    $g.RotateTransform(-90)
    $degStr = "Temperature (" + [char]176 + "C)"
    $g.DrawString($degStr, $fontSansBold, $brushDark, -65, 0)
    $g.Restore($state)

    # Line of best fit: passes near (5, 23) and (75, 12.75)
    $penLine = New-Object System.Drawing.Pen($cDark, 2.2)
    $xStart = MapX 5; $yStart = MapY 23.0
    $xEnd = MapX 75; $yEnd = MapY 12.75
    $g.DrawLine($penLine, [float]$xStart, [float]$yStart, [float]$xEnd, [float]$yEnd)

    # Data Points (crosses): (10, 22), (20, 21), (30, 19), (40, 18), (50, 17), (60, 15), (70, 13)
    $pts = @(
        @(10, 22.0),
        @(20, 21.0),
        @(30, 19.0),
        @(40, 18.0),
        @(50, 17.0),
        @(60, 15.0),
        @(70, 13.0)
    )

    $penPt = New-Object System.Drawing.Pen($cBlue, 2.4)
    foreach ($p in $pts) {
        $px = MapX $p[0]
        $py = MapY $p[1]
        $sz = 5.0
        $g.DrawLine($penPt, [float]($px - $sz), [float]($py - $sz), [float]($px + $sz), [float]($py + $sz))
        $g.DrawLine($penPt, [float]($px - $sz), [float]($py + $sz), [float]($px + $sz), [float]($py - $sz))
    }

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# -------------------------------------------------------------
# 3. M1 Q20: Triangles RST and XYZ
# -------------------------------------------------------------
function Create-M1-Q20 {
    param($outFile)
    $w = 460; $h = 480
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penDark = New-Object System.Drawing.Pen($cDark, 2.5)
    $penThin = New-Object System.Drawing.Pen($cDark, 1.8)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)

    # Triangle RST
    $R = New-Object System.Drawing.PointF(100, 50)
    $T = New-Object System.Drawing.PointF(100, 410)
    $S = New-Object System.Drawing.PointF(380, 410)

    $g.DrawPolygon($penDark, @($R, $T, $S))

    # Right angle at T
    $g.DrawRectangle($penThin, 100, 392, 18, 18)

    # Inner triangle XYZ
    # X on RS: x=165, y = 50 + (360/280)*(65) = 133.5
    # Z on RS: x=315, y = 50 + (360/280)*(215) = 326.4
    # Y is (315, 133.5)
    $X = New-Object System.Drawing.PointF(165, 134)
    $Z = New-Object System.Drawing.PointF(315, 326)
    $Y = New-Object System.Drawing.PointF(315, 134)

    $g.DrawLine($penDark, $X, $Y)
    $g.DrawLine($penDark, $Y, $Z)

    # Right angle at Y (inside triangle, quadrant 3 from Y)
    $g.DrawRectangle($penThin, [float]($Y.X - 18), [float]($Y.Y), 18, 18)

    # Labels
    $g.DrawString("R", $fontSerifItalic, $brushDark, 70, 40)
    $g.DrawString("T", $fontSerifItalic, $brushDark, 70, 415)
    $g.DrawString("S", $fontSerifItalic, $brushDark, 388, 415)

    $g.DrawString("X", $fontSerifItalic, $brushDark, 162, 105)
    $g.DrawString("Y", $fontSerifItalic, $brushDark, 328, 115)
    $g.DrawString("Z", $fontSerifItalic, $brushDark, 335, 325)

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# -------------------------------------------------------------
# 4. M2 Q22: Circle with chords AC and BE
# -------------------------------------------------------------
function Create-M2-Q22 {
    param($outFile)
    $w = 480; $h = 480
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penDark = New-Object System.Drawing.Pen($cDark, 2.5)
    $penThin = New-Object System.Drawing.Pen($cDark, 1.8)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)

    # Circle center (240, 210), radius R=175
    $cx = 240.0; $cy = 210.0; $R = 175.0
    $g.DrawEllipse($penDark, [float]($cx - $R), [float]($cy - $R), [float](2 * $R), [float](2 * $R))

    # Diameter AC at angle 15 deg
    $rad15 = 15.0 * [Math]::PI / 180.0
    $C = New-Object System.Drawing.PointF([float]($cx + $R * [Math]::Cos($rad15)), [float]($cy - $R * [Math]::Sin($rad15)))
    $A = New-Object System.Drawing.PointF([float]($cx - $R * [Math]::Cos($rad15)), [float]($cy + $R * [Math]::Sin($rad15)))

    # Point B at angle 135 deg (top left)
    $rad135 = 135.0 * [Math]::PI / 180.0
    $B = New-Object System.Drawing.PointF([float]($cx + $R * [Math]::Cos($rad135)), [float]($cy - $R * [Math]::Sin($rad135)))

    # Draw chord AC
    $g.DrawLine($penDark, $A, $C)
    # Draw chords AB and BC
    $g.DrawLine($penDark, $A, $B)
    $g.DrawLine($penDark, $B, $C)

    # Altitude from B perpendicular to AC meeting at D, continuing to E
    # Vector AC = C - A
    $vACx = $C.X - $A.X; $vACy = $C.Y - $A.Y
    $lenAC2 = $vACx * $vACx + $vACy * $vACy
    # Project B - A onto AC
    $vBAx = $B.X - $A.X; $vBAy = $B.Y - $A.Y
    $tProj = ($vBAx * $vACx + $vBAy * $vACy) / $lenAC2
    $Dx = $A.X + $tProj * $vACx
    $Dy = $A.Y + $tProj * $vACy
    $D = New-Object System.Drawing.PointF([float]$Dx, [float]$Dy)

    # Vector BD
    $vBDx = $D.X - $B.X; $vBDy = $D.Y - $B.Y
    $lenBD = [Math]::Sqrt($vBDx * $vBDx + $vBDy * $vBDy)
    $uBDx = $vBDx / $lenBD; $uBDy = $vBDy / $lenBD

    # E is on the circle along ray B -> D
    # Circle equation: (B.X + s*uBDx - cx)^2 + (B.Y + s*uBDy - cy)^2 = R^2
    # Quadratic in s: s^2 + 2*(uBD . (B - c))*s + (|B - c|^2 - R^2) = 0
    # since |B - c| = R, constant is 0! So s*(s + 2*(uBD . (B - c))) = 0
    # s = -2 * (uBDx*(B.X - cx) + uBDy*(B.Y - cy))
    $sChord = -2.0 * ($uBDx * ($B.X - $cx) + $uBDy * ($B.Y - $cy))
    $E = New-Object System.Drawing.PointF([float]($B.X + $sChord * $uBDx), [float]($B.Y + $sChord * $uBDy))

    # Draw segment BE
    $g.DrawLine($penDark, $B, $E)

    # Right angle marker at B (between BA and BC)
    $uBAx = ($A.X - $B.X) / [Math]::Sqrt(($A.X - $B.X)*($A.X - $B.X) + ($A.Y - $B.Y)*($A.Y - $B.Y))
    $uBAy = ($A.Y - $B.Y) / [Math]::Sqrt(($A.X - $B.X)*($A.X - $B.X) + ($A.Y - $B.Y)*($A.Y - $B.Y))
    $uBCx = ($C.X - $B.X) / [Math]::Sqrt(($C.X - $B.X)*($C.X - $B.X) + ($C.Y - $B.Y)*($C.Y - $B.Y))
    $uBCy = ($C.Y - $B.Y) / [Math]::Sqrt(($C.X - $B.X)*($C.X - $B.X) + ($C.Y - $B.Y)*($C.Y - $B.Y))
    $sqSz = 14.0
    $ptB1 = New-Object System.Drawing.PointF([float]($B.X + $sqSz * $uBAx), [float]($B.Y + $sqSz * $uBAy))
    $ptB2 = New-Object System.Drawing.PointF([float]($ptB1.X + $sqSz * $uBCx), [float]($ptB1.Y + $sqSz * $uBCy))
    $ptB3 = New-Object System.Drawing.PointF([float]($B.X + $sqSz * $uBCx), [float]($B.Y + $sqSz * $uBCy))
    $g.DrawLine($penThin, $ptB1, $ptB2)
    $g.DrawLine($penThin, $ptB2, $ptB3)

    # Right angle marker at D (between DA and DE)
    $uDAx = ($A.X - $D.X) / [Math]::Sqrt(($A.X - $D.X)*($A.X - $D.X) + ($A.Y - $D.Y)*($A.Y - $D.Y))
    $uDAy = ($A.Y - $D.Y) / [Math]::Sqrt(($A.X - $D.X)*($A.X - $D.X) + ($A.Y - $D.Y)*($A.Y - $D.Y))
    $uDEx = ($E.X - $D.X) / [Math]::Sqrt(($E.X - $D.X)*($E.X - $D.X) + ($E.Y - $D.Y)*($E.Y - $D.Y))
    $uDEy = ($E.Y - $D.Y) / [Math]::Sqrt(($E.X - $D.X)*($E.X - $D.X) + ($E.Y - $D.Y)*($E.Y - $D.Y))
    $ptD1 = New-Object System.Drawing.PointF([float]($D.X + $sqSz * $uDAx), [float]($D.Y + $sqSz * $uDAy))
    $ptD2 = New-Object System.Drawing.PointF([float]($ptD1.X + $sqSz * $uDEx), [float]($ptD1.Y + $sqSz * $uDEy))
    $ptD3 = New-Object System.Drawing.PointF([float]($D.X + $sqSz * $uDEx), [float]($D.Y + $sqSz * $uDEy))
    $g.DrawLine($penThin, $ptD1, $ptD2)
    $g.DrawLine($penThin, $ptD2, $ptD3)

    # Labels
    $g.DrawString("A", $fontSerifItalic, $brushDark, [float]($A.X - 25), [float]($A.Y - 10))
    $g.DrawString("B", $fontSerifItalic, $brushDark, [float]($B.X - 25), [float]($B.Y - 15))
    $g.DrawString("C", $fontSerifItalic, $brushDark, [float]($C.X + 8), [float]($C.Y - 10))
    $g.DrawString("D", $fontSerifItalic, $brushDark, [float]($D.X + 6), [float]($D.Y - 26))
    $g.DrawString("E", $fontSerifItalic, $brushDark, [float]($E.X - 10), [float]($E.Y + 6))

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontSerif, $brushDark, 140, 440)

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# -------------------------------------------------------------
# 5. M1 Q9: Tables for Choices A, B, C, D
# -------------------------------------------------------------
function Create-Table-Image {
    param($outFile, $xVals, $yVals)
    $w = 340; $h = 160
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penBorder = New-Object System.Drawing.Pen($cDark, 2.0)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)

    $startX = 20.0; $startY = 20.0
    $tblW = 300.0; $tblH = 120.0
    $colW = $tblW / 5.0
    $rowH = $tblH / 2.0

    # Outer border
    $g.DrawRectangle($penBorder, [float]$startX, [float]$startY, [float]$tblW, [float]$tblH)

    # Horizontal divider
    $g.DrawLine($penBorder, [float]$startX, [float]($startY + $rowH), [float]($startX + $tblW), [float]($startY + $rowH))

    # Vertical dividers
    for ($i = 1; $i -lt 5; $i++) {
        $x = $startX + $i * $colW
        $g.DrawLine($penBorder, [float]$x, [float]$startY, [float]$x, [float]($startY + $tblH))
    }

    # Headers
    $g.DrawString("x", $fontTableItalic, $brushDark, [float]($startX + 22), [float]($startY + 15))
    $g.DrawString("y", $fontTableItalic, $brushDark, [float]($startX + 22), [float]($startY + $rowH + 15))

    # Values
    for ($i = 0; $i -lt 4; $i++) {
        $cx = $startX + ($i + 1) * $colW
        $valX = "$($xVals[$i])"
        $valY = "$($yVals[$i])"
        
        # Measure strings for centering
        $szX = $g.MeasureString($valX, $fontTable)
        $szY = $g.MeasureString($valY, $fontTable)

        $g.DrawString($valX, $fontTable, $brushDark, [float]($cx + ($colW - $szX.Width)/2), [float]($startY + ($rowH - $szX.Height)/2))
        $g.DrawString($valY, $fontTable, $brushDark, [float]($cx + ($colW - $szY.Width)/2), [float]($startY + $rowH + ($rowH - $szY.Height)/2))
    }

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outFile"
}

# Run generation
Create-M1-Q2 "$outDir\m1_q2_light.png"
Create-M1-Q16 "$outDir\m1_q16_light.png"
Create-M1-Q20 "$outDir\m1_q20_light.png"
Create-M2-Q22 "$outDir\m2_q22_light.png"

Create-Table-Image "$outDir\m1_q9_choice_a_light.png" @("-1", "0", "1", "2") @("-16", "-21", "-24", "-25")
Create-Table-Image "$outDir\m1_q9_choice_b_light.png" @("-1", "0", "1", "2") @("11", "3", "-3", "-7")
Create-Table-Image "$outDir\m1_q9_choice_c_light.png" @("-1", "0", "1", "2") @("-28", "-21", "-14", "-7")
Create-Table-Image "$outDir\m1_q9_choice_d_light.png" @("-1", "0", "1", "2") @("3", "10", "17", "24")

Write-Host "All September 2025 INT 1 light mode images successfully rendered."
