Add-Type -AssemblyName System.Drawing

$outDir = Join-Path $PSScriptRoot "march2025_int3_light_images"
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

function Create-Canvas([int]$w, [int]$h) {
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)
    return @{ Bitmap = $bmp; Graphics = $g }
}

$fontLabel = New-Object System.Drawing.Font("Arial", 16, [System.Drawing.FontStyle]::Regular)
$fontNote = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Regular)
$fontAxis = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
$fontTitle = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$fontItalic13 = New-Object System.Drawing.Font("Arial", 13, [System.Drawing.FontStyle]::Italic)
$fontItalic16 = New-Object System.Drawing.Font("Arial", 16, [System.Drawing.FontStyle]::Italic)

$brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30, 41, 59))
$brushNote = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(100, 116, 139))
$brushPt = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(59, 130, 246))
$penPt = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(29, 78, 216), 1.5)
$penLine = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 41, 59), 3)
$penAxisA = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 41, 59), 2.5)
$penAxisA.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
$penGridL = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(226, 232, 240), 1)
$sfC = New-Object System.Drawing.StringFormat
$sfC.Alignment = [System.Drawing.StringAlignment]::Center

# ----------------------------------------------------
# 1. M1 Q2 (Scatterplot & Line of Best Fit: y = 0.8 + 1.7x)
# ----------------------------------------------------
$c = Create-Canvas 520 540
$g = $c.Graphics

# X: 0 to 8 (8 intervals of 45px -> 360px, x=80 to 440)
# Y: 0 to 16 (16 intervals of 25px -> 400px, y=460 to 60)
for ($y = 0; $y -le 16; $y++) {
    $yp = 460 - ($y * 25)
    $g.DrawLine($penGridL, 80, $yp, 440, $yp)
    if ($y % 2 -eq 0 -or $y -eq 15 -or $y -eq 1) {
        $g.DrawString("$y", $fontAxis, $brushText, 52, ($yp - 8))
    }
}
for ($x = 0; $x -le 8; $x++) {
    $xp = 80 + ($x * 45)
    $g.DrawLine($penGridL, $xp, 60, $xp, 460)
    $g.DrawString("$x", $fontAxis, $brushText, ($xp - 5), 468)
}

# Axes
$g.DrawLine($penAxisA, 70, 460, 470, 460)
$g.DrawLine($penAxisA, 80, 470, 80, 35)
$g.DrawString("x", $fontItalic13, $brushText, 475, 452)
$g.DrawString("y", $fontItalic13, $brushText, 74, 15)

# Line of best fit from x=0 (y=0.8) to x=7.5 (y=13.55) -> passes near (0, 0.8) and (7.5, 13.5)
$pLStart = New-Object System.Drawing.PointF(80, (460 - (0.8 * 25)))
$pLEnd = New-Object System.Drawing.PointF((80 + (7.5 * 45)), (460 - (13.55 * 25)))
$penFit = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 41, 59), 3)
$g.DrawLine($penFit, $pLStart, $pLEnd)

# Scatter points: (0.5, 2), (1.6, 4), (2.4, 6), (2.6, 4), (3.3, 8), (3.6, 5), (4.2, 9), (4.4, 8), (5.5, 12), (6.2, 12)
$ptsM1Q2 = @(
    @{ x=0.5; y=2 }, @{ x=1.6; y=4 }, @{ x=2.4; y=6 }, @{ x=2.6; y=4 },
    @{ x=3.3; y=8 }, @{ x=3.6; y=5 }, @{ x=4.2; y=9 }, @{ x=4.4; y=8 },
    @{ x=5.5; y=12 }, @{ x=6.2; y=12 }
)
foreach ($p in $ptsM1Q2) {
    $px = 80 + ($p.x * 45)
    $py = 460 - ($p.y * 25)
    $g.FillEllipse($brushPt, ($px - 6), ($py - 6), 12, 12)
    $g.DrawEllipse($penPt, ($px - 6), ($py - 6), 12, 12)
}

$c.Bitmap.Save((Join-Path $outDir "m1_q2_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 2. M1 Q10 (Line passing through (-12, 0) and (0, -11))
# ----------------------------------------------------
$c = Create-Canvas 520 540
$g = $c.Graphics

# X: -15 to 0 (15 intervals of 24px -> 360px, x=80 to 440)
# Y: -15 to 0 (15 intervals of 25px -> 375px, y=455 to 80)
for ($y = -14; $y -le 0; $y += 2) {
    $yp = 80 + (-$y * 25)
    $g.DrawLine($penGridL, 80, $yp, 440, $yp)
    if ($y -ne 0) {
        $g.DrawString("$y", $fontAxis, $brushText, 446, ($yp - 8))
    }
}
for ($x = -14; $x -le 0; $x += 2) {
    $xp = 440 + ($x * 24)
    $g.DrawLine($penGridL, $xp, 80, $xp, 455)
    if ($x -ne 0) {
        $g.DrawString("$x", $fontAxis, $brushText, ($xp - 12), 58)
    } else {
        $g.DrawString("O", $fontAxis, $brushText, ($xp - 12), 58)
    }
}

# Axes
$g.DrawLine($penAxisA, 60, 80, 465, 80)    # X-axis at y=0
$g.DrawLine($penAxisA, 440, 475, 440, 50)  # Y-axis at x=0
$g.DrawString("x", $fontItalic13, $brushText, 470, 72)
$g.DrawString("y", $fontItalic13, $brushText, 448, 30)

# Line through (-12, 0) and (0, -11)
$pXint = New-Object System.Drawing.PointF((440 + (-12 * 24)), 80)
$pYint = New-Object System.Drawing.PointF(440, (80 + (11 * 25)))

$penBlueLine = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(37, 99, 235), 3)
# Extend line slightly
$pExt1 = New-Object System.Drawing.PointF((440 + (-13 * 24)), (80 - (11/12 * 25)))
$pExt2 = New-Object System.Drawing.PointF((440 + (1 * 24)), (80 + (11.9 * 25)))
$g.DrawLine($penBlueLine, $pExt1, $pExt2)

# Intercept dots
$brushWhite = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
$penDotBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(37, 99, 235), 2.5)

$g.FillEllipse($brushWhite, ($pXint.X - 5), ($pXint.Y - 5), 10, 10)
$g.DrawEllipse($penDotBorder, ($pXint.X - 5), ($pXint.Y - 5), 10, 10)

$g.FillEllipse($brushWhite, ($pYint.X - 5), ($pYint.Y - 5), 10, 10)
$g.DrawEllipse($penDotBorder, ($pYint.X - 5), ($pYint.Y - 5), 10, 10)

$c.Bitmap.Save((Join-Path $outDir "m1_q10_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 3. M1 Q11 (Two parallel lines with transversal)
# ----------------------------------------------------
$c = Create-Canvas 460 480
$g = $c.Graphics

# Two vertical lines at x=160 and x=310
$g.DrawLine($penLine, 160, 40, 160, 400)
$g.DrawLine($penLine, 310, 40, 310, 400)

# Transversal slanting from top-left (50, 50) to bottom-right (420, 390)
$g.DrawLine($penLine, 50, 50, 420, 390)

# Labels w, x at first intersection (160, 151)
$g.DrawString("w°", $fontItalic16, $brushText, 175, 120)
$g.DrawString("x°", $fontItalic16, $brushText, 175, 175)

# Labels y, z at second intersection (310, 289)
$g.DrawString("y°", $fontItalic16, $brushText, 325, 255)
$g.DrawString("z°", $fontItalic16, $brushText, 325, 315)

$g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushNote, 230, 440, $sfC)

$c.Bitmap.Save((Join-Path $outDir "m1_q11_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 4. M1 Q16 (Exponential graph: y = ab^x + c with y-intercept (0, -6), asymptote y = -5)
# ----------------------------------------------------
$c = Create-Canvas 520 540
$g = $c.Graphics

# X: -10 to 10 (20 intervals of 18px -> 360px, x=80 to 440)
# Y: -10 to 5 (15 intervals of 25px -> 375px, y=475 to 100)
for ($y = -10; $y -le 5; $y++) {
    $yp = 225 - ($y * 25)
    $g.DrawLine($penGridL, 80, $yp, 440, $yp)
    if ($y % 2 -eq 0 -or $y -eq 5 -or $y -eq -5) {
        $g.DrawString("$y", $fontAxis, $brushText, 52, ($yp - 8))
    }
}
for ($x = -10; $x -le 10; $x++) {
    $xp = 260 + ($x * 18)
    $g.DrawLine($penGridL, $xp, 100, $xp, 475)
    if ($x % 2 -eq 0 -and $x -ne 0) {
        $g.DrawString("$x", $fontAxis, $brushText, ($xp - 8), 232)
    }
}

# Axes
$g.DrawLine($penAxisA, 60, 225, 465, 225) # X-axis at y=0
$g.DrawLine($penAxisA, 260, 490, 260, 80) # Y-axis at x=0
$g.DrawString("x", $fontItalic13, $brushText, 470, 218)
$g.DrawString("y", $fontItalic13, $brushText, 254, 58)

# Curve: y = -3^x - 5
# Horizontal asymptote y = -5 -> yp = 225 - (-5 * 25) = 350
# At x=0, y = -6 -> yp = 375
# At x=1, y = -8 -> yp = 425
# At x=1.5, y = -10.2 -> yp = 480
$penCurve = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(37, 99, 235), 3.5)
$ptsExpM1 = New-Object System.Collections.Generic.List[System.Drawing.PointF]
for ($step = -100; $step -le 15; $step++) {
    $xVal = $step / 10.0
    $yVal = - [Math]::Pow(3, $xVal) - 5
    $px = 260 + ($xVal * 18)
    $py = 225 - ($yVal * 25)
    $ptsExpM1.Add((New-Object System.Drawing.PointF($px, $py)))
}
$g.DrawLines($penCurve, $ptsExpM1.ToArray())

$c.Bitmap.Save((Join-Path $outDir "m1_q16_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 5. M1 Q19 (Right Triangle ABC: right angle at B, angle C = 30 deg)
# ----------------------------------------------------
$c = Create-Canvas 520 380
$g = $c.Graphics

$pA = New-Object System.Drawing.PointF(80, 70)   # top-left
$pB = New-Object System.Drawing.PointF(80, 270)  # bottom-left (right angle)
$pC = New-Object System.Drawing.PointF(440, 270) # bottom-right (30 deg)

# Triangle lines
$g.DrawLine($penLine, $pA, $pB)
$g.DrawLine($penLine, $pB, $pC)
$g.DrawLine($penLine, $pA, $pC)

# Right angle square at B (80, 270)
$sq = 20
$g.DrawRectangle($penLine, 80, (270 - $sq), $sq, $sq)

# Angle arc at C
$g.DrawArc($penLine, (440 - 50), (270 - 50), 100, 100, 180, 30)

# Labels
$g.DrawString("A", $fontLabel, $brushText, 55, 50)
$g.DrawString("B", $fontLabel, $brushText, 55, 270)
$g.DrawString("C", $fontLabel, $brushText, 448, 270)
$g.DrawString("30°", $fontLabel, $brushText, 355, 235)

$g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushNote, 260, 335, $sfC)

$c.Bitmap.Save((Join-Path $outDir "m1_q19_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 6. M2 Q10 (Line passing through (0, 9) and (-2, -3))
# ----------------------------------------------------
$c = Create-Canvas 520 540
$g = $c.Graphics

# X: -10 to 10 (20 intervals of 18px -> 360px, x=80 to 440)
# Y: -10 to 10 (20 intervals of 20px -> 400px, y=460 to 60)
for ($y = -10; $y -le 10; $y += 2) {
    $yp = 260 - ($y * 20)
    $g.DrawLine($penGridL, 80, $yp, 440, $yp)
    if ($y -ne 0) {
        $g.DrawString("$y", $fontAxis, $brushText, 52, ($yp - 8))
    }
}
for ($x = -10; $x -le 10; $x += 2) {
    $xp = 260 + ($x * 18)
    $g.DrawLine($penGridL, $xp, 60, $xp, 460)
    if ($x -ne 0) {
        $g.DrawString("$x", $fontAxis, $brushText, ($xp - 8), 268)
    } else {
        $g.DrawString("O", $fontAxis, $brushText, ($xp - 14), 268)
    }
}

# Axes
$g.DrawLine($penAxisA, 60, 260, 465, 260)
$g.DrawLine($penAxisA, 260, 480, 260, 40)
$g.DrawString("x", $fontItalic13, $brushText, 470, 252)
$g.DrawString("y", $fontItalic13, $brushText, 254, 18)

# Line: y = 6x + 9
# At y=10, 6x = 1 -> x = 0.17 -> xp = 263, yp = 60
# At y=-10, 6x = -19 -> x = -3.17 -> xp = 203, yp = 460
$pL1 = New-Object System.Drawing.PointF((260 + (0.17 * 18)), 60)
$pL2 = New-Object System.Drawing.PointF((260 + (-3.17 * 18)), 460)
$g.DrawLine($penBlueLine, $pL1, $pL2)

# Marked points: (0, 9) and (-2, -3)
$pt1 = New-Object System.Drawing.PointF(260, (260 - (9 * 20)))
$pt2 = New-Object System.Drawing.PointF((260 + (-2 * 18)), (260 - (-3 * 20)))

$g.FillEllipse($brushWhite, ($pt1.X - 5), ($pt1.Y - 5), 10, 10)
$g.DrawEllipse($penDotBorder, ($pt1.X - 5), ($pt1.Y - 5), 10, 10)

$g.FillEllipse($brushWhite, ($pt2.X - 5), ($pt2.Y - 5), 10, 10)
$g.DrawEllipse($penDotBorder, ($pt2.X - 5), ($pt2.Y - 5), 10, 10)

$c.Bitmap.Save((Join-Path $outDir "m2_q10_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 7. M2 Q12 (Linear inequality: rx + ty >= -77 through (-7, -10) and (0, -11))
# ----------------------------------------------------
$c = Create-Canvas 520 520
$g = $c.Graphics

# X: -10 to 0 (10 intervals of 36px -> 360px, x=80 to 440)
# Y: -15 to 0 (15 intervals of 25px -> 375px, y=455 to 80)
for ($y = -14; $y -le 0; $y += 2) {
    $yp = 80 + (-$y * 25)
    $g.DrawLine($penGridL, 80, $yp, 440, $yp)
    if ($y -ne 0) {
        $g.DrawString("$y", $fontAxis, $brushText, 448, ($yp - 8))
    }
}
for ($x = -10; $x -le 0; $x += 2) {
    $xp = 440 + ($x * 36)
    $g.DrawLine($penGridL, $xp, 80, $xp, 455)
    if ($x -ne 0) {
        $g.DrawString("$x", $fontAxis, $brushText, ($xp - 12), 60)
    } else {
        $g.DrawString("O", $fontAxis, $brushText, ($xp - 12), 60)
    }
}

# Axes
$g.DrawLine($penAxisA, 60, 80, 465, 80)    # X-axis at y=0
$g.DrawLine($penAxisA, 440, 475, 440, 50)  # Y-axis at x=0
$g.DrawString("x", $fontItalic13, $brushText, 470, 72)
$g.DrawString("y", $fontItalic13, $brushText, 448, 25)

# Boundary line: y = -1/7 x - 11
# At x=-10, y = -9.57 -> yp = 80 + (9.57 * 25) = 319
# At x=0, y = -11 -> yp = 80 + (11 * 25) = 355
$pShade1 = New-Object System.Drawing.PointF(80, (80 + (9.57 * 25)))
$pShade2 = New-Object System.Drawing.PointF(440, (80 + (11 * 25)))
$pShadeTopR = New-Object System.Drawing.PointF(440, 80)
$pShadeTopL = New-Object System.Drawing.PointF(80, 80)

$brushShade = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(40, 59, 130, 246))
$g.FillPolygon($brushShade, @($pShade1, $pShade2, $pShadeTopR, $pShadeTopL))

# Draw boundary line
$g.DrawLine($penBlueLine, $pShade1, $pShade2)

# Marked points: (-7, -10) and (0, -11)
$pM1 = New-Object System.Drawing.PointF((440 + (-7 * 36)), (80 + (10 * 25)))
$pM2 = New-Object System.Drawing.PointF(440, (80 + (11 * 25)))

$g.FillEllipse($brushWhite, ($pM1.X - 5), ($pM1.Y - 5), 10, 10)
$g.DrawEllipse($penDotBorder, ($pM1.X - 5), ($pM1.Y - 5), 10, 10)

$g.FillEllipse($brushWhite, ($pM2.X - 5), ($pM2.Y - 5), 10, 10)
$g.DrawEllipse($penDotBorder, ($pM2.X - 5), ($pM2.Y - 5), 10, 10)

$c.Bitmap.Save((Join-Path $outDir "m2_q12_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 8. M2 Q15 (Graph of y = f(x) + 2: y = -3^x + 5)
# ----------------------------------------------------
$c = Create-Canvas 520 540
$g = $c.Graphics

for ($y = -5; $y -le 10; $y++) {
    $yp = 340 - ($y * 30)
    if ($y % 2 -eq 0 -or $y -eq 5 -or $y -eq -5) {
        $g.DrawLine($penGridL, 80, $yp, 440, $yp)
        $g.DrawString("$y", $fontAxis, $brushText, 52, ($yp - 8))
    }
}
for ($x = -1; $x -le 5; $x++) {
    $xp = 140 + ($x * 60)
    $g.DrawLine($penGridL, $xp, 40, $xp, 490)
    if ($x -ne 0) {
        $g.DrawString("$x", $fontAxis, $brushText, ($xp - 6), 348)
    }
}

# Axes
$g.DrawLine($penAxisA, 70, 340, 460, 340)
$g.DrawLine($penAxisA, 140, 500, 140, 25)
$g.DrawString("x", $fontItalic13, $brushText, 465, 332)
$g.DrawString("y", $fontItalic13, $brushText, 134, 4)

# Curve: y = -3^x + 5
# Asymptote y = 5
# At x=0, y = 4
# At x=1, y = 2
# At x=1.46, y = 0
# At x=2, y = -4
$ptsExpM2 = New-Object System.Collections.Generic.List[System.Drawing.PointF]
for ($step = -100; $step -le 210; $step++) {
    $xVal = $step / 100.0
    $yVal = - [Math]::Pow(3, $xVal) + 5
    $px = 140 + ($xVal * 60)
    $py = 340 - ($yVal * 30)
    $ptsExpM2.Add((New-Object System.Drawing.PointF($px, $py)))
}
$g.DrawLines($penCurve, $ptsExpM2.ToArray())

$c.Bitmap.Save((Join-Path $outDir "m2_q15_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

Write-Host "All 8 light images successfully generated for March 2025 INT 3 in $outDir"
