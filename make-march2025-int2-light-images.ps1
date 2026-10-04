Add-Type -AssemblyName System.Drawing

$outDir = Join-Path $PSScriptRoot "march2025_int2_light_images"
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
$penLine = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 41, 59), 3)

# ----------------------------------------------------
# 1. M1 Q2 (Right Triangle: legs b and 8, hypotenuse 20)
# ----------------------------------------------------
$c = Create-Canvas 600 380
$g = $c.Graphics

$pA = New-Object System.Drawing.PointF(70, 270)   # bottom-left
$pC = New-Object System.Drawing.PointF(520, 270)  # bottom-right (right angle)
$pB = New-Object System.Drawing.PointF(520, 70)   # top-right

# Draw triangle
$g.DrawLine($penLine, $pA, $pC)
$g.DrawLine($penLine, $pC, $pB)
$g.DrawLine($penLine, $pA, $pB)

# Right angle square at C (520, 270)
$sqSize = 20
$g.DrawRectangle($penLine, (520 - $sqSize), (270 - $sqSize), $sqSize, $sqSize)

# Labels
$g.DrawString("20", $fontLabel, $brushText, 280, 140)
$g.DrawString("8", $fontLabel, $brushText, 535, 165)
$g.DrawString("b", $fontLabel, $brushText, 290, 285)

$sf = New-Object System.Drawing.StringFormat
$sf.Alignment = [System.Drawing.StringAlignment]::Center
$g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushNote, 300, 335, $sf)

$c.Bitmap.Save((Join-Path $outDir "m1_q2_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 2. M1 Q3 (Histogram: Length (feet) vs Frequency)
# ----------------------------------------------------
$c = Create-Canvas 650 420
$g = $c.Graphics

$penAxis = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(51, 65, 85), 2)
$penGrid = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(226, 232, 240), 1)
$penBarBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(29, 78, 216), 2)
$brushBar = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(59, 130, 246))

# Frequency 0 to 5 -> 5 intervals of 56px
for ($i = 0; $i -le 5; $i++) {
    $y = 340 - ($i * 56)
    $g.DrawLine($penGrid, 90, $y, 590, $y)
    $g.DrawString("$i", $fontAxis, $brushText, 65, ($y - 8))
}

# 5 bins: 0-50, 50-100, 100-150, 150-200, 200-250 (each 100px wide)
$heights = @(5, 3, 4, 3, 5)
for ($b = 0; $b -lt 5; $b++) {
    $bx = 90 + ($b * 100)
    $bh = $heights[$b] * 56
    $by = 340 - $bh
    $g.FillRectangle($brushBar, $bx, $by, 100, $bh)
    $g.DrawRectangle($penBarBorder, $bx, $by, 100, $bh)
}

# Axes
$g.DrawLine($penAxis, 90, 340, 590, 340)
$g.DrawLine($penAxis, 90, 60, 90, 340)

# X-axis ticks & labels
$xVals = @(0, 50, 100, 150, 200, 250)
for ($k = 0; $k -le 5; $k++) {
    $xPos = 90 + ($k * 100)
    $g.DrawLine($penAxis, $xPos, 340, $xPos, 346)
    $g.DrawString("$($xVals[$k])", $fontAxis, $brushText, ($xPos - 12), 352)
}

# Axis titles
$sfC = New-Object System.Drawing.StringFormat
$sfC.Alignment = [System.Drawing.StringAlignment]::Center
$g.DrawString("Length (feet)", $fontTitle, $brushText, 340, 385, $sfC)

# Rotated Y-axis title
$state = $g.Save()
$g.TranslateTransform(25, 200)
$g.RotateTransform(-90)
$g.DrawString("Frequency", $fontTitle, $brushText, 0, 0, $sfC)
$g.Restore($state)

$c.Bitmap.Save((Join-Path $outDir "m1_q3_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 3. M1 Q8 (Scatterplot & Line of Best Fit: y = -x + 2.3)
# ----------------------------------------------------
$c = Create-Canvas 520 540
$g = $c.Graphics

$penAxisA = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 41, 59), 2.5)
$penAxisA.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
$penGridL = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(203, 213, 225), 1)

# Horizontal grid
for ($j = 0; $j -le 10; $j++) {
    $yVal = $j * 2
    $yP = 460 - ($j * 40)
    $g.DrawLine($penGridL, 80, $yP, 416, $yP)
    $g.DrawString("$yVal", $fontAxis, $brushText, 422, ($yP - 8))
}

# Vertical grid
for ($i = 0; $i -le 7; $i++) {
    $xVal = -14 + ($i * 2)
    $xP = 80 + ($i * 48)
    $g.DrawLine($penGridL, $xP, 60, $xP, 460)
    if ($xVal -ne 0) {
        $g.DrawString("$xVal", $fontAxis, $brushText, ($xP - 12), 468)
    } else {
        $g.DrawString("O", $fontAxis, $brushText, ($xP - 4), 468)
    }
}

# Axes with arrows
$g.DrawLine($penAxisA, 70, 460, 450, 460) # X-axis
$g.DrawLine($penAxisA, 416, 470, 416, 40)  # Y-axis
$g.DrawString("x", $fontItalic13, $brushText, 455, 450)
$g.DrawString("y", $fontItalic13, $brushText, 412, 18)

# Line of best fit from x=-14 (y=16.3) to x=0 (y=2.3)
$penBestFit = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 41, 59), 3)
$pStart = New-Object System.Drawing.PointF(80, (460 - (16.3 / 2 * 40)))
$pEnd = New-Object System.Drawing.PointF(416, (460 - (2.3 / 2 * 40)))
$g.DrawLine($penBestFit, $pStart, $pEnd)

# Scatter points: (-14, 16), (-12, 14.2), (-10, 12.5), (-8, 11), (-6, 9), (-4, 5.2)
$pts = @(
    @{ x = -14; y = 16.0 },
    @{ x = -12; y = 14.2 },
    @{ x = -10; y = 12.5 },
    @{ x = -8; y = 11.0 },
    @{ x = -6; y = 9.0 },
    @{ x = -4; y = 5.2 }
)
$brushPt = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(59, 130, 246))
$penPt = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(29, 78, 216), 1.5)
foreach ($pt in $pts) {
    $px = 80 + (($pt.x - (-14)) / 2 * 48)
    $py = 460 - ($pt.y / 2 * 40)
    $g.FillEllipse($brushPt, ($px - 6), ($py - 6), 12, 12)
    $g.DrawEllipse($penPt, ($px - 6), ($py - 6), 12, 12)
}

$c.Bitmap.Save((Join-Path $outDir "m1_q8_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 4. M1 Q20 (Right Circular Cone: apex A, point B)
# ----------------------------------------------------
$c = Create-Canvas 500 380
$g = $c.Graphics

$apex = New-Object System.Drawing.PointF(250, 70)
$baseLeft = New-Object System.Drawing.PointF(80, 230)
$baseRight = New-Object System.Drawing.PointF(420, 230)

# Slant lines
$g.DrawLine($penLine, $apex, $baseLeft)
$g.DrawLine($penLine, $apex, $baseRight)

# Front half of base ellipse (solid)
$g.DrawArc($penLine, 80, 200, 340, 60, 0, 180)

# Back half of base ellipse (dashed)
$penDash = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(100, 116, 139), 2)
$penDash.DashPattern = @(4.0, 4.0)
$g.DrawArc($penDash, 80, 200, 340, 60, 180, 180)

# Apex A dot & label
$brushDot = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30, 41, 59))
$g.FillEllipse($brushDot, 246, 66, 8, 8)
$g.DrawString("A", $fontItalic16, $brushText, 243, 38)

# Point B on front circumference
$ptB = New-Object System.Drawing.PointF(145, 252)
$g.FillEllipse($brushDot, ($ptB.X - 4), ($ptB.Y - 4), 8, 8)
$g.DrawString("B", $fontItalic16, $brushText, ($ptB.X - 8), ($ptB.Y + 8))

$g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushNote, 250, 325, $sfC)

$c.Bitmap.Save((Join-Path $outDir "m1_q20_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 5. M2 Q1 (Parabola: Ball height vs time, mark at (1.0, 3.9))
# ----------------------------------------------------
$c = Create-Canvas 560 460
$g = $c.Graphics

for ($y = 0; $y -le 7; $y++) {
    $yp = 390 - ($y * 50)
    $g.DrawLine($penGridL, 100, $yp, 480, $yp)
    $g.DrawString("$y", $fontAxis, $brushText, 80, ($yp - 8))
}
for ($x = 0; $x -le 3; $x++) {
    $xp = 100 + ($x * 120)
    $g.DrawLine($penGridL, $xp, 40, $xp, 390)
    $g.DrawString("$x", $fontAxis, $brushText, ($xp - 5), 398)
}

# Axes
$g.DrawLine($penAxisA, 90, 390, 510, 390)
$g.DrawLine($penAxisA, 100, 400, 100, 20)

$g.DrawString("Time (seconds)", $fontTitle, $brushText, 290, 425, $sfC)

$state = $g.Save()
$g.TranslateTransform(28, 215)
$g.RotateTransform(-90)
$g.DrawString("Height above ground (meters)", $fontTitle, $brushText, 0, 0, $sfC)
$g.Restore($state)

# Parabola
$penCurve = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(37, 99, 235), 3.5)
$ptsParabola = New-Object System.Collections.Generic.List[System.Drawing.PointF]
for ($step = 0; $step -le 156; $step++) {
    $t = $step / 100.0
    $ht = -4.9 * $t * $t + 5.8 * $t + 3.0
    if ($ht -lt 0) { $ht = 0 }
    $px = 100 + ($t * 120)
    $py = 390 - ($ht * 50)
    $ptsParabola.Add((New-Object System.Drawing.PointF($px, $py)))
}
$g.DrawLines($penCurve, $ptsParabola.ToArray())

# Mark at (1.0, 3.9) with an 'x'
$markX = 100 + (1.0 * 120)
$markY = 390 - (3.9 * 50)
$penX = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 38, 38), 3)
$g.DrawLine($penX, ($markX - 6), ($markY - 6), ($markX + 6), ($markY + 6))
$g.DrawLine($penX, ($markX - 6), ($markY + 6), ($markX + 6), ($markY - 6))

$c.Bitmap.Save((Join-Path $outDir "m2_q1_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 6. M2 Q4 (Similar Triangles: CAE and CBD)
# ----------------------------------------------------
$c = Create-Canvas 480 500
$g = $c.Graphics

$pC = New-Object System.Drawing.PointF(400, 60)   # top
$pD = New-Object System.Drawing.PointF(400, 240)  # right middle
$pE = New-Object System.Drawing.PointF(400, 420)  # right bottom
$pB = New-Object System.Drawing.PointF(230, 240)  # hyp middle
$pA = New-Object System.Drawing.PointF(60, 420)   # hyp bottom

# Draw lines
$g.DrawLine($penLine, $pC, $pE)
$g.DrawLine($penLine, $pE, $pA)
$g.DrawLine($penLine, $pA, $pC)
$g.DrawLine($penLine, $pB, $pD)

# Right angle marks at D and E
$sq = 18
$g.DrawRectangle($penLine, (400 - $sq), (240 - $sq), $sq, $sq)
$g.DrawRectangle($penLine, (400 - $sq), (420 - $sq), $sq, $sq)

# Vertex labels
$fontV = New-Object System.Drawing.Font("Arial", 16, [System.Drawing.FontStyle]::Regular)
$g.DrawString("C", $fontV, $brushText, 408, 42)
$g.DrawString("D", $fontV, $brushText, 412, 230)
$g.DrawString("E", $fontV, $brushText, 412, 415)
$g.DrawString("B", $fontV, $brushText, 205, 222)
$g.DrawString("A", $fontV, $brushText, 42, 428)

$c.Bitmap.Save((Join-Path $outDir "m2_q4_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 7. M2 Q12 (Linear inequality: shaded region above line)
# ----------------------------------------------------
$c = Create-Canvas 520 520
$g = $c.Graphics

for ($y = -14; $y -le 0; $y += 2) {
    $yp = 90 + (-$y / 2 * 50)
    $g.DrawLine($penGridL, 80, $yp, 440, $yp)
    $g.DrawString("$y", $fontAxis, $brushText, 448, ($yp - 8))
}
for ($x = -10; $x -le 0; $x += 2) {
    $xp = 440 + ($x / 2 * 72)
    $g.DrawLine($penGridL, $xp, 90, $xp, 440)
    $g.DrawString("$x", $fontAxis, $brushText, ($xp - 12), 68)
}

# Axes
$g.DrawLine($penAxisA, 60, 90, 470, 90)   # X-axis at y=0
$g.DrawLine($penAxisA, 440, 460, 440, 60) # Y-axis at x=0
$g.DrawString("x", $fontItalic13, $brushText, 475, 82)
$g.DrawString("y", $fontItalic13, $brushText, 448, 52)

# Line through (-4, -10) and (0, -11.5)
$pL1 = New-Object System.Drawing.PointF(80, (90 + (7.75 / 2 * 50)))   # at x=-10
$pL2 = New-Object System.Drawing.PointF(440, (90 + (11.5 / 2 * 50)))  # at x=0
$pTopR = New-Object System.Drawing.PointF(440, 90)
$pTopL = New-Object System.Drawing.PointF(80, 90)

$brushShade = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(40, 59, 130, 246))
$g.FillPolygon($brushShade, @($pL1, $pL2, $pTopR, $pTopL))

# Draw boundary line
$penBound = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(37, 99, 235), 3)
$g.DrawLine($penBound, $pL1, $pL2)

# Point (-4, -10) mark with 'x'
$mX = 440 + (-4 / 2 * 72)
$mY = 90 + (10 / 2 * 50)
$penRedX = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 38, 38), 3)
$g.DrawLine($penRedX, ($mX - 6), ($mY - 6), ($mX + 6), ($mY + 6))
$g.DrawLine($penRedX, ($mX - 6), ($mY + 6), ($mX + 6), ($mY - 6))

$c.Bitmap.Save((Join-Path $outDir "m2_q12_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

# ----------------------------------------------------
# 8. M2 Q16 (Graph of y = f(x) + 2: y = -5^x + 5)
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
$g.DrawLine($penAxisA, 70, 340, 460, 340)  # X-axis at y=0
$g.DrawLine($penAxisA, 140, 500, 140, 25) # Y-axis at x=0
$g.DrawString("x", $fontItalic13, $brushText, 465, 332)
$g.DrawString("y", $fontItalic13, $brushText, 134, 4)

$ptsExp = New-Object System.Collections.Generic.List[System.Drawing.PointF]
for ($step = -100; $step -le 145; $step++) {
    $xVal = $step / 100.0
    $yVal = - [Math]::Pow(5, $xVal) + 5
    $px = 140 + ($xVal * 60)
    $py = 340 - ($yVal * 30)
    $ptsExp.Add((New-Object System.Drawing.PointF($px, $py)))
}
$g.DrawLines($penCurve, $ptsExp.ToArray())

$c.Bitmap.Save((Join-Path $outDir "m2_q16_light.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$c.Bitmap.Dispose()
$g.Dispose()

Write-Host "All 8 light images successfully generated in $outDir"
