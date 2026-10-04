Add-Type -AssemblyName System.Drawing

$outputDir = "may2025_int2_light_images"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

function Save-Bitmap($bmp, $filename) {
    $path = Join-Path $outputDir $filename
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Created $filename"
}

# ----------------------------------------------------
# 1. M1 Q18: Distance vs Time graph
# ----------------------------------------------------
function Make-M1-Q18 {
    $width = 600
    $height = 600
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 80
    $top = 40
    $plotW = 460
    $plotH = 460
    $bottom = $top + $plotH
    $right = $left + $plotW

    $penGrid = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 226, 235), 1.5)
    $penAxis = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $penLine = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(37, 99, 235), 3.5) # Blue line
    $brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))
    $fontAxis = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $fontLabel = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)

    # Grid & ticks
    # X from 0 to 8
    for ($i = 0; $i -le 8; $i++) {
        $x = $left + ($i * $plotW / 8.0)
        $g.DrawLine($penGrid, $x, $top, $x, $bottom)
        $txt = "$i"
        $sz = $g.MeasureString($txt, $fontAxis)
        $g.DrawString($txt, $fontAxis, $brushText, ($x - $sz.Width / 2), ($bottom + 8))
    }

    # Y from 0 to 80
    for ($j = 0; $j -le 8; $j++) {
        $val = $j * 10
        $y = $bottom - ($j * $plotH / 8.0)
        $g.DrawLine($penGrid, $left, $y, $right, $y)
        $txt = "$val"
        $sz = $g.MeasureString($txt, $fontAxis)
        $g.DrawString($txt, $fontAxis, $brushText, ($left - $sz.Width - 8), ($y - $sz.Height / 2))
    }

    # Axes
    $g.DrawLine($penAxis, $left, $bottom, $right + 15, $bottom) # X axis
    $g.DrawLine($penAxis, $left, $bottom, $left, $top - 15)      # Y axis

    # Plot line: (0,0) -> (1, 60) -> (5, 60) -> (6, 0)
    $p0 = New-Object System.Drawing.PointF($left, $bottom)
    $p1 = New-Object System.Drawing.PointF(($left + 1 * $plotW / 8.0), ($bottom - 6 * $plotH / 8.0))
    $p2 = New-Object System.Drawing.PointF(($left + 5 * $plotW / 8.0), ($bottom - 6 * $plotH / 8.0))
    $p3 = New-Object System.Drawing.PointF(($left + 6 * $plotW / 8.0), $bottom)

    $points = [System.Drawing.PointF[]]@($p0, $p1, $p2, $p3)
    $g.DrawLines($penLine, $points)

    # Axis Labels
    $lblX = "Time (hours)"
    $szX = $g.MeasureString($lblX, $fontLabel)
    $g.DrawString($lblX, $fontLabel, $brushText, ($left + ($plotW - $szX.Width)/2), ($bottom + 35))

    # Y label rotated
    $state = $g.Save()
    $lblY = "Distance (miles)"
    $szY = $g.MeasureString($lblY, $fontLabel)
    $g.TranslateTransform(25, ($top + ($plotH + $szY.Width)/2))
    $g.RotateTransform(-90)
    $g.DrawString($lblY, $fontLabel, $brushText, 0, 0)
    $g.Restore($state)

    Save-Bitmap $bmp "m1_q18_light.png"
}

# ----------------------------------------------------
# 2. M2 Q2: Parallel lines j and k cut by transversal l
# ----------------------------------------------------
function Make-M2-Q2 {
    $width = 650
    $height = 500
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))
    $fontLabel = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)

    $yJ = 150
    $yK = 320

    # Horizontal lines j and k
    $g.DrawLine($penLine, 50, $yJ, 520, $yJ)
    $g.DrawLine($penLine, 50, $yK, 520, $yK)

    # Line labels j and k
    $g.DrawString("j", $fontLabel, $brushText, 540, ($yJ - 15))
    $g.DrawString("k", $fontLabel, $brushText, 540, ($yK - 15))

    # Transversal line l passing through (400, 70) to (80, 440)
    # Slope approx (440 - 70)/(80 - 400) = 370 / -320
    # Let's parameterize nicely:
    $pTop = New-Object System.Drawing.PointF(450, 40)
    $pBottom = New-Object System.Drawing.PointF(70, 460)
    $g.DrawLine($penLine, $pTop, $pBottom)
    $g.DrawString("l", $fontLabel, $brushText, 460, 20)

    # Intersection at line j:
    # x = 450 - (y - 40) * (380 / 420)
    # At y = 150: x approx 450 - 110 * 0.9048 = 350
    $intJ_x = 450 - (150 - 40) * (380.0 / 420.0) # approx 350.5
    # At y = 320: x approx 450 - 280 * 0.9048 = 196.7
    $intK_x = 450 - (320 - 40) * (380.0 / 420.0)

    # Top intersection angles:
    # w° is top right of intersection with j
    $g.DrawString("w°", $fontVal, $brushText, ($intJ_x + 40), ($yJ - 38))
    # x° is bottom left of intersection with j
    $g.DrawString("x°", $fontVal, $brushText, ($intJ_x - 50), ($yJ + 12))

    # Bottom intersection angles:
    # 54° is top right of intersection with k
    $g.DrawString("54°", $fontVal, $brushText, ($intK_x + 35), ($yK - 38))
    # y° is bottom left of intersection with k
    $g.DrawString("y°", $fontVal, $brushText, ($intK_x - 55), ($yK + 15))
    # z° is bottom right of intersection with k
    $g.DrawString("z°", $fontVal, $brushText, ($intK_x + 15), ($yK + 15))

    Save-Bitmap $bmp "m2_q2_light.png"
}

# ----------------------------------------------------
# 3. M2 Q17: Histograms of Group A and Group B
# ----------------------------------------------------
function Make-M2-Q17 {
    $width = 750
    $height = 480
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(226, 232, 240), 1.0)
    $penGrid.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $penAxis = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.0)
    $brushBar = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(148, 163, 184))
    $penBar = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(71, 85, 105), 1.5)
    $brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))

    $fontTitle = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
    $fontAxis = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $fontTick = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Regular)

    $top = 60
    $plotH = 320
    $bottom = $top + $plotH
    $plotW = 270

    # Y ticks 0 to 12 in increments of 2
    for ($v = 0; $v -le 12; $v += 2) {
        $y = $bottom - ($v * $plotH / 12.0)
        # horizontal grid line across both panels
        $g.DrawLine($penGrid, 70, $y, 360, $y)
        $g.DrawLine($penGrid, 440, $y, 730, $y)
        # Left labels
        $txt = "$v"
        $sz = $g.MeasureString($txt, $fontTick)
        $g.DrawString($txt, $fontTick, $brushText, (65 - $sz.Width), ($y - $sz.Height/2))
    }

    # Left Panel: Group A
    $leftA = 70
    $titleA = "Group A"
    $szTA = $g.MeasureString($titleA, $fontTitle)
    $g.DrawString($titleA, $fontTitle, $brushText, ($leftA + ($plotW - $szTA.Width)/2), 20)

    # Bars for Group A: [0,1]: 6; [1,2]: 3; [2,3]: 2; [3,4]: 3; [4,5]: 6
    $barsA = @(6, 3, 2, 3, 6)
    $binWA = $plotW / 5.0
    for ($i = 0; $i -lt 5; $i++) {
        $h = $barsA[$i] * $plotH / 12.0
        $bx = $leftA + $i * $binWA
        $by = $bottom - $h
        $g.FillRectangle($brushBar, $bx, $by, $binWA, $h)
        $g.DrawRectangle($penBar, $bx, $by, $binWA, $h)

        # X tick label
        $xVal = "$i"
        $szX = $g.MeasureString($xVal, $fontTick)
        $g.DrawString($xVal, $fontTick, $brushText, ($bx - $szX.Width/2), ($bottom + 5))
    }
    # Final tick 5
    $szX5 = $g.MeasureString("5", $fontTick)
    $g.DrawString("5", $fontTick, $brushText, ($leftA + 5 * $binWA - $szX5.Width/2), ($bottom + 5))

    $g.DrawLine($penAxis, $leftA, $top - 10, $leftA, $bottom)
    $g.DrawLine($penAxis, $leftA, $bottom, $leftA + $plotW, $bottom)

    # X axis label A
    $lblXA = "Weight (grams)"
    $szXA = $g.MeasureString($lblXA, $fontAxis)
    $g.DrawString($lblXA, $fontAxis, $brushText, ($leftA + ($plotW - $szXA.Width)/2), ($bottom + 32))

    # Right Panel: Group B
    $leftB = 440
    $titleB = "Group B"
    $szTB = $g.MeasureString($titleB, $fontTitle)
    $g.DrawString($titleB, $fontTitle, $brushText, ($leftB + ($plotW - $szTB.Width)/2), 20)

    # Bars for Group B: [9,10]: 2; [10,11]: 3; [11,12]: 10; [12,13]: 3; [13,14]: 2
    $barsB = @(2, 3, 10, 3, 2)
    $binWB = $plotW / 5.0
    for ($i = 0; $i -lt 5; $i++) {
        $h = $barsB[$i] * $plotH / 12.0
        $bx = $leftB + $i * $binWB
        $by = $bottom - $h
        $g.FillRectangle($brushBar, $bx, $by, $binWB, $h)
        $g.DrawRectangle($penBar, $bx, $by, $binWB, $h)

        $xVal = "$(9 + $i)"
        $szX = $g.MeasureString($xVal, $fontTick)
        $g.DrawString($xVal, $fontTick, $brushText, ($bx - $szX.Width/2), ($bottom + 5))
    }
    # Final tick 14
    $szX14 = $g.MeasureString("14", $fontTick)
    $g.DrawString("14", $fontTick, $brushText, ($leftB + 5 * $binWB - $szX14.Width/2), ($bottom + 5))

    $g.DrawLine($penAxis, $leftB, $top - 10, $leftB, $bottom)
    $g.DrawLine($penAxis, $leftB, $bottom, $leftB + $plotW, $bottom)

    # X axis label B
    $g.DrawString($lblXA, $fontAxis, $brushText, ($leftB + ($plotW - $szXA.Width)/2), ($bottom + 32))

    # Y label rotated on far left
    $state = $g.Save()
    $lblY = "Number of objects"
    $szY = $g.MeasureString($lblY, $fontAxis)
    $g.TranslateTransform(20, ($top + ($plotH + $szY.Width)/2))
    $g.RotateTransform(-90)
    $g.DrawString($lblY, $fontAxis, $brushText, 0, 0)
    $g.Restore($state)

    Save-Bitmap $bmp "m2_q17_light.png"
}

# ----------------------------------------------------
# 4. M2 Q20: Right triangle ABC with altitude AD to hypotenuse
# ----------------------------------------------------
function Make-M2-Q20 {
    $width = 700
    $height = 420
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penTriangle = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 3.0)
    $penAlt = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(37, 99, 235), 2.5)
    $penSquare = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(71, 85, 105), 1.8)
    $brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))
    $fontLabel = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)

    # Coordinates:
    # A (right angle at bottom-left): (80, 340)
    # B (top-left): (80, 60)
    # C (bottom-right): (620, 340)
    $pA = New-Object System.Drawing.PointF(80, 340)
    $pB = New-Object System.Drawing.PointF(80, 60)
    $pC = New-Object System.Drawing.PointF(620, 340)

    # Draw triangle ABC
    $g.DrawLine($penTriangle, $pA, $pB)
    $g.DrawLine($penTriangle, $pB, $pC)
    $g.DrawLine($penTriangle, $pA, $pC)

    # Right angle marker at A: square from (80, 340) to (105, 340) to (105, 315) to (80, 315)
    $sqA = [System.Drawing.PointF[]]@(
        (New-Object System.Drawing.PointF(80, 315)),
        (New-Object System.Drawing.PointF(105, 315)),
        (New-Object System.Drawing.PointF(105, 340))
    )
    $g.DrawLines($penSquare, $sqA)

    # Altitude AD from A to hypotenuse BC:
    # Vector BC = C - B = (540, 280)
    # Length^2 = 540^2 + 280^2 = 291600 + 78400 = 370000
    # Vector BA = A - B = (0, 280)
    # Projection of BA onto BC:
    # t = (BA . BC) / |BC|^2 = (0 * 540 + 280 * 280) / 370000 = 78400 / 370000 = 784 / 3700 approx 0.21189
    # D = B + t * BC = (80 + 0.21189 * 540, 60 + 0.21189 * 280) = (80 + 114.42, 60 + 59.33) = (194.42, 119.33)
    $pD = New-Object System.Drawing.PointF(194.42, 119.33)
    $g.DrawLine($penAlt, $pA, $pD)

    # Right angle marker at D:
    # Unit vector along DB (from D toward B):
    # u_DB = (-114.42, -59.33) / 128.9 = (-0.8877, -0.4603)
    # Unit vector along DA (from D toward A):
    # u_DA = (80 - 194.42, 340 - 119.33) / 248.5 = (-114.42, 220.67) / 248.5 = (-0.4604, 0.8880)
    # Square corners at D:
    $sLen = 22.0
    $pt1 = New-Object System.Drawing.PointF(($pD.X + $sLen * -0.8877), ($pD.Y + $sLen * -0.4603))
    $pt2 = New-Object System.Drawing.PointF(($pD.X + $sLen * -0.8877 + $sLen * -0.4604), ($pD.Y + $sLen * -0.4603 + $sLen * 0.8880))
    $pt3 = New-Object System.Drawing.PointF(($pD.X + $sLen * -0.4604), ($pD.Y + $sLen * 0.8880))
    $sqD = [System.Drawing.PointF[]]@($pt1, $pt2, $pt3)
    $g.DrawLines($penSquare, $sqD)

    # Labels: A, B, C, D
    $g.DrawString("A", $fontLabel, $brushText, 50, 350)
    $g.DrawString("B", $fontLabel, $brushText, 55, 30)
    $g.DrawString("C", $fontLabel, $brushText, 635, 335)
    $g.DrawString("D", $fontLabel, $brushText, 205, 85)

    Save-Bitmap $bmp "m2_q20_light.png"
}

Write-Host "Rendering all light-mode images for May 2025 · INT 2..."
Make-M1-Q18
Make-M2-Q2
Make-M2-Q17
Make-M2-Q20
Write-Host "All light-mode images generated successfully!"
