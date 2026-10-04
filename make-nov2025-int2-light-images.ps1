Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "nov2025_int2_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)
$cLine = [System.Drawing.Color]::FromArgb(37, 99, 235)

# ==============================================================================
# 1. M1 Q6: Scatterplot of Store Size vs Annual Sales
# ==============================================================================
function Render-M1-Q6 {
    $outPath = Join-Path $imgDir "m1_q6_light.png"
    $w = 460; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penDot = New-Object System.Drawing.Pen($cDark, 1.2)
    $brushDot = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(37, 99, 235))
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.5, [System.Drawing.FontStyle]::Regular)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 12, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Coordinate mapping:
    # x in [0, 7], y in [0, 15]
    $ox = 110.0; $oy = 340.0
    $gw = 300.0; $gh = 280.0
    $dx = $gw / 7.0; $dy = $gh / 15.0

    # Draw grid lines
    for ($xi = 1; $xi -le 7; $xi++) {
        $x = $ox + $xi * $dx
        $g.DrawLine($penGrid, [float]$x, [float]($oy - $gh), [float]$x, [float]$oy)
    }
    for ($yi = 1; $yi -le 15; $yi++) {
        $y = $oy - $yi * $dy
        $g.DrawLine($penGrid, [float]$ox, [float]$y, [float]($ox + $gw), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]($ox + $gw + 15), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, [float]($oy - $gh - 15))

    # Arrows
    $g.DrawLine($penAxis, [float]($ox + $gw + 15), [float]$oy, [float]($ox + $gw + 8), [float]($oy - 4))
    $g.DrawLine($penAxis, [float]($ox + $gw + 15), [float]$oy, [float]($ox + $gw + 8), [float]($oy + 4))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - $gh - 15), [float]($ox - 4), [float]($oy - $gh - 8))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - $gh - 15), [float]($ox + 4), [float]($oy - $gh - 8))

    # Ticks & labels
    $g.DrawString("O", $fontV, $brush, [float]($ox - 14), [float]($oy + 2))
    $g.DrawString("x", $fontV, $brush, [float]($ox + $gw + 20), [float]($oy - 8))
    $g.DrawString("y", $fontV, $brush, [float]($ox - 8), [float]($oy - $gh - 30))

    for ($xi = 1; $xi -le 7; $xi++) {
        $x = $ox + $xi * $dx
        $g.DrawString("$xi", $fontAxis, $brush, [float]$x, [float]($oy + 4), $sfC)
    }
    for ($yi = 2; $yi -le 14; $yi += 2) {
        $y = $oy - $yi * $dy
        $g.DrawString("$yi", $fontAxis, $brush, [float]($ox - 6), [float]($y - 7), $sfR)
    }

    # Axis Titles
    $g.DrawString("Square footage of store", $fontLabel, $brush, [float]($ox + $gw/2), [float]($oy + 26), $sfC)
    $g.DrawString("(in thousands of square feet)", $fontLabel, $brush, [float]($ox + $gw/2), [float]($oy + 42), $sfC)

    $state = $g.Save()
    $g.TranslateTransform(25, [float]($oy - $gh/2))
    $g.RotateTransform(-90)
    $g.DrawString("Annual sales", $fontLabel, $brush, [float]0, [float]0, $sfC)
    $g.DrawString("(in millions of dollars)", $fontLabel, $brush, [float]0, [float]16, $sfC)
    $g.Restore($state)

    # 12 Points
    $pts = @(
        @(1.05, 2.3),
        @(1.3, 2.6),
        @(1.7, 2.5),
        @(2.0, 4.0),
        @(2.4, 5.6),
        @(3.0, 4.0),
        @(3.0, 6.9),
        @(3.1, 5.7),
        @(5.0, 7.7),
        @(5.3, 10.7),
        @(5.5, 9.9),
        @(6.0, 12.0)
    )

    $r = 4.5
    foreach ($p in $pts) {
        $px = $ox + $p[0] * $dx
        $py = $oy - $p[1] * $dy
        $g.FillEllipse($brushDot, [float]($px - $r), [float]($py - $r), [float]($r*2), [float]($r*2))
        $g.DrawEllipse($penDot, [float]($px - $r), [float]($py - $r), [float]($r*2), [float]($r*2))
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 2. M1 Q10: Parallel Lines l and k with Transversal t
# ==============================================================================
function Render-M1-Q10 {
    $outPath = Join-Path $imgDir "m1_q10_light.png"
    $w = 400; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.0)
    $thinPen = New-Object System.Drawing.Pen($cDark, 1.2)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontDeg = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 11, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Horizontal lines l and k
    $yL = 110.0; $yK = 210.0
    $g.DrawLine($pen, 30.0, [float]$yL, 350.0, [float]$yL)
    $g.DrawLine($pen, 30.0, [float]$yK, 350.0, [float]$yK)

    # Transversal t: from (50, 40) down to (320, 280)
    $x1 = 45.0; $y1 = 35.0
    $x2 = 335.0; $y2 = 295.0
    $g.DrawLine($pen, [float]$x1, [float]$y1, [float]$x2, [float]$y2)

    # Intersections:
    # slope = (295 - 35) / (335 - 45) = 260 / 290 = 26/29
    # at yL = 110: xL = 45 + (110 - 35) * 29/26 = 45 + 75 * 1.115 = 128.6
    # at yK = 210: xK = 45 + (210 - 35) * 29/26 = 45 + 175 * 1.115 = 240.2
    $xL = 128.6; $xK = 240.2

    # Angle arc for x (top-right at line l)
    $deg = [char]176
    $g.DrawString("x$deg", $fontDeg, $brush, [float]($xL + 10), [float]($yL - 25))

    # Angle arc for y (top-left interior at line k)
    $g.DrawString("y$deg", $fontDeg, $brush, [float]($xK - 32), [float]($yK - 24))

    # Line labels
    $g.DrawString("t", $fontV, $brush, [float]($x1 - 2), [float]($y1 - 24))
    $g.DrawString("l", $fontV, $brush, 362.0, [float]($yL - 10))
    $g.DrawString("k", $fontV, $brush, 362.0, [float]($yK - 10))

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, [float]($w / 2), [float]($h - 26), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 3. M1 Q13: Box Plot of Shoal Bass Lengths
# ==============================================================================
function Render-M1-Q13 {
    $outPath = Join-Path $imgDir "m1_q13_light.png"
    $w = 540; $h = 160
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penBox = New-Object System.Drawing.Pen($cDark, 1.8)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.4)
    $brushFill = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(238, 242, 255))
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 10.5, [System.Drawing.FontStyle]::Regular)
    $fontTitle = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Axis: from 32 to 50
    $ox = 45.0; $axisY = 88.0
    $scaleW = 450.0
    $valMin = 32.0; $valMax = 50.0
    $dx = $scaleW / ($valMax - $valMin)

    # Number line
    $g.DrawLine($penAxis, [float]$ox, [float]$axisY, [float]($ox + $scaleW), [float]$axisY)

    # Ticks
    for ($v = 32; $v -le 50; $v++) {
        $tx = $ox + ($v - $valMin) * $dx
        if ($v % 2 -eq 0) {
            $g.DrawLine($penAxis, [float]$tx, [float]($axisY - 6), [float]$tx, [float]($axisY + 6))
            $g.DrawString("$v", $fontAxis, $brush, [float]$tx, [float]($axisY + 9), $sfC)
        } else {
            $g.DrawLine($penAxis, [float]$tx, [float]($axisY - 3), [float]$tx, [float]($axisY + 3))
        }
    }

    # Axis Title
    $g.DrawString("Shoal bass length (cm)", $fontTitle, $brush, [float]($w / 2), [float]($axisY + 35), $sfC)

    # Box Plot parameters:
    # Min = 34, Q1 = 36, Median = 41, Q3 = 46, Max = 49
    $boxTop = 32.0; $boxH = 26.0
    $boxMid = $boxTop + $boxH / 2.0

    $xMin = $ox + (34.0 - $valMin) * $dx
    $xQ1 = $ox + (36.0 - $valMin) * $dx
    $xMed = $ox + (41.0 - $valMin) * $dx
    $xQ3 = $ox + (46.0 - $valMin) * $dx
    $xMax = $ox + (49.0 - $valMin) * $dx

    # Whiskers
    $g.DrawLine($penBox, [float]$xMin, [float]$boxMid, [float]$xQ1, [float]$boxMid)
    $g.DrawLine($penBox, [float]$xMin, [float]($boxMid - 7), [float]$xMin, [float]($boxMid + 7))

    $g.DrawLine($penBox, [float]$xQ3, [float]$boxMid, [float]$xMax, [float]$boxMid)
    $g.DrawLine($penBox, [float]$xMax, [float]($boxMid - 7), [float]$xMax, [float]($boxMid + 7))

    # Box
    $g.FillRectangle($brushFill, [float]$xQ1, [float]$boxTop, [float]($xQ3 - $xQ1), [float]$boxH)
    $g.DrawRectangle($penBox, [float]$xQ1, [float]$boxTop, [float]($xQ3 - $xQ1), [float]$boxH)

    # Median line
    $g.DrawLine($penBox, [float]$xMed, [float]$boxTop, [float]$xMed, [float]($boxTop + $boxH))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 4. M1 Q14: Triangle ABC with Base 10 cm and Height h
# ==============================================================================
function Render-M1-Q14 {
    $outPath = Join-Path $imgDir "m1_q14_light.png"
    $w = 460; $h = 240
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.0)
    $penDash = New-Object System.Drawing.Pen($cDark, 1.6)
    $penDash.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $thinPen = New-Object System.Drawing.Pen($cDark, 1.2)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontNum = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Coordinates: A left, C right, B top center
    $Ax = 50.0; $Ay = 170.0
    $Cx = 410.0; $Cy = 170.0
    $Bx = 230.0; $By = 50.0

    # Draw Triangle ABC
    $pts = @(
        (New-Object System.Drawing.PointF($Ax, $Ay)),
        (New-Object System.Drawing.PointF($Bx, $By)),
        (New-Object System.Drawing.PointF($Cx, $Cy))
    )
    $g.DrawPolygon($pen, $pts)

    # Altitude h
    $g.DrawLine($penDash, [float]$Bx, [float]$By, [float]$Bx, [float]$Ay)

    # Right-angle mark at base of altitude
    $sq = 12.0
    $g.DrawRectangle($thinPen, [float]$Bx, [float]($Ay - $sq), [float]$sq, [float]$sq)

    # Labels
    $g.DrawString("A", $fontV, $brush, [float]($Ax - 22), [float]($Ay - 8))
    $g.DrawString("C", $fontV, $brush, [float]($Cx + 8), [float]($Cy - 8))
    $g.DrawString("B", $fontV, $brush, [float]($Bx - 6), [float]($By - 24))
    $g.DrawString("h", $fontV, $brush, [float]($Bx + 8), [float](($By + $Ay)/2 - 10))
    $g.DrawString("10 cm", $fontNum, $brush, [float](($Ax + $Cx)/2), [float]($Ay + 12), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 5. M1 Q17: Rational Curve y = f(x)
# ==============================================================================
function Render-M1-Q17 {
    $outPath = Join-Path $imgDir "m1_q17_light.png"
    $w = 440; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penCurve = New-Object System.Drawing.Pen($cLine, 2.4)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Regular)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 12, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Grid -8 to 8 on both axes
    $ox = 220.0; $oy = 220.0
    $step = 21.0 # 8 * 21 = 168 pixels

    for ($i = -8; $i -le 8; $i++) {
        $x = $ox + $i * $step
        $g.DrawLine($penGrid, [float]$x, [float]($oy - 8 * $step), [float]$x, [float]($oy + 8 * $step))
        $y = $oy + $i * $step
        $g.DrawLine($penGrid, [float]($ox - 8 * $step), [float]$y, [float]($ox + 8 * $step), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]($ox - 8 * $step - 15), [float]$oy, [float]($ox + 8 * $step + 15), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]($oy + 8 * $step + 15), [float]$ox, [float]($oy - 8 * $step - 15))

    # Arrowheads
    $g.DrawLine($penAxis, [float]($ox + 8 * $step + 15), [float]$oy, [float]($ox + 8 * $step + 8), [float]($oy - 4))
    $g.DrawLine($penAxis, [float]($ox + 8 * $step + 15), [float]$oy, [float]($ox + 8 * $step + 8), [float]($oy + 4))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - 8 * $step - 15), [float]($ox - 4), [float]($oy - 8 * $step - 8))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - 8 * $step - 15), [float]($ox + 4), [float]($oy - 8 * $step - 8))

    # Ticks & labels
    $g.DrawString("O", $fontV, $brush, [float]($ox - 14), [float]($oy + 2))
    $g.DrawString("x", $fontV, $brush, [float]($ox + 8 * $step + 18), [float]($oy - 8))
    $g.DrawString("y", $fontV, $brush, [float]($ox - 8), [float]($oy - 8 * $step - 26))

    for ($i = -8; $i -le 8; $i += 2) {
        if ($i -ne 0) {
            $x = $ox + $i * $step
            $g.DrawString("$i", $fontAxis, $brush, [float]$x, [float]($oy + 4), $sfC)
            $y = $oy - $i * $step
            $g.DrawString("$i", $fontAxis, $brush, [float]($ox - 4), [float]($y - 7), $sfR)
        }
    }

    # Plot rational curve f(x) = (x - 4) / (x + 5) * 1.25 or similar with asymptote at x = -5
    # Branch 1: x in [-8, -5.2]
    $ptsL = New-Object System.Collections.Generic.List[System.Drawing.PointF]
    for ($t = -8.0; $t -le -5.2; $t += 0.05) {
        # y = 1 - 9 / (t + 5)
        $yVal = 1.0 - 9.0 / ($t + 5.0)
        if ($yVal -ge -8.5 -and $yVal -le 8.5) {
            $px = $ox + $t * $step
            $py = $oy - $yVal * $step
            $ptsL.Add((New-Object System.Drawing.PointF([float]$px, [float]$py)))
        }
    }
    if ($ptsL.Count -gt 1) {
        $g.DrawCurve($penCurve, $ptsL.ToArray())
    }

    # Branch 2: x in [-4.6, 8.5]
    $ptsR = New-Object System.Collections.Generic.List[System.Drawing.PointF]
    for ($t = -4.6; $t -le 8.5; $t += 0.05) {
        # at x=0 -> y = -0.8 ~ -1; at x=4 -> y = 0
        $yVal = 1.0 - 9.0 / ($t + 5.0)
        if ($yVal -ge -8.5 -and $yVal -le 8.5) {
            $px = $ox + $t * $step
            $py = $oy - $yVal * $step
            $ptsR.Add((New-Object System.Drawing.PointF([float]$px, [float]$py)))
        }
    }
    if ($ptsR.Count -gt 1) {
        $g.DrawCurve($penCurve, $ptsR.ToArray())
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 6. M2 Q1: Parallel Lines r and s with Transversal k
# ==============================================================================
function Render-M2-Q1 {
    $outPath = Join-Path $imgDir "m2_q1_light.png"
    $w = 380; $h = 380
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.0)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontDeg = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)

    # Vertical lines r and s
    $xR = 145.0; $xS = 265.0
    $g.DrawLine($pen, [float]$xR, 45.0, [float]$xR, 345.0)
    $g.DrawLine($pen, [float]$xS, 45.0, [float]$xS, 345.0)

    # Transversal k: from (40, 50) to (350, 330)
    $x1 = 40.0; $y1 = 50.0
    $x2 = 350.0; $y2 = 330.0
    $g.DrawLine($pen, [float]$x1, [float]$y1, [float]$x2, [float]$y2)

    # Intersections:
    # slope = 280 / 310 = 28/31
    # at xR = 145: yR = 50 + (145 - 40) * 28/31 = 50 + 105 * 0.903 = 144.8
    # at xS = 265: yS = 50 + (265 - 40) * 28/31 = 50 + 225 * 0.903 = 253.2
    $yR = 144.8; $yS = 253.2

    # Angle labels
    $deg = [char]176
    $g.DrawString("w$deg", $fontDeg, $brush, [float]($xR + 12), [float]($yR - 26))
    $g.DrawString("x$deg", $fontDeg, $brush, [float]($xR - 28), [float]($yR + 14))

    $g.DrawString("y$deg", $fontDeg, $brush, [float]($xS + 12), [float]($yS - 26))
    $g.DrawString("z$deg", $fontDeg, $brush, [float]($xS - 26), [float]($yS + 14))

    # Line labels
    $g.DrawString("k", $fontV, $brush, [float]($x1 - 18), [float]($y1 - 15))
    $g.DrawString("r", $fontV, $brush, [float]($xR - 6), 20.0)
    $g.DrawString("s", $fontV, $brush, [float]($xS - 6), 20.0)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 7. M2 Q11: Right Triangle QRS with side 23
# ==============================================================================
function Render-M2-Q11 {
    $outPath = Join-Path $imgDir "m2_q11_light.png"
    $w = 420; $h = 340
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.0)
    $thinPen = New-Object System.Drawing.Pen($cDark, 1.2)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontNum = New-Object System.Drawing.Font("Arial", 13, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 11, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Coordinates: S bottom-left, R bottom-right, Q top-right
    $Sx = 60.0; $Sy = 260.0
    $Rx = 360.0; $Ry = 260.0
    $Qx = 360.0; $Qy = 50.0

    $pts = @(
        (New-Object System.Drawing.PointF($Sx, $Sy)),
        (New-Object System.Drawing.PointF($Rx, $Ry)),
        (New-Object System.Drawing.PointF($Qx, $Qy))
    )
    $g.DrawPolygon($pen, $pts)

    # Right-angle mark at R
    $sq = 16.0
    $g.DrawRectangle($thinPen, [float]($Rx - $sq), [float]($Ry - $sq), [float]$sq, [float]$sq)

    # Labels
    $g.DrawString("S", $fontV, $brush, [float]($Sx - 20), [float]($Sy - 6))
    $g.DrawString("R", $fontV, $brush, [float]($Rx + 6), [float]($Ry - 6))
    $g.DrawString("Q", $fontV, $brush, [float]($Qx + 6), [float]($Qy - 12))
    $g.DrawString("23", $fontNum, $brush, [float](($Sx + $Rx)/2), [float]($Ry + 8), $sfC)

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, [float]($w / 2), [float]($h - 24), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 8. M2 Q12: Exponential Curve y = 5^x - 8
# ==============================================================================
function Render-M2-Q12 {
    $outPath = Join-Path $imgDir "m2_q12_light.png"
    $w = 460; $h = 460
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penCurve = New-Object System.Drawing.Pen($cLine, 2.4)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Regular)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 12, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Grid -10 to 10 on both axes
    $ox = 230.0; $oy = 230.0
    $step = 19.0 # 10 * 19 = 190 pixels

    for ($i = -10; $i -le 10; $i++) {
        $x = $ox + $i * $step
        $g.DrawLine($penGrid, [float]$x, [float]($oy - 10 * $step), [float]$x, [float]($oy + 10 * $step))
        $y = $oy + $i * $step
        $g.DrawLine($penGrid, [float]($ox - 10 * $step), [float]$y, [float]($ox + 10 * $step), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]($ox - 10 * $step - 15), [float]$oy, [float]($ox + 10 * $step + 15), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]($oy + 10 * $step + 15), [float]$ox, [float]($oy - 10 * $step - 15))

    # Arrowheads
    $g.DrawLine($penAxis, [float]($ox + 10 * $step + 15), [float]$oy, [float]($ox + 10 * $step + 8), [float]($oy - 4))
    $g.DrawLine($penAxis, [float]($ox + 10 * $step + 15), [float]$oy, [float]($ox + 10 * $step + 8), [float]($oy + 4))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - 10 * $step - 15), [float]($ox - 4), [float]($oy - 10 * $step - 8))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - 10 * $step - 15), [float]($ox + 4), [float]($oy - 10 * $step - 8))

    # Ticks & labels
    $g.DrawString("O", $fontV, $brush, [float]($ox - 14), [float]($oy + 2))
    $g.DrawString("x", $fontV, $brush, [float]($ox + 10 * $step + 18), [float]($oy - 8))
    $g.DrawString("y", $fontV, $brush, [float]($ox - 8), [float]($oy - 10 * $step - 26))

    for ($i = -10; $i -le 10; $i += 2) {
        if ($i -ne 0) {
            $x = $ox + $i * $step
            $g.DrawString("$i", $fontAxis, $brush, [float]$x, [float]($oy + 4), $sfC)
            $y = $oy - $i * $step
            $g.DrawString("$i", $fontAxis, $brush, [float]($ox - 4), [float]($y - 7), $sfR)
        }
    }

    # Plot y = 5^x - 8
    $pts = New-Object System.Collections.Generic.List[System.Drawing.PointF]
    for ($t = -10.0; $t -le 2.0; $t += 0.05) {
        $yVal = [math]::Pow(5.0, $t) - 8.0
        if ($yVal -ge -10.5 -and $yVal -le 10.5) {
            $px = $ox + $t * $step
            $py = $oy - $yVal * $step
            $pts.Add((New-Object System.Drawing.PointF([float]$px, [float]$py)))
        }
    }
    if ($pts.Count -gt 1) {
        $g.DrawCurve($penCurve, $pts.ToArray())
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# Execute All Renders
Render-M1-Q6
Render-M1-Q10
Render-M1-Q13
Render-M1-Q14
Render-M1-Q17
Render-M2-Q1
Render-M2-Q11
Render-M2-Q12
Write-Host "`nAll 8 Light-Mode Images Rendered Successfully!"
