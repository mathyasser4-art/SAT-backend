Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "sep2025_us2_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)
$cLine = [System.Drawing.Color]::FromArgb(37, 99, 235)
$cDot = [System.Drawing.Color]::FromArgb(37, 99, 235)

# ==============================================================================
# 1. M1 Q2: Parallel horizontal lines r and s cut by transversal t
# ==============================================================================
function Render-M1Q2 {
    $outPath = Join-Path $imgDir "m1_q2_light.png"
    $w = 400; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontLabel = New-Object System.Drawing.Font("Arial", 11.5, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 10.5, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    $leftX = 40.0; $rightX = 350.0
    $ry = 120.0; $sy = 220.0
    $g.DrawLine($penLine, [float]$leftX, [float]$ry, [float]$rightX, [float]$ry)
    $g.DrawLine($penLine, [float]$leftX, [float]$sy, [float]$rightX, [float]$sy)

    $t1x = 55.0;  $t1y = 320.0
    $t2x = 345.0; $t2y = 50.0
    $g.DrawLine($penLine, [float]$t1x, [float]$t1y, [float]$t2x, [float]$t2y)

    $ix_r = 270.0
    $ix_s = 162.0

    $g.DrawString("r", $fontLabel, $brushDark, [float]($rightX + 15), [float]($ry - 10))
    $g.DrawString("s", $fontLabel, $brushDark, [float]($rightX + 15), [float]($sy - 10))
    $g.DrawString("t", $fontLabel, $brushDark, [float]($t2x + 10), [float]($t2y - 15))

    $g.DrawString("107°", $fontVal, $brushDark, [float]($ix_r - 48), [float]($ry - 24))
    $g.DrawString("73°", $fontVal, $brushDark, [float]($ix_r + 15), [float]($ry - 24))

    $g.DrawString("x°", $fontVal, $brushDark, [float]($ix_s - 32), [float]($sy - 24))

    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushDark, [float]($w / 2), [float]($h - 25), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 2. M1 Q4: Scatterplot of Temperature vs Time
# ==============================================================================
function Render-M1Q4 {
    $outPath = Join-Path $imgDir "m1_q4_light.png"
    $w = 460; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penLine = New-Object System.Drawing.Pen($cLine, 2.2)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushDot = New-Object System.Drawing.SolidBrush($cDot)
    $brushWhite = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $fontAxis = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)
    $fontTitle = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far; $sfR.LineAlignment = [System.Drawing.StringAlignment]::Center

    $xMin = 0.0; $xMax = 10.0
    $yMin = 0.0; $yMax = 600.0
    $left = 75.0; $right = 410.0
    $top = 35.0; $bottom = 370.0

    function ToScreenX([float]$x) { return $left + ($x - $xMin) / ($xMax - $xMin) * ($right - $left) }
    function ToScreenY([float]$y) { return $bottom - ($y - $yMin) / ($yMax - $yMin) * ($bottom - $top) }

    # Grid
    for ($x = 0; $x -le 10; $x++) {
        $sx = ToScreenX $x
        $g.DrawLine($penGrid, [float]$sx, [float]$top, [float]$sx, [float]$bottom)
    }
    for ($y = 0; $y -le 600; $y += 75) {
        $sy = ToScreenY $y
        $g.DrawLine($penGrid, [float]$left, [float]$sy, [float]$right, [float]$sy)
    }

    # Axes
    $originX = ToScreenX 0
    $originY = ToScreenY 0
    $g.DrawLine($penAxis, [float]$originX, [float]$bottom + 10, [float]$originX, [float]$top - 15)
    $g.DrawLine($penAxis, [float]$left - 10, [float]$originY, [float]$right + 15, [float]$originY)

    $capPen = New-Object System.Drawing.Pen($cDark, 1.8)
    $capPen.CustomEndCap = New-Object System.Drawing.Drawing2D.AdjustableArrowCap(4, 5)
    $g.DrawLine($capPen, [float]$originX, [float]$top - 5, [float]$originX, [float]$top - 18)
    $g.DrawLine($capPen, [float]$right + 5, [float]$originY, [float]$right + 18, [float]$originY)

    $g.DrawString("y", $fontLabel, $brushDark, [float]($originX - 6), [float]($top - 28))
    $g.DrawString("x", $fontLabel, $brushDark, [float]($right + 20), [float]($originY - 8))
    $g.DrawString("O", $fontAxis, $brushDark, [float]($originX - 12), [float]($originY + 3))

    for ($x = 2; $x -le 10; $x += 2) {
        $sx = ToScreenX $x
        $g.DrawLine($penAxis, [float]$sx, [float]($originY - 3), [float]$sx, [float]($originY + 3))
        $g.DrawString("$x", $fontAxis, $brushDark, [float]$sx, [float]($originY + 5), $sfC)
    }
    for ($y = 75; $y -le 600; $y += 75) {
        $sy = ToScreenY $y
        $g.DrawLine($penAxis, [float]($originX - 3), [float]$sy, [float]($originX + 3), [float]$sy)
        $g.DrawString("$y", $fontAxis, $brushDark, [float]($originX - 5), [float]$sy, $sfR)
    }

    # Line of best fit
    $x1 = 0.0;  $y1 = 170.0
    $x2 = 10.0; $y2 = 580.0
    $g.DrawLine($penLine, [float](ToScreenX $x1), [float](ToScreenY $y1), [float](ToScreenX $x2), [float](ToScreenY $y2))

    # Points
    $pts = @(
        @(2.0, 265.0),
        @(4.0, 325.0),
        @(6.0, 415.0),
        @(7.0, 465.0),
        @(9.0, 520.0)
    )
    foreach ($p in $pts) {
        $px = ToScreenX $p[0]
        $py = ToScreenY $p[1]
        $g.FillEllipse($brushDot, [float]($px - 5), [float]($py - 5), 10, 10)
        $g.FillEllipse($brushWhite, [float]($px - 2.5), [float]($py - 2.5), 5, 5)
    }

    # Axis titles
    $g.DrawString("Time (hours)", $fontTitle, $brushDark, [float](($left + $right)/2), [float]($bottom + 26), $sfC)
    
    # Vertical title "Temperature (°F)"
    $g.TranslateTransform(20, [float](($top + $bottom)/2))
    $g.RotateTransform(-90)
    $g.DrawString("Temperature (°F)", $fontTitle, $brushDark, 0, 0, $sfC)
    $g.ResetTransform()

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 3. M1 Q5: Bank account balance vs Time
# ==============================================================================
function Render-M1Q5 {
    $outPath = Join-Path $imgDir "m1_q5_light.png"
    $w = 460; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penLine = New-Object System.Drawing.Pen($cLine, 2.4)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)
    $fontTitle = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far; $sfR.LineAlignment = [System.Drawing.StringAlignment]::Center

    $xMin = 0.0; $xMax = 10.0
    $yMin = 0.0; $yMax = 80.0
    $left = 75.0; $right = 410.0
    $top = 35.0; $bottom = 370.0

    function ToScreenX([float]$x) { return $left + ($x - $xMin) / ($xMax - $xMin) * ($right - $left) }
    function ToScreenY([float]$y) { return $bottom - ($y - $yMin) / ($yMax - $yMin) * ($bottom - $top) }

    # Grid
    for ($x = 0; $x -le 10; $x++) {
        $sx = ToScreenX $x
        $g.DrawLine($penGrid, [float]$sx, [float]$top, [float]$sx, [float]$bottom)
    }
    for ($y = 0; $y -le 80; $y += 5) {
        $sy = ToScreenY $y
        $g.DrawLine($penGrid, [float]$left, [float]$sy, [float]$right, [float]$sy)
    }

    # Axes
    $originX = ToScreenX 0
    $originY = ToScreenY 0
    $g.DrawLine($penAxis, [float]$originX, [float]$bottom + 10, [float]$originX, [float]$top - 15)
    $g.DrawLine($penAxis, [float]$left - 10, [float]$originY, [float]$right + 15, [float]$originY)

    $capPen = New-Object System.Drawing.Pen($cDark, 1.8)
    $capPen.CustomEndCap = New-Object System.Drawing.Drawing2D.AdjustableArrowCap(4, 5)
    $g.DrawLine($capPen, [float]$originX, [float]$top - 5, [float]$originX, [float]$top - 18)
    $g.DrawLine($capPen, [float]$right + 5, [float]$originY, [float]$right + 18, [float]$originY)

    $g.DrawString("y", $fontLabel, $brushDark, [float]($originX - 6), [float]($top - 28))
    $g.DrawString("x", $fontLabel, $brushDark, [float]($right + 20), [float]($originY - 8))
    $g.DrawString("O", $fontAxis, $brushDark, [float]($originX - 12), [float]($originY + 3))

    for ($x = 2; $x -le 10; $x += 2) {
        $sx = ToScreenX $x
        $g.DrawLine($penAxis, [float]$sx, [float]($originY - 3), [float]$sx, [float]($originY + 3))
        $g.DrawString("$x", $fontAxis, $brushDark, [float]$sx, [float]($originY + 5), $sfC)
    }
    for ($y = 10; $y -le 80; $y += 10) {
        $sy = ToScreenY $y
        $g.DrawLine($penAxis, [float]($originX - 3), [float]$sy, [float]($originX + 3), [float]$sy)
        $g.DrawString("$y", $fontAxis, $brushDark, [float]($originX - 5), [float]$sy, $sfR)
    }

    # Line from (0, 30) to (10, 80)
    $g.DrawLine($penLine, [float](ToScreenX 0), [float](ToScreenY 30), [float](ToScreenX 10), [float](ToScreenY 80))

    # Axis titles
    $g.DrawString("Time since initial deposit (months)", $fontTitle, $brushDark, [float](($left + $right)/2), [float]($bottom + 26), $sfC)
    
    # Vertical title "Bank account balance (dollars)"
    $g.TranslateTransform(20, [float](($top + $bottom)/2))
    $g.RotateTransform(-90)
    $g.DrawString("Bank account balance (dollars)", $fontTitle, $brushDark, 0, 0, $sfC)
    $g.ResetTransform()

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 4. M1 Q10: Cubic polynomial curve with roots -3, 2, 5
# ==============================================================================
function Render-M1Q10 {
    $outPath = Join-Path $imgDir "m1_q10_light.png"
    $w = 440; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penCurve = New-Object System.Drawing.Pen($cLine, 2.4)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far; $sfR.LineAlignment = [System.Drawing.StringAlignment]::Center

    $xMin = -8.0; $xMax = 8.0
    $yMin = -8.0; $yMax = 8.0
    $left = 40.0; $right = 410.0
    $top = 30.0; $bottom = 400.0

    function ToScreenX([float]$x) { return $left + ($x - $xMin) / ($xMax - $xMin) * ($right - $left) }
    function ToScreenY([float]$y) { return $bottom - ($y - $yMin) / ($yMax - $yMin) * ($bottom - $top) }

    # Grid
    for ($x = -8; $x -le 8; $x++) {
        $sx = ToScreenX $x
        $g.DrawLine($penGrid, [float]$sx, [float]$top, [float]$sx, [float]$bottom)
    }
    for ($y = -8; $y -le 8; $y++) {
        $sy = ToScreenY $y
        $g.DrawLine($penGrid, [float]$left, [float]$sy, [float]$right, [float]$sy)
    }

    # Axes
    $originX = ToScreenX 0
    $originY = ToScreenY 0
    $g.DrawLine($penAxis, [float]$originX, [float]$bottom + 10, [float]$originX, [float]$top - 15)
    $g.DrawLine($penAxis, [float]$left - 15, [float]$originY, [float]$right + 15, [float]$originY)

    $capPen = New-Object System.Drawing.Pen($cDark, 1.8)
    $capPen.CustomEndCap = New-Object System.Drawing.Drawing2D.AdjustableArrowCap(4, 5)
    $g.DrawLine($capPen, [float]$originX, [float]$top - 5, [float]$originX, [float]$top - 18)
    $g.DrawLine($capPen, [float]$right + 5, [float]$originY, [float]$right + 18, [float]$originY)

    $g.DrawString("y", $fontLabel, $brushDark, [float]($originX - 6), [float]($top - 28))
    $g.DrawString("x", $fontLabel, $brushDark, [float]($right + 20), [float]($originY - 8))
    $g.DrawString("O", $fontAxis, $brushDark, [float]($originX - 12), [float]($originY + 3))

    for ($x = -8; $x -le 8; $x += 2) {
        if ($x -ne 0) {
            $sx = ToScreenX $x
            $g.DrawLine($penAxis, [float]$sx, [float]($originY - 3), [float]$sx, [float]($originY + 3))
            $g.DrawString("$x", $fontAxis, $brushDark, [float]$sx, [float]($originY + 5), $sfC)
        }
    }
    for ($y = -8; $y -le 8; $y += 2) {
        if ($y -ne 0) {
            $sy = ToScreenY $y
            $g.DrawLine($penAxis, [float]($originX - 3), [float]$sy, [float]($originX + 3), [float]$sy)
            $g.DrawString("$y", $fontAxis, $brushDark, [float]($originX - 5), [float]$sy, $sfR)
        }
    }

    # Cubic curve: y = 0.1333 * (x + 3) * (x - 2) * (x - 5)
    $curvePts = New-Object System.Collections.Generic.List[System.Drawing.PointF]
    for ($x = -4.0; $x -le 6.6; $x += 0.05) {
        $y = (4.0 / 30.0) * ($x + 3.0) * ($x - 2.0) * ($x - 5.0)
        if ($y -ge -8.2 -and $y -le 8.2) {
            $curvePts.Add((New-Object System.Drawing.PointF((ToScreenX $x), (ToScreenY $y))))
        }
    }
    $g.DrawLines($penCurve, $curvePts.ToArray())

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 5. M1 Q12: Right triangle JKL with hypotenuse 59 and angle y
# ==============================================================================
function Render-M1Q12 {
    $outPath = Join-Path $imgDir "m1_q12_light.png"
    $w = 380; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penTri = New-Object System.Drawing.Pen($cDark, 2.2)
    $penBox = New-Object System.Drawing.Pen($cDark, 1.5)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontLabel = New-Object System.Drawing.Font("Arial", 11.5, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    $jx = 70.0;  $jy = 50.0
    $kx = 70.0;  $ky = 275.0
    $lx = 335.0; $ly = 275.0

    $g.DrawLine($penTri, [float]$jx, [float]$jy, [float]$kx, [float]$ky)
    $g.DrawLine($penTri, [float]$kx, [float]$ky, [float]$lx, [float]$ly)
    $g.DrawLine($penTri, [float]$lx, [float]$ly, [float]$jx, [float]$jy)

    $sq = 18.0
    $g.DrawLine($penBox, [float]$kx, [float]($ky - $sq), [float]($kx + $sq), [float]($ky - $sq))
    $g.DrawLine($penBox, [float]($kx + $sq), [float]($ky - $sq), [float]($kx + $sq), [float]$ky)

    $g.DrawString("J", $fontLabel, $brushDark, [float]($jx - 15), [float]($jy - 22))
    $g.DrawString("K", $fontLabel, $brushDark, [float]($kx - 20), [float]($ky + 2))
    $g.DrawString("L", $fontLabel, $brushDark, [float]($lx + 5), [float]($ly + 2))

    $g.DrawString("59", $fontVal, $brushDark, [float](($jx + $lx)/2 + 5), [float](($jy + $ly)/2 - 20))
    $g.DrawString("y°", $fontVal, $brushDark, [float]($lx - 48), [float]($ly - 24))

    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushDark, [float]($w / 2), [float]($h - 25), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

Render-M1Q2
Render-M1Q4
Render-M1Q5
Render-M1Q10
Render-M1Q12
