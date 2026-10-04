Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "march2026_int1_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)
$cLine = [System.Drawing.Color]::FromArgb(37, 99, 235)
$cPoint = [System.Drawing.Color]::FromArgb(15, 23, 42)

# ==============================================================================
# 1. M1 Q1: Candle Weight vs Time (Line Graph)
# ==============================================================================
function Render-M1-Q1 {
    $outPath = Join-Path $imgDir "m1_q1_light.png"
    $w = 500; $h = 460
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 90.0; $right = 440.0; $top = 45.0; $bottom = 390.0
    $pW = $right - $left; $pH = $bottom - $top

    function MX($x) { return $left + ($x / 14.0) * $pW }
    function MY($y) { return $bottom - ($y / 14.0) * $pH }

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    for ($i = 0; $i -le 14; $i++) {
        $gx = MX $i
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
        $gy = MY $i
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    # X axis
    $g.DrawLine($penAxis, [float]$left, [float]$bottom, [float]($right + 18), [float]$bottom)
    # Y axis
    $g.DrawLine($penAxis, [float]$left, [float]$bottom, [float]$left, [float]($top - 18))

    $fontLabel = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Regular)
    $fontAxis = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
    $fontMath = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Italic)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Ticks & numbers
    for ($i = 2; $i -le 14; $i += 2) {
        $gx = MX $i
        $g.DrawString($i.ToString(), $fontLabel, $brushDark, [float]$gx, [float]($bottom + 5), $sfC)
        $gy = MY $i
        $g.DrawString($i.ToString(), $fontLabel, $brushDark, [float]($left - 6), [float]($gy - 7), $sfR)
    }
    $g.DrawString("O", $fontMath, $brushDark, [float]($left - 15), [float]($bottom + 2))

    # Axis variable labels
    $g.DrawString("x", $fontMath, $brushDark, [float]($right + 22), [float]($bottom - 10))
    $g.DrawString("y", $fontMath, $brushDark, [float]($left - 8), [float]($top - 38))

    # Axis titles
    $g.DrawString("Time (hours)", $fontAxis, $brushDark, [float](($left + $right)/2), [float]($bottom + 26), $sfC)

    # Rotated Y-axis title
    $state = $g.Save()
    $g.TranslateTransform(32, (($top + $bottom)/2))
    $g.RotateTransform(-90)
    $g.DrawString("Weight (ounces)", $fontAxis, $brushDark, 0, 0, $sfC)
    $g.Restore($state)

    # Line: y = 13 - 0.25x from x=0 to x=14
    $penLine = New-Object System.Drawing.Pen($cLine, 2.5)
    $x1 = MX 0.0; $y1 = MY 13.0
    $x2 = MX 14.0; $y2 = MY 9.5
    $g.DrawLine($penLine, [float]$x1, [float]$y1, [float]$x2, [float]$y2)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 2. M1 Q5: Table (x, y)
# ==============================================================================
function Render-M1-Q5 {
    $outPath = Join-Path $imgDir "m1_q5_light.png"
    $w = 200; $h = 240
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penOuter = New-Object System.Drawing.Pen($cDark, 2.0)
    $penInner = New-Object System.Drawing.Pen($cDark, 1.2)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushHdrBg = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(241, 245, 249))

    $tLeft = 30.0; $tTop = 25.0; $tW = 140.0; $tH = 190.0
    $colW = $tW / 2.0
    $rowH = $tH / 4.0

    # Header background
    $g.FillRectangle($brushHdrBg, [float]$tLeft, [float]$tTop, [float]$tW, [float]$rowH)
    # Outer border
    $g.DrawRectangle($penOuter, [float]$tLeft, [float]$tTop, [float]$tW, [float]$tH)

    # Vertical divider
    $g.DrawLine($penInner, [float]($tLeft + $colW), [float]$tTop, [float]($tLeft + $colW), [float]($tTop + $tH))

    # Horizontal dividers
    for ($r = 1; $r -le 3; $r++) {
        $ry = $tTop + $r * $rowH
        $g.DrawLine($penInner, [float]$tLeft, [float]$ry, [float]($tLeft + $tW), [float]$ry)
    }

    $fontMath = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontNum = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Regular)
    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = [System.Drawing.StringAlignment]::Center
    $sf.LineAlignment = [System.Drawing.StringAlignment]::Center

    # Header labels
    $g.DrawString("x", $fontMath, $brushDark, [float]($tLeft + $colW/2), [float]($tTop + $rowH/2), $sf)
    $g.DrawString("y", $fontMath, $brushDark, [float]($tLeft + $colW*1.5), [float]($tTop + $rowH/2), $sf)

    # Row 1: 0, 8
    $g.DrawString("0", $fontNum, $brushDark, [float]($tLeft + $colW/2), [float]($tTop + $rowH*1.5), $sf)
    $g.DrawString("8", $fontNum, $brushDark, [float]($tLeft + $colW*1.5), [float]($tTop + $rowH*1.5), $sf)

    # Row 2: 1, 9
    $g.DrawString("1", $fontNum, $brushDark, [float]($tLeft + $colW/2), [float]($tTop + $rowH*2.5), $sf)
    $g.DrawString("9", $fontNum, $brushDark, [float]($tLeft + $colW*1.5), [float]($tTop + $rowH*2.5), $sf)

    # Row 3: 2, 10
    $g.DrawString("2", $fontNum, $brushDark, [float]($tLeft + $colW/2), [float]($tTop + $rowH*3.5), $sf)
    $g.DrawString("10", $fontNum, $brushDark, [float]($tLeft + $colW*1.5), [float]($tTop + $rowH*3.5), $sf)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 3. M1 Q8: Scatterplot with Line of Best Fit (d vs t)
# ==============================================================================
function Render-M1-Q8 {
    $outPath = Join-Path $imgDir "m1_q8_light.png"
    $w = 520; $h = 420
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 70.0; $right = 470.0; $top = 55.0; $bottom = 350.0
    $pW = $right - $left; $pH = $bottom - $top

    # t in [225, 275], d in [390, 510]
    function MX($t) { return $left + (($t - 225.0) / 50.0) * $pW }
    function MY($d) { return $bottom - (($d - 390.0) / 120.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    for ($ti = 230; $ti -le 270; $ti += 10) {
        $gx = MX $ti
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
    }
    for ($di = 400; $di -le 500; $di += 20) {
        $gy = MY $di
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Bounding Box / Axes
    $penBox = New-Object System.Drawing.Pen($cDark, 1.8)
    $g.DrawRectangle($penBox, [float]$left, [float]$top, [float]$pW, [float]$pH)

    $fontLabel = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Regular)
    $fontTitle = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
    $fontMath = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Italic)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Title
    $g.DrawString("Scatterplot with Line of Best Fit", $fontTitle, $brushDark, [float](($left + $right)/2), 18, $sfC)

    # Ticks & labels
    for ($ti = 230; $ti -le 270; $ti += 10) {
        $gx = MX $ti
        $g.DrawString($ti.ToString(), $fontLabel, $brushDark, [float]$gx, [float]($bottom + 6), $sfC)
    }
    for ($di = 400; $di -le 500; $di += 20) {
        $gy = MY $di
        $g.DrawString($di.ToString(), $fontLabel, $brushDark, [float]($left - 6), [float]($gy - 7), $sfR)
    }

    # Axis titles
    $g.DrawString("t", $fontMath, $brushDark, [float](($left + $right)/2), [float]($bottom + 28), $sfC)
    $g.DrawString("d", $fontMath, $brushDark, [float]($left - 42), [float](($top + $bottom)/2 - 7))

    # Line of best fit: d = -60.1 + 2.02 t
    # at t=225: d = -60.1 + 454.5 = 394.4
    # at t=275: d = -60.1 + 555.5 = 495.4
    $penLine = New-Object System.Drawing.Pen($cLine, 2.4)
    $lx1 = MX 225.0; $ly1 = MY 394.4
    $lx2 = MX 275.0; $ly2 = MY 495.4
    $g.DrawLine($penLine, [float]$lx1, [float]$ly1, [float]$lx2, [float]$ly2)

    # Points: (230, 400), (235, 417), (240, 423), (245, 439), (250, 442), (255, 457), (260, 461), (265, 478), (270, 483)
    $pts = @(
        @(230.0, 400.0),
        @(235.0, 417.0),
        @(240.0, 423.0),
        @(245.0, 439.0),
        @(250.0, 442.0),
        @(255.0, 457.0),
        @(260.0, 461.0),
        @(265.0, 478.0),
        @(270.0, 483.0)
    )
    $brushPt = New-Object System.Drawing.SolidBrush($cDark)
    $rPt = 4.5
    foreach ($p in $pts) {
        $px = MX $p[0]
        $py = MY $p[1]
        $g.FillEllipse($brushPt, [float]($px - $rPt), [float]($py - $rPt), [float]($rPt * 2), [float]($rPt * 2))
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 4. M2 Q22: Scatterplot with Line of Best Fit (y vs x)
# ==============================================================================
function Render-M2-Q22 {
    $outPath = Join-Path $imgDir "m2_q22_light.png"
    $w = 460; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 60.0; $right = 410.0; $top = 40.0; $bottom = 370.0
    $pW = $right - $left; $pH = $bottom - $top

    function MX($x) { return $left + ($x / 14.0) * $pW }
    function MY($y) { return $bottom - ($y / 14.0) * $pH }

    # Grid (every 1 unit)
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    for ($i = 0; $i -le 14; $i++) {
        $gx = MX $i
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
        $gy = MY $i
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float]$left, [float]$bottom, [float]($right + 18), [float]$bottom)
    $g.DrawLine($penAxis, [float]$left, [float]$bottom, [float]$left, [float]($top - 18))

    $fontLabel = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Regular)
    $fontMath = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Italic)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Ticks & labels
    for ($i = 2; $i -le 14; $i += 2) {
        $gx = MX $i
        $g.DrawString($i.ToString(), $fontLabel, $brushDark, [float]$gx, [float]($bottom + 5), $sfC)
        $gy = MY $i
        $g.DrawString($i.ToString(), $fontLabel, $brushDark, [float]($left - 6), [float]($gy - 7), $sfR)
    }
    $g.DrawString("O", $fontMath, $brushDark, [float]($left - 15), [float]($bottom + 2))

    # Axis variable labels
    $g.DrawString("x", $fontMath, $brushDark, [float]($right + 22), [float]($bottom - 10))
    $g.DrawString("y", $fontMath, $brushDark, [float]($left - 7), [float]($top - 35))

    # Line of best fit: y = 9.5 - 0.4x from x=0 to x=14
    $penLine = New-Object System.Drawing.Pen($cLine, 2.5)
    $lx1 = MX 0.0; $ly1 = MY 9.5
    $lx2 = MX 14.0; $ly2 = MY (9.5 - 0.4 * 14.0)
    $g.DrawLine($penLine, [float]$lx1, [float]$ly1, [float]$lx2, [float]$ly2)

    # Data points: (1, 10), (1, 8), (3, 8), (4, 7), (6, 11), (6, 7), (7, 4), (9, 5), (11, 7), (13, 3)
    $pts = @(
        @(1.0, 10.0),
        @(1.0, 8.0),
        @(3.0, 8.0),
        @(4.0, 7.0),
        @(6.0, 11.0),
        @(6.0, 7.0),
        @(7.0, 4.0),
        @(9.0, 5.0),
        @(11.0, 7.0),
        @(13.0, 3.0)
    )
    $brushPt = New-Object System.Drawing.SolidBrush($cDark)
    $rPt = 4.5
    foreach ($p in $pts) {
        $px = MX $p[0]
        $py = MY $p[1]
        $g.FillEllipse($brushPt, [float]($px - $rPt), [float]($py - $rPt), [float]($rPt * 2), [float]($rPt * 2))
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# Run all renders
Render-M1-Q1
Render-M1-Q5
Render-M1-Q8
Render-M2-Q22
Write-Host "All light mode images created successfully!"
