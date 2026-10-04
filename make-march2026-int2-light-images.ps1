Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "march2026_int2_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)
$cLine = [System.Drawing.Color]::FromArgb(37, 99, 235)
$cShade = [System.Drawing.Color]::FromArgb(50, 59, 130, 246)

# ==============================================================================
# 1. M1 Q1: Right Triangle FGH (60 deg, hypotenuse 68)
# ==============================================================================
function Render-M1-Q1 {
    $outPath = Join-Path $imgDir "m1_q1_light.png"
    $w = 480; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.2)
    $thinPen = New-Object System.Drawing.Pen($cDark, 1.4)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontSub = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
    $fontNum = New-Object System.Drawing.Font("Times New Roman", 16, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 11, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Coordinates: G bottom-left, H bottom-right, F top-right
    $Gx = 70.0; $Gy = 270.0
    $Hx = 390.0; $Hy = 270.0
    $Fx = 390.0; $Fy = 50.0

    # Draw Triangle
    $pts = @(
        (New-Object System.Drawing.PointF($Gx, $Gy)),
        (New-Object System.Drawing.PointF($Hx, $Hy)),
        (New-Object System.Drawing.PointF($Fx, $Fy))
    )
    $g.DrawPolygon($pen, $pts)

    # Right angle square at H
    $sq = 16.0
    $g.DrawRectangle($thinPen, [float]($Hx - $sq), [float]($Hy - $sq), [float]$sq, [float]$sq)

    # Angle arc at G (60 deg)
    # G to H is 0 deg. G to F: dy = 220, dx = 320 -> angle ~34.5 deg visually
    $arcR = 40.0
    $g.DrawArc($thinPen, [float]($Gx - $arcR), [float]($Gy - $arcR), [float]($arcR*2), [float]($arcR*2), -34.5, 34.5)
    $deg = [char]176
    $g.DrawString("60$deg", $fontSub, $brush, [float]($Gx + 48), [float]($Gy - 20))

    # Hypotenuse label 68
    $g.DrawString("68", $fontNum, $brush, [float](($Gx + $Fx)/2 - 32), [float](($Gy + $Fy)/2 - 24))

    # Vertices
    $g.DrawString("G", $fontV, $brush, [float]($Gx - 20), [float]($Gy - 6))
    $g.DrawString("H", $fontV, $brush, [float]($Hx + 4), [float]($Hy - 6))
    $g.DrawString("F", $fontV, $brush, [float]($Fx + 4), [float]($Fy - 14))

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, [float]($w / 2), [float]($h - 30), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 2. M1 Q14: Right Triangle ABC (AB = 22, AC = 41)
# ==============================================================================
function Render-M1-Q14 {
    $outPath = Join-Path $imgDir "m1_q14_light.png"
    $w = 480; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.2)
    $thinPen = New-Object System.Drawing.Pen($cDark, 1.4)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontNum = New-Object System.Drawing.Font("Times New Roman", 16, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 11, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Coordinates: C bottom-left, B bottom-right, A top-right
    $Cx = 70.0; $Cy = 270.0
    $Bx = 400.0; $By = 270.0
    $Ax = 400.0; $Ay = 50.0

    # Draw Triangle
    $pts = @(
        (New-Object System.Drawing.PointF($Cx, $Cy)),
        (New-Object System.Drawing.PointF($Bx, $By)),
        (New-Object System.Drawing.PointF($Ax, $Ay))
    )
    $g.DrawPolygon($pen, $pts)

    # Right angle square at B
    $sq = 16.0
    $g.DrawRectangle($thinPen, [float]($Bx - $sq), [float]($By - $sq), [float]$sq, [float]$sq)

    # Side labels
    $g.DrawString("41", $fontNum, $brush, [float](($Cx + $Ax)/2 - 32), [float](($Cy + $Ay)/2 - 24))
    $g.DrawString("22", $fontNum, $brush, [float]($Bx + 8), [float](($Ay + $By)/2 - 10))

    # Vertices
    $g.DrawString("C", $fontV, $brush, [float]($Cx - 20), [float]($Cy - 6))
    $g.DrawString("B", $fontV, $brush, [float]($Bx + 4), [float]($By + 4))
    $g.DrawString("A", $fontV, $brush, [float]($Ax + 4), [float]($Ay - 14))

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, [float]($w / 2), [float]($h - 30), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 3. M1 Q21: Parallel Lines m || n with Intersecting Transversals
# ==============================================================================
function Render-M1-Q21 {
    $outPath = Join-Path $imgDir "m1_q21_light.png"
    $w = 460; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.0)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 14, [System.Drawing.FontStyle]::Italic)
    $fontLine = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 11, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Top line m at y = 100, bottom line n at y = 240
    $yM = 100.0; $yN = 240.0
    $g.DrawLine($pen, 40.0, [float]$yM, 390.0, [float]$yM)
    $g.DrawLine($pen, 40.0, [float]$yN, 390.0, [float]$yN)

    # Transversal AE: from (70, 310) up-right through A(160, 240), B(215, 170), E(270, 100) to (320, 35)
    $g.DrawLine($pen, 70.0, 310.0, 320.0, 35.0)

    # Transversal DC: from (95, 35) down-right through D(170, 100), B(215, 170), C(260, 240) to (335, 310)
    $g.DrawLine($pen, 95.0, 35.0, 335.0, 310.0)

    # Line labels
    $g.DrawString("m", $fontLine, $brush, 402.0, [float]($yM - 12))
    $g.DrawString("n", $fontLine, $brush, 402.0, [float]($yN - 12))

    # Point labels
    $g.DrawString("D", $fontV, $brush, 148.0, [float]($yM - 24))
    $g.DrawString("E", $fontV, $brush, 282.0, [float]($yM - 24))
    $g.DrawString("B", $fontV, $brush, 226.0, 162.0)
    $g.DrawString("A", $fontV, $brush, 140.0, [float]($yN + 4))
    $g.DrawString("C", $fontV, $brush, 252.0, [float]($yN + 4))

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, [float]($w / 2), [float]($h - 22), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 4. M2 Q2: Sunspots vs Months (Line Graph)
# ==============================================================================
function Render-M2-Q2 {
    $outPath = Join-Path $imgDir "m2_q2_light.png"
    $w = 520; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 110.0; $right = 460.0; $top = 40.0; $bottom = 370.0
    $pW = $right - $left; $pH = $bottom - $top

    function MX($x) { return $left + ($x / 30.0) * $pW }
    function MY($y) { return $bottom - ($y / 120.0) * $pH }

    # Grid lines
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    for ($xi = 5; $xi -le 30; $xi += 5) {
        $gx = MX $xi
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
    }
    for ($yi = 20; $yi -le 120; $yi += 20) {
        $gy = MY $yi
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float]$left, [float]$bottom, [float]($right + 18), [float]$bottom)
    $g.DrawLine($penAxis, [float]$left, [float]$bottom, [float]$left, [float]($top - 18))

    $fontLabel = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Regular)
    $fontAxis = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
    $fontMath = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Italic)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Ticks & labels
    for ($xi = 5; $xi -le 30; $xi += 5) {
        $gx = MX $xi
        $g.DrawString($xi.ToString(), $fontLabel, $brushDark, [float]$gx, [float]($bottom + 5), $sfC)
    }
    for ($yi = 20; $yi -le 120; $yi += 20) {
        $gy = MY $yi
        $g.DrawString($yi.ToString(), $fontLabel, $brushDark, [float]($left - 6), [float]($gy - 7), $sfR)
    }
    $g.DrawString("O", $fontMath, $brushDark, [float]($left - 15), [float]($bottom + 2))

    # Axis variable labels
    $g.DrawString("x", $fontMath, $brushDark, [float]($right + 22), [float]($bottom - 10))
    $g.DrawString("y", $fontMath, $brushDark, [float]($left - 8), [float]($top - 38))

    # Axis titles
    $g.DrawString("Months since December 2013", $fontAxis, $brushDark, [float](($left + $right)/2), [float]($bottom + 26), $sfC)

    # Rotated Y-axis title
    $state = $g.Save()
    $g.TranslateTransform(35, (($top + $bottom)/2))
    $g.RotateTransform(-90)
    $g.DrawString("Monthly mean number of sunspots", $fontAxis, $brushDark, 0, 0, $sfC)
    $g.Restore($state)

    # Line: from (0, 120) to (30, 50)
    $penLine = New-Object System.Drawing.Pen($cLine, 2.5)
    $lx1 = MX 0.0; $ly1 = MY 120.0
    $lx2 = MX 30.0; $ly2 = MY 50.0
    $g.DrawLine($penLine, [float]$lx1, [float]$ly1, [float]$lx2, [float]$ly2)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 5. M2 Q4: Inequality y < 4x + 1
# ==============================================================================
function Render-M2-Q4 {
    $outPath = Join-Path $imgDir "m2_q4_light.png"
    $w = 460; $h = 460
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    # x in [-4, 8], y in [-2, 16]
    $left = 50.0; $right = 410.0; $top = 40.0; $bottom = 410.0
    $pW = $right - $left; $pH = $bottom - $top

    function MX($x) { return $left + (($x - (-4.0)) / 12.0) * $pW }
    function MY($y) { return $bottom - (($y - (-2.0)) / 18.0) * $pH }

    # Grid lines (every 1 unit)
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    for ($xi = -4; $xi -le 8; $xi++) {
        $gx = MX $xi
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
    }
    for ($yi = -2; $yi -le 16; $yi++) {
        $gy = MY $yi
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Shaded region: y < 4x + 1
    # Line boundary: at y = -2 -> x = -0.75; at y = 16 -> x = 3.75
    # Region to the right/below: polygon (MX -0.75, MY -2) -> (MX 3.75, MY 16) -> (MX 8, MY 16) -> (MX 8, MY -2)
    $poly = @(
        (New-Object System.Drawing.PointF((MX -0.75), (MY -2.0))),
        (New-Object System.Drawing.PointF((MX 3.75), (MY 16.0))),
        (New-Object System.Drawing.PointF((MX 8.0), (MY 16.0))),
        (New-Object System.Drawing.PointF((MX 8.0), (MY -2.0)))
    )
    $brushShade = New-Object System.Drawing.SolidBrush($cShade)
    $g.FillPolygon($brushShade, $poly)

    # Dashed line: y = 4x + 1
    $penDashed = New-Object System.Drawing.Pen($cLine, 2.4)
    $penDashed.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $g.DrawLine($penDashed, [float](MX -0.75), [float](MY -2.0), [float](MX 3.75), [float](MY 16.0))

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $y0 = MY 0.0
    $x0 = MX 0.0
    # X-axis
    $g.DrawLine($penAxis, [float]$left, [float]$y0, [float]($right + 18), [float]$y0)
    # Y-axis
    $g.DrawLine($penAxis, [float]$x0, [float]$bottom, [float]$x0, [float]($top - 18))

    $fontLabel = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Regular)
    $fontMath = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Italic)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Ticks & labels
    $xTicks = @(-4, 4, 8)
    foreach ($xt in $xTicks) {
        $gx = MX $xt
        $g.DrawString($xt.ToString(), $fontLabel, $brushDark, [float]$gx, [float]($y0 + 5), $sfC)
    }
    $yTicks = @(4, 8, 12)
    foreach ($yt in $yTicks) {
        $gy = MY $yt
        $g.DrawString($yt.ToString(), $fontLabel, $brushDark, [float]($x0 - 6), [float]($gy - 7), $sfR)
    }
    $g.DrawString("O", $fontMath, $brushDark, [float]($x0 - 15), [float]($y0 + 2))

    # Axis variable labels
    $g.DrawString("x", $fontMath, $brushDark, [float]($right + 22), [float]($y0 - 10))
    $g.DrawString("y", $fontMath, $brushDark, [float]($x0 - 7), [float]($top - 38))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 6. M2 Q6: Triangle ACE with Parallel Segment BD
# ==============================================================================
function Render-M2-Q6 {
    $outPath = Join-Path $imgDir "m2_q6_light.png"
    $w = 380; $h = 380
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.2)
    $thinPen = New-Object System.Drawing.Pen($cDark, 1.4)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)

    # Right triangle ACE: E bottom-right, A bottom-left, C top-right
    $Ex = 290.0; $Ey = 310.0
    $Ax = 90.0;  $Ay = 310.0
    $Cx = 290.0; $Cy = 50.0

    # Draw main triangle ACE
    $pts = @(
        (New-Object System.Drawing.PointF($Ax, $Ay)),
        (New-Object System.Drawing.PointF($Ex, $Ey)),
        (New-Object System.Drawing.PointF($Cx, $Cy))
    )
    $g.DrawPolygon($pen, $pts)

    # Segment BD parallel to AE at y = 190 (midway)
    $Dy = 190.0
    $Dx = 290.0
    # On AC: line from (90, 310) to (290, 50). Slope: dx/dy = (290 - 90)/(50 - 310) = 200/(-260) = -20/26
    # At y = 190: dy = 190 - 310 = -120 -> dx = -120 * (-20/26) = +92.3 -> Bx = 90 + 92.3 = 182.3
    $Bx = 90.0 + (310.0 - $Dy) * (200.0 / 260.0)
    $g.DrawLine($pen, [float]$Bx, [float]$Dy, [float]$Dx, [float]$Dy)

    # Right angle squares at E and D
    $sq = 15.0
    $g.DrawRectangle($thinPen, [float]($Ex - $sq), [float]($Ey - $sq), [float]$sq, [float]$sq)
    $g.DrawRectangle($thinPen, [float]($Dx - $sq), [float]($Dy - $sq), [float]$sq, [float]$sq)

    # Vertices
    $g.DrawString("C", $fontV, $brush, [float]($Cx - 6), [float]($Cy - 26))
    $g.DrawString("D", $fontV, $brush, [float]($Dx + 6), [float]($Dy - 10))
    $g.DrawString("E", $fontV, $brush, [float]($Ex + 4), [float]($Ey + 4))
    $g.DrawString("B", $fontV, $brush, [float]($Bx - 22), [float]($Dy - 10))
    $g.DrawString("A", $fontV, $brush, [float]($Ax - 20), [float]($Ay + 4))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 7. M2 Q10: Parabola y = 6x^2 + 12x - 3
# ==============================================================================
function Render-M2-Q10 {
    $outPath = Join-Path $imgDir "m2_q10_light.png"
    $w = 460; $h = 480
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    # x in [-6, 5], y in [-11, 5]
    $left = 60.0; $right = 410.0; $top = 40.0; $bottom = 430.0
    $pW = $right - $left; $pH = $bottom - $top

    function MX($x) { return $left + (($x - (-6.0)) / 11.0) * $pW }
    function MY($y) { return $bottom - (($y - (-11.0)) / 16.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    for ($xi = -6; $xi -le 5; $xi++) {
        $gx = MX $xi
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
    }
    for ($yi = -11; $yi -le 5; $yi++) {
        $gy = MY $yi
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $y0 = MY 0.0
    $x0 = MX 0.0
    # X axis
    $g.DrawLine($penAxis, [float]$left, [float]$y0, [float]($right + 18), [float]$y0)
    # Y axis
    $g.DrawLine($penAxis, [float]$x0, [float]$bottom, [float]$x0, [float]($top - 18))

    $fontLabel = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Regular)
    $fontMath = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Italic)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Ticks & labels
    for ($xi = -6; $xi -le 4; $xi += 2) {
        if ($xi -ne 0) {
            $gx = MX $xi
            $g.DrawString($xi.ToString(), $fontLabel, $brushDark, [float]$gx, [float]($y0 + 5), $sfC)
        }
    }
    for ($yi = -10; $yi -le 4; $yi += 2) {
        if ($yi -ne 0) {
            $gy = MY $yi
            if ($yi -lt 0) {
                $g.DrawString($yi.ToString(), $fontLabel, $brushDark, [float]($x0 + 6), [float]($gy - 7))
            } else {
                $g.DrawString($yi.ToString(), $fontLabel, $brushDark, [float]($x0 - 6), [float]($gy - 7), $sfR)
            }
        }
    }
    $g.DrawString("O", $fontMath, $brushDark, [float]($x0 - 15), [float]($y0 + 2))

    # Axis variable labels
    $g.DrawString("x", $fontMath, $brushDark, [float]($right + 22), [float]($y0 - 10))
    $g.DrawString("y", $fontMath, $brushDark, [float]($x0 - 7), [float]($top - 38))

    # Parabola: y = 6(x + 1)^2 - 9
    # from x = -2.5 to x = 0.5 (y goes up to 6*1.5^2 - 9 = 13.5 - 9 = 4.5)
    $penCurve = New-Object System.Drawing.Pen($cLine, 2.5)
    $curvePts = New-Object System.Collections.Generic.List[System.Drawing.PointF]
    for ($xVal = -2.53; $xVal -le 0.53; $xVal += 0.05) {
        $yVal = 6.0 * [Math]::Pow(($xVal + 1.0), 2) - 9.0
        $curvePts.Add((New-Object System.Drawing.PointF((MX $xVal), (MY $yVal))))
    }
    $g.DrawCurve($penCurve, $curvePts.ToArray())

    # Points of interest: (-1, -9) vertex, (0, -3) y-intercept, (-2, -3)
    $dotPts = @(
        @(-1.0, -9.0),
        @(0.0, -3.0),
        @(-2.0, -3.0)
    )
    $brushDot = New-Object System.Drawing.SolidBrush($cDark)
    $rPt = 5.0
    foreach ($dp in $dotPts) {
        $px = MX $dp[0]
        $py = MY $dp[1]
        $g.FillEllipse($brushDot, [float]($px - $rPt), [float]($py - $rPt), [float]($rPt * 2), [float]($rPt * 2))
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# Run all renders
Render-M1-Q1
Render-M1-Q14
Render-M1-Q21
Render-M2-Q2
Render-M2-Q4
Render-M2-Q6
Render-M2-Q10
Write-Host "All 7 light mode images for March 2026 INT 2 created successfully!"
