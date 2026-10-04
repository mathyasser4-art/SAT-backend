Add-Type -AssemblyName System.Drawing

# --- Helper Colors & Pens ---
$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)
$cShade = [System.Drawing.Color]::FromArgb(60, 59, 130, 246) # Soft translucent blue
$cBar = [System.Drawing.Color]::FromArgb(30, 58, 138)

# -------------------------------------------------------------
# 1. M1 Q1: Inequality y < 3x + 12
# -------------------------------------------------------------
function Create-M1-Q1 {
    param($out)
    $w = 460; $h = 480
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    # Plot area: x in [-4.5, 8.5], y in [-1, 16]
    $left = 50.0; $right = 420.0; $top = 40.0; $bottom = 440.0
    $pW = $right - $left; $pH = $bottom - $top

    function MX($x) { return $left + (($x - (-4.0)) / 12.0) * $pW }
    function MY($y) { return $bottom - (($y - 0.0) / 16.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    for ($xi = -4; $xi -le 8; $xi++) {
        $gx = MX $xi
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
    }
    for ($yi = 0; $yi -le 16; $yi += 2) {
        $gy = MY $yi
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Shaded region: y < 3x + 12
    # Vertices of polygon:
    # From x = -4, y = 0 up to x = 1.333, y = 16, then (8, 16), then (8, 0), then (-4, 0)
    $polyPts = @(
        (New-Object System.Drawing.PointF((MX -4.0), (MY 0.0))),
        (New-Object System.Drawing.PointF((MX 1.333), (MY 16.0))),
        (New-Object System.Drawing.PointF((MX 8.0), (MY 16.0))),
        (New-Object System.Drawing.PointF((MX 8.0), (MY 0.0)))
    )
    $brushShade = New-Object System.Drawing.SolidBrush($cShade)
    $g.FillPolygon($brushShade, $polyPts)

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    # Y-axis at x=0
    $g.DrawLine($penAxis, [float](MX 0), [float]$bottom, [float](MX 0), [float]($top - 20))
    # X-axis at y=0
    $g.DrawLine($penAxis, [float]$left, [float](MY 0), [float]($right + 20), [float](MY 0))

    # Boundary Line (dashed): y = 3x + 12
    $penLine = New-Object System.Drawing.Pen($cDark, 2.5)
    $penLine.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $g.DrawLine($penLine, [float](MX -4.0), [float](MY 0.0), [float](MX 1.333), [float](MY 16.0))

    # Labels
    $fLabel = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fNum = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
    $bText = New-Object System.Drawing.SolidBrush($cDark)
    $sf = New-Object System.Drawing.StringFormat; $sf.Alignment = [System.Drawing.StringAlignment]::Center

    $g.DrawString("y", $fLabel, $bText, [float](MX 0 - 6), [float]($top - 38))
    $g.DrawString("x", $fLabel, $bText, [float]($right + 25), [float](MY 0 - 8))
    $g.DrawString("O", $fLabel, $bText, [float](MX 0 - 15), [float](MY 0 + 4))

    # Ticks & numbers
    $g.DrawString("-4", $fNum, $bText, [float](MX -4), [float](MY 0 + 6), $sf)
    $g.DrawString("4", $fNum, $bText, [float](MX 4), [float](MY 0 + 6), $sf)
    $g.DrawString("8", $fNum, $bText, [float](MX 8), [float](MY 0 + 6), $sf)

    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far
    $g.DrawString("4", $fNum, $bText, [float](MX 0 - 6), [float](MY 4 - 7), $sfR)
    $g.DrawString("8", $fNum, $bText, [float](MX 0 - 6), [float](MY 8 - 7), $sfR)
    $g.DrawString("12", $fNum, $bText, [float](MX 0 - 6), [float](MY 12 - 7), $sfR)

    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}

# -------------------------------------------------------------
# 2. M1 Q2: Similar Triangles DEF and QRS
# -------------------------------------------------------------
function Create-M1-Q2 {
    param($out)
    $w = 480; $h = 420
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.5)
    $fV = New-Object System.Drawing.Font("Times New Roman", 17, [System.Drawing.FontStyle]::Italic)
    $fNote = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
    $bText = New-Object System.Drawing.SolidBrush($cDark)
    $sf = New-Object System.Drawing.StringFormat; $sf.Alignment = [System.Drawing.StringAlignment]::Center

    # Triangle 1 (DEF)
    $Dx = 50.0;  $Dy = 310.0
    $Ex = 140.0; $Ey = 200.0
    $Fx = 120.0; $Fy = 310.0
    $g.DrawPolygon($pen, @(
        (New-Object System.Drawing.PointF($Dx, $Dy)),
        (New-Object System.Drawing.PointF($Ex, $Ey)),
        (New-Object System.Drawing.PointF($Fx, $Fy))
    ))

    $g.DrawString("D", $fV, $bText, ($Dx - 22), ($Dy - 5))
    $g.DrawString("E", $fV, $bText, ($Ex - 6), ($Ey - 26))
    $g.DrawString("F", $fV, $bText, ($Fx + 6), ($Fy - 5))
    $g.DrawString("e", $fV, $bText, (($Dx + $Fx)/2.0), ($Dy + 4), $sf)
    $g.DrawString("f", $fV, $bText, (($Dx + $Ex)/2.0 - 16), (($Dy + $Ey)/2.0 - 14))
    $g.DrawString("d", $fV, $bText, (($Ex + $Fx)/2.0 + 8), (($Ey + $Fy)/2.0 - 10))

    # Triangle 2 (QRS) - 2x scale
    $Qx = 220.0; $Qy = 310.0
    $Rx = 400.0; $Ry = 50.0
    $Sx = 360.0; $Sy = 310.0
    $g.DrawPolygon($pen, @(
        (New-Object System.Drawing.PointF($Qx, $Qy)),
        (New-Object System.Drawing.PointF($Rx, $Ry)),
        (New-Object System.Drawing.PointF($Sx, $Sy))
    ))

    $g.DrawString("Q", $fV, $bText, ($Qx - 22), ($Qy - 5))
    $g.DrawString("R", $fV, $bText, ($Rx - 6), ($Ry - 26))
    $g.DrawString("S", $fV, $bText, ($Sx + 6), ($Sy - 5))
    $g.DrawString("ke", $fV, $bText, (($Qx + $Sx)/2.0), ($Qy + 4), $sf)
    $g.DrawString("kf", $fV, $bText, (($Qx + $Rx)/2.0 - 24), (($Qy + $Ry)/2.0 - 14))
    $g.DrawString("kd", $fV, $bText, (($Rx + $Sx)/2.0 + 8), (($Ry + $Sy)/2.0 - 10))

    $g.DrawString("Note: Figure not drawn to scale.", $fNote, $bText, ($w / 2.0), 375.0, $sf)

    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}

# -------------------------------------------------------------
# 3. M1 Q4: Parabola vertex (-5, 3) and line y = 3
# -------------------------------------------------------------
function Create-M1-Q4 {
    param($out)
    $w = 460; $h = 460
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 40.0; $right = 420.0; $top = 40.0; $bottom = 420.0
    $pW = $right - $left; $pH = $bottom - $top

    function MX($x) { return $left + (($x - (-10.0)) / 14.0) * $pW }
    function MY($y) { return $bottom - (($y - (-4.0)) / 11.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    for ($xi = -10; $xi -le 4; $xi++) {
        $gx = MX $xi
        $g.DrawLine($penGrid, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
    }
    for ($yi = -4; $yi -le 7; $yi++) {
        $gy = MY $yi
        $g.DrawLine($penGrid, [float]$left, [float]$gy, [float]$right, [float]$gy)
    }

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float](MX 0), [float]$bottom, [float](MX 0), [float]($top - 20))
    $g.DrawLine($penAxis, [float]$left, [float](MY 0), [float]($right + 20), [float](MY 0))

    # Curve: y = -(x + 5)^2 + 3
    $curvePts = New-Object System.Collections.Generic.List[System.Drawing.PointF]
    for ($xVal = -8.2; $xVal -le -1.8; $xVal += 0.1) {
        $yVal = -1.0 * [Math]::Pow($xVal + 5.0, 2) + 3.0
        if ($yVal -ge -4.0) {
            $curvePts.Add((New-Object System.Drawing.PointF((MX $xVal), (MY $yVal))))
        }
    }
    $penCurve = New-Object System.Drawing.Pen($cDark, 2.8)
    $g.DrawCurve($penCurve, $curvePts.ToArray())

    # Tangent line: y = 3
    $penTang = New-Object System.Drawing.Pen($cDark, 2.5)
    $g.DrawLine($penTang, [float]$left, [float](MY 3.0), [float]$right, [float](MY 3.0))

    # Labels
    $fLabel = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fNum = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
    $bText = New-Object System.Drawing.SolidBrush($cDark)
    $sf = New-Object System.Drawing.StringFormat; $sf.Alignment = [System.Drawing.StringAlignment]::Center

    $g.DrawString("y", $fLabel, $bText, [float](MX 0 - 6), [float]($top - 38))
    $g.DrawString("x", $fLabel, $bText, [float]($right + 25), [float](MY 0 - 8))
    $g.DrawString("O", $fLabel, $bText, [float](MX 0 - 15), [float](MY 0 + 4))

    for ($xi = -10; $xi -le 4; $xi += 2) {
        if ($xi -ne 0) {
            $g.DrawString("$xi", $fNum, $bText, [float](MX $xi), [float](MY 0 + 5), $sf)
        }
    }
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far
    for ($yi = -4; $yi -le 6; $yi += 2) {
        if ($yi -ne 0) {
            $g.DrawString("$yi", $fNum, $bText, [float](MX 0 - 6), [float](MY $yi - 7), $sfR)
        }
    }

    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}

# -------------------------------------------------------------
# 4. M1 Q8: Intersecting lines with angles r and s
# -------------------------------------------------------------
function Create-M1-Q8 {
    param($out)
    $w = 400; $h = 280
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.5)
    $fV = New-Object System.Drawing.Font("Times New Roman", 18, [System.Drawing.FontStyle]::Italic)
    $fDeg = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Regular)
    $bText = New-Object System.Drawing.SolidBrush($cDark)
    $deg = [char]176

    $cx = 200.0; $cy = 140.0
    # Line 1: bottom-left to top-right
    $g.DrawLine($pen, 30.0, 245.0, 370.0, 35.0)
    # Line 2: top-left to bottom-right
    $g.DrawLine($pen, 30.0, 35.0, 370.0, 245.0)

    # Angle labels r and s
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far
    $g.DrawString("r$deg", $fV, $bText, ($cx - 24), ($cy - 12))
    $g.DrawString("s$deg", $fV, $bText, ($cx + 12), ($cy - 12))

    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}

# -------------------------------------------------------------
# 5. M1 Q13: 4-Panel Inequality y <= -1/4 x + 7
# -------------------------------------------------------------
function Create-M1-Q13 {
    param($out)
    $w = 720; $h = 620
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    function DrawPanel($ox, $oy, $label, $slope, $shadeAbove) {
        $pW = 280.0; $pH = 220.0
        $left = $ox + 35.0; $right = $left + $pW
        $top = $oy + 25.0; $bottom = $top + $pH

        function PX($x) { return $left + (($x - (-8.0)) / 16.0) * $pW }
        function PY($y) { return $bottom - ($y / 12.0) * $pH }

        # Grid
        $penG = New-Object System.Drawing.Pen($cGrid, 1.0)
        for ($xi = -8; $xi -le 8; $xi += 2) {
            $g.DrawLine($penG, [float](PX $xi), [float]$top, [float](PX $xi), [float]$bottom)
        }
        for ($yi = 0; $yi -le 12; $yi += 2) {
            $g.DrawLine($penG, [float]$left, [float](PY $yi), [float]$right, [float](PY $yi))
        }

        # Shading
        $yLeft = 7.0 + $slope * (-8.0)
        $yRight = 7.0 + $slope * 8.0
        $poly = New-Object System.Collections.Generic.List[System.Drawing.PointF]
        $poly.Add((New-Object System.Drawing.PointF((PX -8.0), (PY $yLeft))))
        $poly.Add((New-Object System.Drawing.PointF((PX 8.0), (PY $yRight))))
        if ($shadeAbove) {
            $poly.Add((New-Object System.Drawing.PointF((PX 8.0), (PY 12.0))))
            $poly.Add((New-Object System.Drawing.PointF((PX -8.0), (PY 12.0))))
        } else {
            $poly.Add((New-Object System.Drawing.PointF((PX 8.0), (PY 0.0))))
            $poly.Add((New-Object System.Drawing.PointF((PX -8.0), (PY 0.0))))
        }
        $bShade = New-Object System.Drawing.SolidBrush($cShade)
        $g.FillPolygon($bShade, $poly.ToArray())

        # Axes
        $pAx = New-Object System.Drawing.Pen($cDark, 1.8)
        $pAx.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
        $g.DrawLine($pAx, [float](PX 0), [float]$bottom, [float](PX 0), [float]($top - 12))
        $g.DrawLine($pAx, [float]$left, [float](PY 0), [float]($right + 12), [float](PY 0))

        # Solid Boundary Line
        $pL = New-Object System.Drawing.Pen($cDark, 2.2)
        $g.DrawLine($pL, [float](PX -8.0), [float](PY $yLeft), [float](PX 8.0), [float](PY $yRight))

        # Circle badge for panel letter
        $bCirc = New-Object System.Drawing.SolidBrush($cDark)
        $bWhite = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
        $fBadge = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Bold)
        $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center; $sfC.LineAlignment = [System.Drawing.StringAlignment]::Center
        $g.FillEllipse($bCirc, ($ox + 5.0), ($oy + 5.0), 22.0, 22.0)
        $g.DrawString($label, $fBadge, $bWhite, ($ox + 16.0), ($oy + 16.0), $sfC)

        # Labels
        $fL = New-Object System.Drawing.Font("Times New Roman", 12, [System.Drawing.FontStyle]::Italic)
        $fN = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Regular)
        $bT = New-Object System.Drawing.SolidBrush($cDark)
        $g.DrawString("y", $fL, $bT, [float](PX 0 - 5), [float]($top - 24))
        $g.DrawString("x", $fL, $bT, [float]($right + 15), [float](PY 0 - 6))

        for ($xi = -8; $xi -le 8; $xi += 4) {
            $g.DrawString("$xi", $fN, $bT, [float](PX $xi), [float](PY 0 + 3), $sfC)
        }
        $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far
        for ($yi = 4; $yi -le 12; $yi += 4) {
            $g.DrawString("$yi", $fN, $bT, [float](PX 0 - 4), [float](PY $yi - 5), $sfR)
        }
    }

    DrawPanel 10 10 "A" (1.0/4.0) $false
    DrawPanel 370 10 "C" (-1.0/4.0) $false
    DrawPanel 10 310 "B" (1.0/4.0) $true
    DrawPanel 370 310 "D" (-1.0/4.0) $true

    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}

# -------------------------------------------------------------
# 6. M1 Q18: Parabola vertex (4,3) and line through (6,7)
# -------------------------------------------------------------
function Create-M1-Q18 {
    param($out)
    $w = 460; $h = 460
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 45.0; $right = 420.0; $top = 40.0; $bottom = 415.0
    $pW = $right - $left; $pH = $bottom - $top

    function MX($x) { return $left + ($x / 10.0) * $pW }
    function MY($y) { return $bottom - ($y / 10.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    for ($i = 0; $i -le 10; $i++) {
        $g.DrawLine($penGrid, [float](MX $i), [float]$top, [float](MX $i), [float]$bottom)
        $g.DrawLine($penGrid, [float]$left, [float](MY $i), [float]$right, [float](MY $i))
    }

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float](MX 0), [float]$bottom, [float](MX 0), [float]($top - 20))
    $g.DrawLine($penAxis, [float]$left, [float](MY 0), [float]($right + 20), [float](MY 0))

    # Parabola: y = (x - 4)^2 + 3
    $curvePts = New-Object System.Collections.Generic.List[System.Drawing.PointF]
    for ($xVal = 1.35; $xVal -le 6.65; $xVal += 0.1) {
        $yVal = [Math]::Pow($xVal - 4.0, 2) + 3.0
        if ($yVal -le 10.5) {
            $curvePts.Add((New-Object System.Drawing.PointF((MX $xVal), (MY $yVal))))
        }
    }
    $penCurve = New-Object System.Drawing.Pen($cDark, 2.6)
    $g.DrawCurve($penCurve, $curvePts.ToArray())

    # Line: passing through (6, 7) and (8.8, 0)
    # slope = -2.5 -> at x = 4.8, y = 10; at x = 8.8, y = 0
    $g.DrawLine($penCurve, [float](MX 4.8), [float](MY 10.0), [float](MX 8.8), [float](MY 0.0))

    # Labels
    $fLabel = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fNum = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
    $bText = New-Object System.Drawing.SolidBrush($cDark)
    $sf = New-Object System.Drawing.StringFormat; $sf.Alignment = [System.Drawing.StringAlignment]::Center

    $g.DrawString("y", $fLabel, $bText, [float](MX 0 - 6), [float]($top - 38))
    $g.DrawString("x", $fLabel, $bText, [float]($right + 25), [float](MY 0 - 8))
    $g.DrawString("O", $fLabel, $bText, [float](MX 0 - 15), [float](MY 0 + 4))

    for ($i = 1; $i -le 10; $i++) {
        $g.DrawString("$i", $fNum, $bText, [float](MX $i), [float](MY 0 + 5), $sf)
    }
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far
    for ($i = 1; $i -le 10; $i++) {
        $g.DrawString("$i", $fNum, $bText, [float](MX 0 - 6), [float](MY $i - 7), $sfR)
    }

    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}

# -------------------------------------------------------------
# 7. M1 Q20: Bar chart of sports students
# -------------------------------------------------------------
function Create-M1-Q20 {
    param($out)
    $w = 520; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 75.0; $right = 480.0; $top = 40.0; $bottom = 300.0
    $pW = $right - $left; $pH = $bottom - $top

    function MY($v) { return $bottom - ($v / 60.0) * $pH }

    # Grid lines & ticks
    $penG = New-Object System.Drawing.Pen($cGrid, 1.2)
    $fNum = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
    $bText = New-Object System.Drawing.SolidBrush($cDark)
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    for ($v = 0; $v -le 60; $v += 10) {
        $gy = MY $v
        $g.DrawLine($penG, [float]$left, [float]$gy, [float]$right, [float]$gy)
        $g.DrawString("$v", $fNum, $bText, [float]($left - 8), [float]($gy - 7), $sfR)
    }

    # Axes
    $penAx = New-Object System.Drawing.Pen($cDark, 2.0)
    $g.DrawLine($penAx, [float]$left, [float]$top, [float]$left, [float]$bottom)
    $g.DrawLine($penAx, [float]$left, [float]$bottom, [float]$right, [float]$bottom)

    # Bars: volleyball=30, hockey=40, basketball=55, soccer=42
    $bars = @(
        @("volleyball", 30),
        @("hockey", 40),
        @("basketball", 55),
        @("soccer", 42)
    )

    $barW = 60.0
    $gap = ($pW - (4.0 * $barW)) / 5.0
    $bBar = New-Object System.Drawing.SolidBrush($cBar)
    $pBar = New-Object System.Drawing.Pen($cDark, 1.5)
    $fCat = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    for ($i = 0; $i -lt 4; $i++) {
        $bx = $left + $gap + $i * ($barW + $gap)
        $by = MY $bars[$i][1]
        $bh = $bottom - $by
        $g.FillRectangle($bBar, [float]$bx, [float]$by, [float]$barW, [float]$bh)
        $g.DrawRectangle($pBar, [float]$bx, [float]$by, [float]$barW, [float]$bh)

        # Label rotated
        $state = $g.Save()
        $g.TranslateTransform(($bx + $barW / 2.0), ($bottom + 12))
        $g.RotateTransform(25)
        $g.DrawString($bars[$i][0], $fCat, $bText, 0, 0, $sfC)
        $g.Restore($state)
    }

    # Y-axis title: "Number of students" rotated
    $fTitle = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
    $stateY = $g.Save()
    $g.TranslateTransform(22, (($top + $bottom) / 2.0))
    $g.RotateTransform(-90)
    $g.DrawString("Number of students", $fTitle, $bText, 0, 0, $sfC)
    $g.Restore($stateY)

    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}

# -------------------------------------------------------------
# 8. M2 Q6: Right triangle ABC (AC = 43, AB = 22)
# -------------------------------------------------------------
function Create-M2-Q6 {
    param($out)
    $w = 460; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.5)
    $thinPen = New-Object System.Drawing.Pen($cDark, 1.8)
    $fV = New-Object System.Drawing.Font("Times New Roman", 18, [System.Drawing.FontStyle]::Italic)
    $fNum = New-Object System.Drawing.Font("Times New Roman", 17, [System.Drawing.FontStyle]::Regular)
    $fNote = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
    $bText = New-Object System.Drawing.SolidBrush($cDark)
    $sf = New-Object System.Drawing.StringFormat; $sf.Alignment = [System.Drawing.StringAlignment]::Center

    # A at top-right, B at bottom-right, C at bottom-left
    $Ax = 390.0; $Ay = 40.0
    $Bx = 390.0; $By = 270.0
    $Cx = 60.0;  $Cy = 270.0

    $g.DrawPolygon($pen, @(
        (New-Object System.Drawing.PointF($Ax, $Ay)),
        (New-Object System.Drawing.PointF($Bx, $By)),
        (New-Object System.Drawing.PointF($Cx, $Cy))
    ))

    # Right angle box at B
    $sq = 15.0
    $g.DrawLine($thinPen, ($Bx - $sq), $By, ($Bx - $sq), ($By - $sq))
    $g.DrawLine($thinPen, ($Bx - $sq), ($By - $sq), $Bx, ($By - $sq))

    # Vertex labels
    $g.DrawString("A", $fV, $bText, ($Ax + 6), ($Ay - 10))
    $g.DrawString("B", $fV, $bText, ($Bx + 6), ($By - 2))
    $g.DrawString("C", $fV, $bText, ($Cx - 24), ($Cy - 2))

    # Dimension labels
    $g.DrawString("22", $fNum, $bText, ($Bx + 8), (($Ay + $By)/2.0 - 10))
    $g.DrawString("43", $fNum, $bText, (($Ax + $Cx)/2.0 - 20), (($Ay + $Cy)/2.0 - 24))

    $g.DrawString("Note: Figure not drawn to scale.", $fNote, $bText, ($w / 2.0), 325.0, $sf)

    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}

# -------------------------------------------------------------
# 9. M2 Q10: Right rectangular pyramid
# -------------------------------------------------------------
function Create-M2-Q10 {
    param($out)
    $w = 460; $h = 480
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.2)
    $dashPen = New-Object System.Drawing.Pen($cDark, 1.8)
    $dashPen.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $thinPen = New-Object System.Drawing.Pen($cDark, 1.5)

    $fV = New-Object System.Drawing.Font("Times New Roman", 18, [System.Drawing.FontStyle]::Italic)
    $fNote = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
    $bText = New-Object System.Drawing.SolidBrush($cDark)
    $sf = New-Object System.Drawing.StringFormat; $sf.Alignment = [System.Drawing.StringAlignment]::Center

    # Apex
    $Tx = 320.0; $Ty = 40.0

    # Base vertices: Front (P1), Right (P2), Back (P3), Left (P4)
    $P1x = 250.0; $P1y = 390.0 # Bottom front
    $P2x = 350.0; $P2y = 320.0 # Right
    $P3x = 190.0; $P3y = 170.0 # Back (hidden)
    $P4x = 90.0;  $P4y = 240.0 # Left

    # Center of base
    $Cx = ($P1x + $P2x + $P3x + $P4x) / 4.0
    $Cy = ($P1y + $P2y + $P3y + $P4y) / 4.0

    # Draw hidden edges (dashed)
    $g.DrawLine($dashPen, $P4x, $P4y, $P3x, $P3y)
    $g.DrawLine($dashPen, $P2x, $P2y, $P3x, $P3y)
    $g.DrawLine($dashPen, $Tx, $Ty, $P3x, $P3y)

    # Base diagonals to center (dashed)
    $g.DrawLine($dashPen, $P3x, $P3y, $P1x, $P1y)
    $g.DrawLine($dashPen, $P4x, $P4y, $P2x, $P2y)

    # Altitude from apex to center (dashed)
    $g.DrawLine($dashPen, $Tx, $Ty, $Cx, $Cy)

    # Right angle marker at center in 3D
    $g.DrawLine($thinPen, ($Cx - 6), ($Cy - 8), ($Cx + 4), ($Cy - 14))
    $g.DrawLine($thinPen, ($Cx + 4), ($Cy - 14), ($Cx + 10), ($Cy - 6))

    # Visible outer edges (solid)
    $g.DrawLine($pen, $P4x, $P4y, $P1x, $P1y)
    $g.DrawLine($pen, $P1x, $P1y, $P2x, $P2y)
    $g.DrawLine($pen, $Tx, $Ty, $P4x, $P4y)
    $g.DrawLine($pen, $Tx, $Ty, $P1x, $P1y)
    $g.DrawLine($pen, $Tx, $Ty, $P2x, $P2y)

    # Labels
    $g.DrawString("h", $fV, $bText, ($Cx + 18), (($Ty + $Cy)/2.0 - 10))
    $g.DrawString([char]8467, $fV, $bText, (($P4x + $P1x)/2.0 - 24), (($P4y + $P1y)/2.0 + 4)) # script l
    $g.DrawString("w", $fV, $bText, (($P1x + $P2x)/2.0 + 8), (($P1y + $P2y)/2.0 + 6))

    $g.DrawString("Note: Figure not drawn to scale.", $fNote, $bText, ($w / 2.0), 445.0, $sf)

    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}

# -------------------------------------------------------------
# 10. M2 Q14: Scatterplot with line of best fit y = 12.4 - 0.7x
# -------------------------------------------------------------
function Create-M2-Q14 {
    param($out)
    $w = 460; $h = 460
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 45.0; $right = 420.0; $top = 40.0; $bottom = 415.0
    $pW = $right - $left; $pH = $bottom - $top

    function MX($x) { return $left + ($x / 14.0) * $pW }
    function MY($y) { return $bottom - ($y / 14.0) * $pH }

    # Grid
    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.2)
    for ($i = 0; $i -le 14; $i++) {
        $g.DrawLine($penGrid, [float](MX $i), [float]$top, [float](MX $i), [float]$bottom)
        $g.DrawLine($penGrid, [float]$left, [float](MY $i), [float]$right, [float](MY $i))
    }

    # Axes
    $penAxis = New-Object System.Drawing.Pen($cDark, 2.0)
    $penAxis.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $g.DrawLine($penAxis, [float](MX 0), [float]$bottom, [float](MX 0), [float]($top - 20))
    $g.DrawLine($penAxis, [float]$left, [float](MY 0), [float]($right + 20), [float](MY 0))

    # Line of best fit: y = 12.4 - 0.7x
    $penLine = New-Object System.Drawing.Pen($cDark, 2.5)
    $g.DrawLine($penLine, [float](MX 0.0), [float](MY 12.4), [float](MX 14.0), [float](MY (12.4 - 0.7*14.0)))

    # Scatter points
    $pts = @(
        @(1.0, 13.0),
        @(1.0, 11.0),
        @(3.0, 9.0),
        @(4.0, 8.0),
        @(6.0, 12.0),
        @(6.0, 8.0),
        @(6.6, 5.0),
        @(8.4, 5.0),
        @(11.5, 6.0),
        @(12.5, 2.0)
    )
    $bDot = New-Object System.Drawing.SolidBrush($cDark)
    foreach ($pt in $pts) {
        $px = MX $pt[0]
        $py = MY $pt[1]
        $g.FillEllipse($bDot, [float]($px - 4.5), [float]($py - 4.5), 9.0, 9.0)
    }

    # Labels
    $fLabel = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fNum = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
    $bText = New-Object System.Drawing.SolidBrush($cDark)
    $sf = New-Object System.Drawing.StringFormat; $sf.Alignment = [System.Drawing.StringAlignment]::Center

    $g.DrawString("y", $fLabel, $bText, [float](MX 0 - 6), [float]($top - 38))
    $g.DrawString("x", $fLabel, $bText, [float]($right + 25), [float](MY 0 - 8))
    $g.DrawString("O", $fLabel, $bText, [float](MX 0 - 15), [float](MY 0 + 4))

    for ($i = 2; $i -le 14; $i += 2) {
        $g.DrawString("$i", $fNum, $bText, [float](MX $i), [float](MY 0 + 5), $sf)
    }
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far
    for ($i = 2; $i -le 14; $i += 2) {
        $g.DrawString("$i", $fNum, $bText, [float](MX 0 - 6), [float](MY $i - 7), $sfR)
    }

    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}

# -------------------------------------------------------------
# 11. M2 Q19: 4-Panel Inequality 4x + 5y < 9
# -------------------------------------------------------------
function Create-M2-Q19 {
    param($out)
    $w = 720; $h = 620
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    function DrawPanelM2($ox, $oy, $label, $slope, $shadeAbove) {
        $pW = 280.0; $pH = 220.0
        $left = $ox + 35.0; $right = $left + $pW
        $top = $oy + 25.0; $bottom = $top + $pH

        function PX($x) { return $left + (($x - (-10.0)) / 20.0) * $pW }
        function PY($y) { return $bottom - (($y - (-10.0)) / 20.0) * $pH }

        # Grid
        $penG = New-Object System.Drawing.Pen($cGrid, 1.0)
        for ($xi = -10; $xi -le 10; $xi += 2) {
            $g.DrawLine($penG, [float](PX $xi), [float]$top, [float](PX $xi), [float]$bottom)
        }
        for ($yi = -10; $yi -le 10; $yi += 2) {
            $g.DrawLine($penG, [float]$left, [float](PY $yi), [float]$right, [float](PY $yi))
        }

        # Shading
        $yLeft = 1.8 + $slope * (-10.0)
        $yRight = 1.8 + $slope * 10.0
        $poly = New-Object System.Collections.Generic.List[System.Drawing.PointF]
        $poly.Add((New-Object System.Drawing.PointF((PX -10.0), (PY $yLeft))))
        $poly.Add((New-Object System.Drawing.PointF((PX 10.0), (PY $yRight))))
        if ($shadeAbove) {
            $poly.Add((New-Object System.Drawing.PointF((PX 10.0), (PY 10.0))))
            $poly.Add((New-Object System.Drawing.PointF((PX -10.0), (PY 10.0))))
        } else {
            $poly.Add((New-Object System.Drawing.PointF((PX 10.0), (PY -10.0))))
            $poly.Add((New-Object System.Drawing.PointF((PX -10.0), (PY -10.0))))
        }
        $bShade = New-Object System.Drawing.SolidBrush($cShade)
        $g.FillPolygon($bShade, $poly.ToArray())

        # Axes
        $pAx = New-Object System.Drawing.Pen($cDark, 1.8)
        $pAx.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
        $g.DrawLine($pAx, [float](PX 0), [float]$bottom, [float](PX 0), [float]($top - 12))
        $g.DrawLine($pAx, [float]$left, [float](PY 0), [float]($right + 12), [float](PY 0))

        # Dashed Boundary Line
        $pL = New-Object System.Drawing.Pen($cDark, 2.2)
        $pL.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
        $g.DrawLine($pL, [float](PX -10.0), [float](PY $yLeft), [float](PX 10.0), [float](PY $yRight))

        # Circle badge for panel letter
        $bCirc = New-Object System.Drawing.SolidBrush($cDark)
        $bWhite = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
        $fBadge = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Bold)
        $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center; $sfC.LineAlignment = [System.Drawing.StringAlignment]::Center
        $g.FillEllipse($bCirc, ($ox + 5.0), ($oy + 5.0), 22.0, 22.0)
        $g.DrawString($label, $fBadge, $bWhite, ($ox + 16.0), ($oy + 16.0), $sfC)

        # Labels
        $fL = New-Object System.Drawing.Font("Times New Roman", 12, [System.Drawing.FontStyle]::Italic)
        $fN = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Regular)
        $bT = New-Object System.Drawing.SolidBrush($cDark)
        $g.DrawString("y", $fL, $bT, [float](PX 0 - 5), [float]($top - 24))
        $g.DrawString("x", $fL, $bT, [float]($right + 15), [float](PY 0 - 6))

        for ($xi = -10; $xi -le 10; $xi += 4) {
            if ($xi -ne 0) {
                $g.DrawString("$xi", $fN, $bT, [float](PX $xi), [float](PY 0 + 3), $sfC)
            }
        }
        $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far
        for ($yi = -8; $yi -le 10; $yi += 4) {
            if ($yi -ne 0) {
                $g.DrawString("$yi", $fN, $bT, [float](PX 0 - 4), [float](PY $yi - 5), $sfR)
            }
        }
    }

    DrawPanelM2 10 10 "A" 0.8 $false
    DrawPanelM2 370 10 "B" 0.8 $true
    DrawPanelM2 10 310 "C" (-0.8) $false
    DrawPanelM2 370 310 "D" (-0.8) $true

    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}

# --- Execute All 11 Renderings ---
Create-M1-Q1  "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\mar26_us1_m1_q1_light.png"
Create-M1-Q2  "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\mar26_us1_m1_q2_light.png"
Create-M1-Q4  "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\mar26_us1_m1_q4_light.png"
Create-M1-Q8  "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\mar26_us1_m1_q8_light.png"
Create-M1-Q13 "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\mar26_us1_m1_q13_light.png"
Create-M1-Q18 "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\mar26_us1_m1_q18_light.png"
Create-M1-Q20 "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\mar26_us1_m1_q20_light.png"
Create-M2-Q6  "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\mar26_us1_m2_q6_light.png"
Create-M2-Q10 "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\mar26_us1_m2_q10_light.png"
Create-M2-Q14 "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\mar26_us1_m2_q14_light.png"
Create-M2-Q19 "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\mar26_us1_m2_q19_light.png"

Write-Host "All 11 March 2026 US 1 light mode images successfully rendered."
