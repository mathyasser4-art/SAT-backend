Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "oct2025_us1_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)
$cLine = [System.Drawing.Color]::FromArgb(37, 99, 235)
$cLine2 = [System.Drawing.Color]::FromArgb(225, 29, 72)
$cDot = [System.Drawing.Color]::FromArgb(37, 99, 235)

# ==============================================================================
# 1. M1 Q6: Line through (-6, -8), (0, -7), (6, -6)
# ==============================================================================
function Render-M1Q6 {
    $outPath = Join-Path $imgDir "m1_q6_light.png"
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
    $brushDot = New-Object System.Drawing.SolidBrush($cDot)
    $brushWhite = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far; $sfR.LineAlignment = [System.Drawing.StringAlignment]::Center

    $xMin = -8.0; $xMax = 8.0
    $yMin = -10.0; $yMax = 2.0
    $left = 40.0; $right = 420.0
    $top = 30.0; $bottom = 400.0

    function ToScreenX([float]$x) { return $left + ($x - $xMin) / ($xMax - $xMin) * ($right - $left) }
    function ToScreenY([float]$y) { return $bottom - ($y - $yMin) / ($yMax - $yMin) * ($bottom - $top) }

    # Grid
    for ($x = -8; $x -le 8; $x++) {
        $sx = ToScreenX $x
        $g.DrawLine($penGrid, [float]$sx, [float]$top, [float]$sx, [float]$bottom)
    }
    for ($y = -10; $y -le 2; $y++) {
        $sy = ToScreenY $y
        $g.DrawLine($penGrid, [float]$left, [float]$sy, [float]$right, [float]$sy)
    }

    # Axes
    $originX = ToScreenX 0
    $originY = ToScreenY 0
    $g.DrawLine($penAxis, [float]$originX, [float]$bottom + 15, [float]$originX, [float]$top - 15)
    $g.DrawLine($penAxis, [float]$left - 15, [float]$originY, [float]$right + 15, [float]$originY)

    # Arrowheads
    $capPen = New-Object System.Drawing.Pen($cDark, 1.8)
    $capPen.CustomEndCap = New-Object System.Drawing.Drawing2D.AdjustableArrowCap(4, 5)
    $g.DrawLine($capPen, [float]$originX, [float]$top - 5, [float]$originX, [float]$top - 18)
    $g.DrawLine($capPen, [float]$right + 5, [float]$originY, [float]$right + 18, [float]$originY)

    # Labels
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
    for ($y = -10; $y -le 2; $y += 2) {
        if ($y -ne 0) {
            $sy = ToScreenY $y
            $g.DrawLine($penAxis, [float]($originX - 3), [float]$sy, [float]($originX + 3), [float]$sy)
            $g.DrawString("$y", $fontAxis, $brushDark, [float]($originX - 5), [float]$sy, $sfR)
        }
    }

    # Line: y = (1/6)x - 7
    $x1 = -8.5; $y1 = (1.0/6.0)*$x1 - 7.0
    $x2 = 8.5; $y2 = (1.0/6.0)*$x2 - 7.0
    $g.DrawLine($penLine, [float](ToScreenX $x1), [float](ToScreenY $y1), [float](ToScreenX $x2), [float](ToScreenY $y2))

    # Points: (-6, -8), (0, -7), (6, -6)
    $pts = @(@(-6, -8), @(0, -7), @(6, -6))
    foreach ($p in $pts) {
        $px = ToScreenX $p[0]
        $py = ToScreenY $p[1]
        $g.FillEllipse($brushDot, [float]($px - 5), [float]($py - 5), 10, 10)
        $g.FillEllipse($brushWhite, [float]($px - 2.5), [float]($py - 2.5), 5, 5)
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 2. M1 Q15: Right triangle ABC, right angle at B, angle A = 56 deg
# ==============================================================================
function Render-M1Q15 {
    $outPath = Join-Path $imgDir "m1_q15_light.png"
    $w = 400; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penTri = New-Object System.Drawing.Pen($cDark, 2.2)
    $penBox = New-Object System.Drawing.Pen($cDark, 1.5)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontLabel = New-Object System.Drawing.Font("Arial", 11.5, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 10.5, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Vertices
    # A at top (80, 50)
    # B at bottom-left (80, 280)
    # C at bottom-right (350, 280)
    $ax = 80.0; $ay = 50.0
    $bx = 80.0; $by = 280.0
    $cx = 350.0; $cy = 280.0

    # Draw triangle
    $g.DrawLine($penTri, [float]$ax, [float]$ay, [float]$bx, [float]$by)
    $g.DrawLine($penTri, [float]$bx, [float]$by, [float]$cx, [float]$cy)
    $g.DrawLine($penTri, [float]$cx, [float]$cy, [float]$ax, [float]$ay)

    # Right angle marker at B
    $sq = 18.0
    $g.DrawLine($penBox, [float]$bx, [float]($by - $sq), [float]($bx + $sq), [float]($by - $sq))
    $g.DrawLine($penBox, [float]($bx + $sq), [float]($by - $sq), [float]($bx + $sq), [float]$by)

    # Labels A, B, C
    $g.DrawString("A", $fontLabel, $brushDark, [float]($ax - 18), [float]($ay - 8))
    $g.DrawString("B", $fontLabel, $brushDark, [float]($bx - 18), [float]($by - 2))
    $g.DrawString("C", $fontLabel, $brushDark, [float]($cx + 8), [float]($by - 2))

    # Angle 56 deg at A
    $g.DrawString("56°", $fontVal, $brushDark, [float]($ax + 8), [float]($ay + 32))

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushDark, [float]($w / 2), [float]($h - 30), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 3. M1 Q18: Parallel lines r and s cut by transversal t
# ==============================================================================
function Render-M1Q18 {
    $outPath = Join-Path $imgDir "m1_q18_light.png"
    $w = 380; $h = 400
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

    # Vertical parallel lines r and s
    $rx = 135.0; $sx = 235.0
    $topY = 80.0; $botY = 340.0
    $g.DrawLine($penLine, [float]$rx, [float]$topY, [float]$rx, [float]$botY)
    $g.DrawLine($penLine, [float]$sx, [float]$topY, [float]$sx, [float]$botY)

    # Transversal line t: slope = -1.0 approx
    # passes through (rx, 155) and (sx, 255)
    $t1x = 65.0; $t1y = 85.0
    $t2x = 305.0; $t2y = 325.0
    $g.DrawLine($penLine, [float]$t1x, [float]$t1y, [float]$t2x, [float]$t2y)

    # Line labels r, s, t
    $g.DrawString("r", $fontLabel, $brushDark, [float]($rx - 5), [float]($topY - 25))
    $g.DrawString("s", $fontLabel, $brushDark, [float]($sx - 5), [float]($topY - 25))
    $g.DrawString("t", $fontLabel, $brushDark, [float]($t1x - 18), [float]($t1y - 18))

    # Angle labels
    # Intersection 1: (rx, 155) = (135, 155). Angle a is top-right
    $g.DrawString("a°", $fontVal, $brushDark, [float]($rx + 10), [float]138)

    # Intersection 2: (sx, 255) = (235, 255). Angle b is top-left, c is bottom-left
    $g.DrawString("b°", $fontVal, $brushDark, [float]($sx - 25), [float]225)
    $g.DrawString("c°", $fontVal, $brushDark, [float]($sx - 25), [float]262)

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushDark, [float]($w / 2), [float]($h - 25), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 4. M1 Q21: Scatterplot of exponential growth
# ==============================================================================
function Render-M1Q21 {
    $outPath = Join-Path $imgDir "m1_q21_light.png"
    $w = 440; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushDot = New-Object System.Drawing.SolidBrush($cDot)
    $brushWhite = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far; $sfR.LineAlignment = [System.Drawing.StringAlignment]::Center

    $xMin = -5.0; $xMax = 5.0
    $yMin = 0.0; $yMax = 80.0
    $left = 50.0; $right = 400.0
    $top = 30.0; $bottom = 400.0

    function ToScreenX([float]$x) { return $left + ($x - $xMin) / ($xMax - $xMin) * ($right - $left) }
    function ToScreenY([float]$y) { return $bottom - ($y - $yMin) / ($yMax - $yMin) * ($bottom - $top) }

    # Grid
    for ($x = -5; $x -le 5; $x++) {
        $sx = ToScreenX $x
        $g.DrawLine($penGrid, [float]$sx, [float]$top, [float]$sx, [float]$bottom)
    }
    for ($y = 0; $y -le 80; $y += 10) {
        $sy = ToScreenY $y
        $g.DrawLine($penGrid, [float]$left, [float]$sy, [float]$right, [float]$sy)
    }

    # Axes
    $originX = ToScreenX 0
    $originY = ToScreenY 0
    $g.DrawLine($penAxis, [float]$originX, [float]$bottom + 10, [float]$originX, [float]$top - 15)
    $g.DrawLine($penAxis, [float]$left - 15, [float]$originY, [float]$right + 15, [float]$originY)

    # Arrowheads
    $capPen = New-Object System.Drawing.Pen($cDark, 1.8)
    $capPen.CustomEndCap = New-Object System.Drawing.Drawing2D.AdjustableArrowCap(4, 5)
    $g.DrawLine($capPen, [float]$originX, [float]$top - 5, [float]$originX, [float]$top - 18)
    $g.DrawLine($capPen, [float]$right + 5, [float]$originY, [float]$right + 18, [float]$originY)

    # Labels
    $g.DrawString("y", $fontLabel, $brushDark, [float]($originX - 6), [float]($top - 28))
    $g.DrawString("x", $fontLabel, $brushDark, [float]($right + 20), [float]($originY - 8))
    $g.DrawString("O", $fontAxis, $brushDark, [float]($originX - 12), [float]($originY + 3))

    for ($x = -5; $x -le 5; $x++) {
        if ($x -ne 0) {
            $sx = ToScreenX $x
            $g.DrawLine($penAxis, [float]$sx, [float]($originY - 3), [float]$sx, [float]($originY + 3))
            $g.DrawString("$x", $fontAxis, $brushDark, [float]$sx, [float]($originY + 5), $sfC)
        }
    }
    for ($y = 10; $y -le 80; $y += 10) {
        $sy = ToScreenY $y
        $g.DrawLine($penAxis, [float]($originX - 3), [float]$sy, [float]($originX + 3), [float]$sy)
        $g.DrawString("$y", $fontAxis, $brushDark, [float]($originX - 5), [float]$sy, $sfR)
    }

    # Points
    $pts = @(
        @(-4.1, 19.0),
        @(-3.5, 19.5),
        @(-2.5, 20.0),
        @(-1.5, 21.5),
        @(-0.7, 22.8),
        @(0.0, 24.2),
        @(0.5, 25.3),
        @(1.7, 30.0),
        @(3.0, 42.0),
        @(3.2, 45.8),
        @(4.0, 49.2),
        @(4.3, 56.7)
    )
    foreach ($p in $pts) {
        $px = ToScreenX $p[0]
        $py = ToScreenY $p[1]
        $g.FillEllipse($brushDot, [float]($px - 4.5), [float]($py - 4.5), 9, 9)
        $g.FillEllipse($brushWhite, [float]($px - 2.0), [float]($py - 2.0), 4, 4)
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 5. M2 Q3: Linear & Nonlinear system intersection at (5, 4)
# ==============================================================================
function Render-M2Q3 {
    $outPath = Join-Path $imgDir "m2_q3_light.png"
    $w = 440; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penLine1 = New-Object System.Drawing.Pen($cLine, 2.4)
    $penLine2 = New-Object System.Drawing.Pen($cLine2, 2.4)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushDot = New-Object System.Drawing.SolidBrush($cDark)
    $brushWhite = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $fontAxis = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far; $sfR.LineAlignment = [System.Drawing.StringAlignment]::Center

    $xMin = -2.0; $xMax = 9.0
    $yMin = -2.0; $yMax = 9.0
    $left = 40.0; $right = 410.0
    $top = 30.0; $bottom = 400.0

    function ToScreenX([float]$x) { return $left + ($x - $xMin) / ($xMax - $xMin) * ($right - $left) }
    function ToScreenY([float]$y) { return $bottom - ($y - $yMin) / ($yMax - $yMin) * ($bottom - $top) }

    # Grid
    for ($x = -2; $x -le 9; $x++) {
        $sx = ToScreenX $x
        $g.DrawLine($penGrid, [float]$sx, [float]$top, [float]$sx, [float]$bottom)
    }
    for ($y = -2; $y -le 9; $y++) {
        $sy = ToScreenY $y
        $g.DrawLine($penGrid, [float]$left, [float]$sy, [float]$right, [float]$sy)
    }

    # Axes
    $originX = ToScreenX 0
    $originY = ToScreenY 0
    $g.DrawLine($penAxis, [float]$originX, [float]$bottom + 10, [float]$originX, [float]$top - 15)
    $g.DrawLine($penAxis, [float]$left - 15, [float]$originY, [float]$right + 15, [float]$originY)

    # Arrowheads
    $capPen = New-Object System.Drawing.Pen($cDark, 1.8)
    $capPen.CustomEndCap = New-Object System.Drawing.Drawing2D.AdjustableArrowCap(4, 5)
    $g.DrawLine($capPen, [float]$originX, [float]$top - 5, [float]$originX, [float]$top - 18)
    $g.DrawLine($capPen, [float]$right + 5, [float]$originY, [float]$right + 18, [float]$originY)

    # Labels
    $g.DrawString("y", $fontLabel, $brushDark, [float]($originX - 6), [float]($top - 28))
    $g.DrawString("x", $fontLabel, $brushDark, [float]($right + 20), [float]($originY - 8))
    $g.DrawString("O", $fontAxis, $brushDark, [float]($originX - 12), [float]($originY + 3))

    for ($x = -2; $x -le 9; $x++) {
        if ($x -ne 0) {
            $sx = ToScreenX $x
            $g.DrawLine($penAxis, [float]$sx, [float]($originY - 3), [float]$sx, [float]($originY + 3))
            $g.DrawString("$x", $fontAxis, $brushDark, [float]$sx, [float]($originY + 5), $sfC)
        }
    }
    for ($y = -2; $y -le 9; $y++) {
        if ($y -ne 0) {
            $sy = ToScreenY $y
            $g.DrawLine($penAxis, [float]($originX - 3), [float]$sy, [float]($originX + 3), [float]$sy)
            $g.DrawString("$y", $fontAxis, $brushDark, [float]($originX - 5), [float]$sy, $sfR)
        }
    }

    # Linear line: y = -4x + 24
    $x1 = 3.75; $y1 = -4.0 * $x1 + 24.0 # y = 9
    $x2 = 6.5;  $y2 = -4.0 * $x2 + 24.0 # y = -2
    $g.DrawLine($penLine1, [float](ToScreenX $x1), [float](ToScreenY $y1), [float](ToScreenX $x2), [float](ToScreenY $y2))

    # Nonlinear curve: y = 3 + 2^(x - 5)
    $curvePts = New-Object System.Collections.Generic.List[System.Drawing.PointF]
    for ($x = -2.0; $x -le 7.6; $x += 0.05) {
        $y = 3.0 + [Math]::Pow(2.0, $x - 5.0)
        if ($y -le 9.2) {
            $curvePts.Add((New-Object System.Drawing.PointF((ToScreenX $x), (ToScreenY $y))))
        }
    }
    $g.DrawLines($penLine2, $curvePts.ToArray())

    # Intersection point (5, 4)
    $ix = ToScreenX 5.0
    $iy = ToScreenY 4.0
    $g.FillEllipse($brushDot, [float]($ix - 6), [float]($iy - 6), 12, 12)
    $g.FillEllipse($brushWhite, [float]($ix - 3), [float]($iy - 3), 6, 6)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 6. M2 Q6: Polynomial function f(x) with y-intercept at (0, 5)
# ==============================================================================
function Render-M2Q6 {
    $outPath = Join-Path $imgDir "m2_q6_light.png"
    $w = 420; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penCurve = New-Object System.Drawing.Pen($cLine, 2.4)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushDot = New-Object System.Drawing.SolidBrush($cDark)
    $brushWhite = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $fontAxis = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = [System.Drawing.StringAlignment]::Far; $sfR.LineAlignment = [System.Drawing.StringAlignment]::Center

    $xMin = -1.0; $xMax = 1.0
    $yMin = -1.0; $yMax = 12.0
    $left = 50.0; $right = 380.0
    $top = 30.0; $bottom = 400.0

    function ToScreenX([float]$x) { return $left + ($x - $xMin) / ($xMax - $xMin) * ($right - $left) }
    function ToScreenY([float]$y) { return $bottom - ($y - $yMin) / ($yMax - $yMin) * ($bottom - $top) }

    # Grid: ticks every 0.25 on x, every 1 on y
    for ($i = -4; $i -le 4; $i++) {
        $x = $i * 0.25
        $sx = ToScreenX $x
        $g.DrawLine($penGrid, [float]$sx, [float]$top, [float]$sx, [float]$bottom)
    }
    for ($y = -1; $y -le 12; $y++) {
        $sy = ToScreenY $y
        $g.DrawLine($penGrid, [float]$left, [float]$sy, [float]$right, [float]$sy)
    }

    # Axes
    $originX = ToScreenX 0
    $originY = ToScreenY 0
    $g.DrawLine($penAxis, [float]$originX, [float]$bottom + 10, [float]$originX, [float]$top - 15)
    $g.DrawLine($penAxis, [float]$left - 15, [float]$originY, [float]$right + 15, [float]$originY)

    # Arrowheads
    $capPen = New-Object System.Drawing.Pen($cDark, 1.8)
    $capPen.CustomEndCap = New-Object System.Drawing.Drawing2D.AdjustableArrowCap(4, 5)
    $g.DrawLine($capPen, [float]$originX, [float]$top - 5, [float]$originX, [float]$top - 18)
    $g.DrawLine($capPen, [float]$right + 5, [float]$originY, [float]$right + 18, [float]$originY)

    # Labels
    $g.DrawString("y", $fontLabel, $brushDark, [float]($originX - 6), [float]($top - 28))
    $g.DrawString("x", $fontLabel, $brushDark, [float]($right + 20), [float]($originY - 8))
    $g.DrawString("O", $fontAxis, $brushDark, [float]($originX - 12), [float]($originY + 3))

    # Ticks on x: -1, 1
    $sXneg = ToScreenX -1.0; $g.DrawString("-1", $fontAxis, $brushDark, [float]$sXneg, [float]($originY + 5), $sfC)
    $sXpos = ToScreenX 1.0;  $g.DrawString("1", $fontAxis, $brushDark, [float]$sXpos, [float]($originY + 5), $sfC)

    # Ticks on y: -1, 1..12
    for ($y = -1; $y -le 12; $y++) {
        if ($y -ne 0) {
            $sy = ToScreenY $y
            $g.DrawLine($penAxis, [float]($originX - 3), [float]$sy, [float]($originX + 3), [float]$sy)
            $g.DrawString("$y", $fontAxis, $brushDark, [float]($originX - 5), [float]$sy, $sfR)
        }
    }

    # Curve: y = 5 + 7 * x^6
    $curvePts = New-Object System.Collections.Generic.List[System.Drawing.PointF]
    for ($x = -1.0; $x -le 1.001; $x += 0.01) {
        $y = 5.0 + 7.0 * [Math]::Pow($x, 6)
        if ($y -le 12.2) {
            $curvePts.Add((New-Object System.Drawing.PointF((ToScreenX $x), (ToScreenY $y))))
        }
    }
    $g.DrawLines($penCurve, $curvePts.ToArray())

    # Point at (0, 5)
    $ix = ToScreenX 0.0
    $iy = ToScreenY 5.0
    $g.FillEllipse($brushDot, [float]($ix - 5.5), [float]($iy - 5.5), 11, 11)
    $g.FillEllipse($brushWhite, [float]($ix - 2.5), [float]($iy - 2.5), 5, 5)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

Render-M1Q6
Render-M1Q15
Render-M1Q18
Render-M1Q21
Render-M2Q3
Render-M2Q6
