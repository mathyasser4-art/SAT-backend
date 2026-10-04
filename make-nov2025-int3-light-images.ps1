Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "nov2025_int3_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)
$cLine = [System.Drawing.Color]::FromArgb(37, 99, 235)

# ==============================================================================
# 1. M1 Q5: Scatterplot of Store Size vs Annual Sales
# ==============================================================================
function Render-M1-Q5 {
    $outPath = Join-Path $imgDir "m1_q5_light.png"
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
        @(3.0, 7.1),
        @(3.1, 5.7),
        @(5.0, 7.7),
        @(5.3, 10.5),
        @(5.5, 9.4),
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
# 2. M1 Q10: Right Triangle (sides a, b, c; angle 58 deg)
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
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontMath = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontText = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Triangle vertices:
    # Right angle at (330, 290)
    # Top vertex at (330, 50)
    # Left vertex at (50, 290)
    $pRight = New-Object System.Drawing.PointF(330, 290)
    $pTop   = New-Object System.Drawing.PointF(330, 50)
    $pLeft  = New-Object System.Drawing.PointF(50, 290)

    $pts = @($pLeft, $pRight, $pTop)
    $g.DrawPolygon($pen, $pts)

    # Right angle box at pRight
    $boxSize = 16
    $g.DrawRectangle($pen, ($pRight.X - $boxSize), ($pRight.Y - $boxSize), $boxSize, $boxSize)

    # Angle label at top (58°)
    $g.DrawString("58°", $fontText, $brush, [float]300, [float]85)

    # Side labels:
    # a at bottom
    $g.DrawString("a", $fontMath, $brush, [float]190, [float]302, $sfC)
    # b at right
    $g.DrawString("b", $fontMath, $brush, [float]345, [float]165)
    # c on hypotenuse
    $g.DrawString("c", $fontMath, $brush, [float]165, [float]145)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 3. M1 Q11: Parallel lines l and k with transversal t
# ==============================================================================
function Render-M1-Q11 {
    $outPath = Join-Path $imgDir "m1_q11_light.png"
    $w = 380; $h = 340
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 1.8)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontItalic = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontDegree = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)

    # Line l (horizontal at y = 110)
    # Line k (horizontal at y = 210)
    $g.DrawLine($pen, 30, 110, 310, 110)
    $g.DrawLine($pen, 30, 210, 310, 210)

    # Transversal t: from (45, 35) to (325, 295) -> slope = 260 / 280 = 0.928
    $g.DrawLine($pen, 45, 35, 325, 295)

    # Labels for lines:
    $g.DrawString("ℓ", $fontItalic, $brush, [float]325, [float]95)
    $g.DrawString("k", $fontItalic, $brush, [float]325, [float]195)
    $g.DrawString("t", $fontItalic, $brush, [float]40, [float]15)

    # Intersections:
    # At l (y = 110): x = 45 + (110 - 35) * (280/260) = 45 + 80.7 = 125.7
    # At k (y = 210): x = 45 + (210 - 35) * (280/260) = 45 + 188.5 = 233.5
    # x° is at top-right of intersection with l
    $g.DrawString("x°", $fontDegree, $brush, [float]135, [float]88)

    # y° is at top-left of intersection with k
    $g.DrawString("y°", $fontDegree, $brush, [float]200, [float]188)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 4. M1 Q13: Video Game Cost Graph (Line from (0,50) to (10,210))
# ==============================================================================
function Render-M1-Q13 {
    $outPath = Join-Path $imgDir "m1_q13_light.png"
    $w = 460; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penLine = New-Object System.Drawing.Pen($cLine, 2.4)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Regular)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 12, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Coordinate mapping:
    # x in [0, 10], y in [0, 500]
    $ox = 75.0; $oy = 370.0
    $gw = 340.0; $gh = 320.0
    $dx = $gw / 10.0; $dy = $gh / 500.0

    # Grid: x every 1, y every 50
    for ($xi = 1; $xi -le 10; $xi++) {
        $x = $ox + $xi * $dx
        $g.DrawLine($penGrid, [float]$x, [float]($oy - $gh), [float]$x, [float]$oy)
    }
    for ($yi = 25; $yi -le 500; $yi += 25) {
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
    $g.DrawString("O", $fontV, $brush, [float]($ox - 15), [float]($oy + 2))
    $g.DrawString("x", $fontV, $brush, [float]($ox + $gw + 20), [float]($oy - 8))
    $g.DrawString("y", $fontV, $brush, [float]($ox - 8), [float]($oy - $gh - 30))

    for ($xi = 1; $xi -le 10; $xi++) {
        $x = $ox + $xi * $dx
        $g.DrawString("$xi", $fontAxis, $brush, [float]$x, [float]($oy + 4), $sfC)
    }
    for ($yi = 50; $yi -le 500; $yi += 50) {
        $y = $oy - $yi * $dy
        $g.DrawString("$yi", $fontAxis, $brush, [float]($ox - 6), [float]($y - 7), $sfR)
    }

    # Data line: from (0, 50) to (10, 210)
    $x1 = $ox + 0 * $dx; $y1 = $oy - 50 * $dy
    $x2 = $ox + 10 * $dx; $y2 = $oy - 210 * $dy
    $g.DrawLine($penLine, [float]$x1, [float]$y1, [float]$x2, [float]$y2)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 5. M2 Q4: Triangle ABC with Base 10 cm and Height h
# ==============================================================================
function Render-M2-Q4 {
    $outPath = Join-Path $imgDir "m2_q4_light.png"
    $w = 460; $h = 240
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.0)
    $penDashed = New-Object System.Drawing.Pen($cDark, 1.8)
    $penDashed.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontLabel = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Regular)
    $fontMath = New-Object System.Drawing.Font("Times New Roman", 14, [System.Drawing.FontStyle]::Italic)
    $fontText = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Vertices:
    # A at (50, 170)
    # C at (410, 170)
    # B at (230, 40)
    $pA = New-Object System.Drawing.PointF(50, 170)
    $pC = New-Object System.Drawing.PointF(410, 170)
    $pB = New-Object System.Drawing.PointF(230, 40)

    $pts = @($pA, $pB, $pC)
    $g.DrawPolygon($pen, $pts)

    # Altitude dashed line from B(230, 40) to base (230, 170)
    $g.DrawLine($penDashed, 230, 40, 230, 170)

    # Right angle box at (230, 170)
    $boxSize = 14
    $g.DrawRectangle($pen, 230, (170 - $boxSize), $boxSize, $boxSize)

    # Labels
    $g.DrawString("A", $fontLabel, $brush, [float]25, [float]165)
    $g.DrawString("B", $fontLabel, $brush, [float]230, [float]15, $sfC)
    $g.DrawString("C", $fontLabel, $brush, [float]418, [float]165)

    # Height label h
    $g.DrawString("h", $fontMath, $brush, [float]245, [float]100)

    # Base label 10 cm
    $g.DrawString("10 cm", $fontText, $brush, [float]230, [float]185, $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

Render-M1-Q5
Render-M1-Q10
Render-M1-Q11
Render-M1-Q13
Render-M2-Q4
