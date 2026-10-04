Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "oct2025_int2_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)
$cLine = [System.Drawing.Color]::FromArgb(37, 99, 235)
$cShade = [System.Drawing.Color]::FromArgb(60, 37, 99, 235)

# ==============================================================================
# 1. M1 Q12 & M2 Q19: Hollow Cylinder Pipe
# ==============================================================================
function Render-Pipe {
    param([string]$fileName)
    $outPath = Join-Path $imgDir $fileName
    $w = 380; $h = 420
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penPipe = New-Object System.Drawing.Pen($cDark, 2.0)
    $penInner = New-Object System.Drawing.Pen($cDark, 1.5)
    $penDim = New-Object System.Drawing.Pen($cDark, 1.3)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $brushPipe = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(241, 245, 249))
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.5, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Pipe geometry:
    # Outer ellipse at top: center (200, 85), width 80, height 26
    # Inner ellipse at top: center (200, 85), width 64, height 20
    # Outer ellipse at bottom: center (200, 335), width 80, height 26
    $cx = 200.0; $topY = 85.0; $botY = 335.0
    $outW = 80.0; $outH = 26.0
    $inW = 64.0; $inH = 20.0

    # Fill body
    $g.FillRectangle($brushPipe, [float]($cx - $outW/2), [float]$topY, [float]$outW, [float]($botY - $topY))
    $g.FillEllipse($brushPipe, [float]($cx - $outW/2), [float]($botY - $outH/2), [float]$outW, [float]$outH)
    $g.FillEllipse($brushPipe, [float]($cx - $outW/2), [float]($topY - $outH/2), [float]$outW, [float]$outH)

    # Draw bottom ellipse (lower half)
    $g.DrawArc($penPipe, [float]($cx - $outW/2), [float]($botY - $outH/2), [float]$outW, [float]$outH, 0, 180)
    # Side lines
    $g.DrawLine($penPipe, [float]($cx - $outW/2), [float]$topY, [float]($cx - $outW/2), [float]$botY)
    $g.DrawLine($penPipe, [float]($cx + $outW/2), [float]$topY, [float]($cx + $outW/2), [float]$botY)

    # Top outer ellipse
    $g.DrawEllipse($penPipe, [float]($cx - $outW/2), [float]($topY - $outH/2), [float]$outW, [float]$outH)
    # Top inner ellipse
    $brushInner = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(226, 232, 240))
    $g.FillEllipse($brushInner, [float]($cx - $inW/2), [float]($topY - $inH/2), [float]$inW, [float]$inH)
    $g.DrawEllipse($penInner, [float]($cx - $inW/2), [float]($topY - $inH/2), [float]$inW, [float]$inH)

    # Outside diameter dimension arrow above top
    $dimY = 55.0
    $g.DrawLine($penDim, [float]($cx - $outW/2), [float]$dimY, [float]($cx + $outW/2), [float]$dimY)
    $g.DrawLine($penDim, [float]($cx - $outW/2), [float]($dimY - 5), [float]($cx - $outW/2), [float]($dimY + 5))
    $g.DrawLine($penDim, [float]($cx + $outW/2), [float]($dimY - 5), [float]($cx + $outW/2), [float]($dimY + 5))
    $g.DrawString("outside", $fontLabel, $brush, [float]$cx, [float]20, $sfC)
    $g.DrawString("diameter", $fontLabel, $brush, [float]$cx, [float]34, $sfC)

    # Wall thickness pointer on left
    $g.DrawString("wall thickness", $fontLabel, $brush, [float]40, [float]75)
    $g.DrawLine($penDim, 115, 83, 163, 85)

    # Height dimension arrow on right
    $dimX = $cx + $outW/2 + 25
    $g.DrawLine($penDim, [float]$dimX, [float]$topY, [float]$dimX, [float]$botY)
    $g.DrawLine($penDim, [float]($dimX - 5), [float]$topY, [float]($dimX + 5), [float]$topY)
    $g.DrawLine($penDim, [float]($dimX - 5), [float]$botY, [float]($dimX + 5), [float]$botY)
    $g.DrawString("height", $fontLabel, $brush, [float]($dimX + 8), [float](($topY + $botY)/2 - 8))

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, [float]($w/2), [float]380, $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 2. M2 Q3: Line passing through (-5, -1) and (2, 4)
# ==============================================================================
function Render-M2-Q3 {
    $outPath = Join-Path $imgDir "m2_q3_light.png"
    $w = 420; $h = 420
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penLine = New-Object System.Drawing.Pen($cLine, 2.2)
    $penDot = New-Object System.Drawing.Pen($cDark, 1.5)
    $brushDot = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(37, 99, 235))
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 12, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Coordinate mapping: x in [-6, 6], y in [-6, 6]
    $ox = 210.0; $oy = 210.0
    $scale = 26.0

    for ($i = -6; $i -le 6; $i++) {
        $x = $ox + $i * $scale
        $y = $oy - $i * $scale
        $g.DrawLine($penGrid, [float]$x, [float]($oy - 6 * $scale), [float]$x, [float]($oy + 6 * $scale))
        $g.DrawLine($penGrid, [float]($ox - 6 * $scale), [float]$y, [float]($ox + 6 * $scale), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]($ox - 6 * $scale - 12), [float]$oy, [float]($ox + 6 * $scale + 12), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]($oy + 6 * $scale + 12), [float]$ox, [float]($oy - 6 * $scale - 12))

    # Arrows
    $g.DrawLine($penAxis, [float]($ox + 6 * $scale + 12), [float]$oy, [float]($ox + 6 * $scale + 6), [float]($oy - 4))
    $g.DrawLine($penAxis, [float]($ox + 6 * $scale + 12), [float]$oy, [float]($ox + 6 * $scale + 6), [float]($oy + 4))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - 6 * $scale - 12), [float]($ox - 4), [float]($oy - 6 * $scale - 6))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - 6 * $scale - 12), [float]($ox + 4), [float]($oy - 6 * $scale - 6))

    # Ticks & labels
    $g.DrawString("O", $fontV, $brush, [float]($ox - 14), [float]($oy + 2))
    $g.DrawString("x", $fontV, $brush, [float]($ox + 6 * $scale + 15), [float]($oy - 8))
    $g.DrawString("y", $fontV, $brush, [float]($ox - 8), [float]($oy - 6 * $scale - 26))

    for ($i = -6; $i -le 6; $i++) {
        if ($i -ne 0) {
            $x = $ox + $i * $scale
            $g.DrawString("$i", $fontAxis, $brush, [float]$x, [float]($oy + 3), $sfC)
            $y = $oy - $i * $scale
            $g.DrawString("$i", $fontAxis, $brush, [float]($ox - 4), [float]($y - 6), $sfR)
        }
    }

    # Line: through (-5, -1) and (2, 4) -> slope = 5/7, y = (5/7)x + 18/7
    # At x = -6, y = -1.714. At x = 5.2, y = 6.28
    $x1 = -6.0; $y1 = (5.0/7.0)*(-6.0) + (18.0/7.0)
    $x2 = 5.2;  $y2 = (5.0/7.0)*(5.2)  + (18.0/7.0)
    $g.DrawLine($penLine, [float]($ox + $x1 * $scale), [float]($oy - $y1 * $scale), [float]($ox + $x2 * $scale), [float]($oy - $y2 * $scale))

    # Dots at (-5, -1) and (2, 4)
    $pts = @(@(-5, -1), @(2, 4))
    foreach ($p in $pts) {
        $px = $ox + $p[0] * $scale
        $py = $oy - $p[1] * $scale
        $g.FillEllipse($brushDot, [float]($px - 4), [float]($py - 4), [float]8, [float]8)
        $g.DrawEllipse($penDot, [float]($px - 4), [float]($py - 4), [float]8, [float]8)
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 3. M2 Q5: Inequality y > 4x + 3 (Dashed line & shaded region)
# ==============================================================================
function Render-M2-Q5 {
    $outPath = Join-Path $imgDir "m2_q5_light.png"
    $w = 420; $h = 420
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penDashed = New-Object System.Drawing.Pen($cLine, 2.2)
    $penDashed.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $brushShade = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(45, 37, 99, 235))
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 12, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Coordinate mapping: x in [-6, 4], y in [-1, 13]
    $ox = 250.0; $oy = 370.0
    $scaleX = 30.0; $scaleY = 25.0

    # Shading: polygon above dashed line y = 4x + 3
    # Boundary: from x = -6, y = 13 (top left)
    # To x = 2.5, y = 13 (where line hits top)
    # Down line to x = -1.0, y = -1 (bottom)
    # To x = -6, y = -1 (bottom left)
    $poly = @(
        (New-Object System.Drawing.PointF([float]($ox - 6 * $scaleX), [float]($oy - 13 * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox + 2.5 * $scaleX), [float]($oy - 13 * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox - 1.0 * $scaleX), [float]($oy - (-1.0) * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox - 6 * $scaleX), [float]($oy - (-1.0) * $scaleY)))
    )
    $g.FillPolygon($brushShade, $poly)

    # Grid lines
    for ($xi = -6; $xi -le 4; $xi++) {
        $x = $ox + $xi * $scaleX
        $g.DrawLine($penGrid, [float]$x, [float]($oy - 13 * $scaleY), [float]$x, [float]($oy + 1 * $scaleY))
    }
    for ($yi = -1; $yi -le 13; $yi++) {
        $y = $oy - $yi * $scaleY
        $g.DrawLine($penGrid, [float]($ox - 6 * $scaleX), [float]$y, [float]($ox + 4 * $scaleX), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]($ox - 6 * $scaleX - 12), [float]$oy, [float]($ox + 4 * $scaleX + 12), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]($oy + 1 * $scaleY + 12), [float]$ox, [float]($oy - 13 * $scaleY - 12))

    # Arrows
    $g.DrawLine($penAxis, [float]($ox + 4 * $scaleX + 12), [float]$oy, [float]($ox + 4 * $scaleX + 6), [float]($oy - 4))
    $g.DrawLine($penAxis, [float]($ox + 4 * $scaleX + 12), [float]$oy, [float]($ox + 4 * $scaleX + 6), [float]($oy + 4))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - 13 * $scaleY - 12), [float]($ox - 4), [float]($oy - 13 * $scaleY - 6))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - 13 * $scaleY - 12), [float]($ox + 4), [float]($oy - 13 * $scaleY - 6))

    # Labels
    $g.DrawString("O", $fontV, $brush, [float]($ox - 14), [float]($oy + 2))
    $g.DrawString("x", $fontV, $brush, [float]($ox + 4 * $scaleX + 15), [float]($oy - 8))
    $g.DrawString("y", $fontV, $brush, [float]($ox - 8), [float]($oy - 13 * $scaleY - 26))

    for ($xi = -6; $xi -le 4; $xi += 2) {
        if ($xi -ne 0) {
            $x = $ox + $xi * $scaleX
            $g.DrawString("$xi", $fontAxis, $brush, [float]$x, [float]($oy + 3), $sfC)
        }
    }
    for ($yi = 2; $yi -le 12; $yi += 2) {
        $y = $oy - $yi * $scaleY
        $g.DrawString("$yi", $fontAxis, $brush, [float]($ox - 4), [float]($y - 6), $sfR)
    }

    # Dashed line y = 4x + 3
    $x1 = -1.0; $y1 = -1.0
    $x2 = 2.5;  $y2 = 13.0
    $g.DrawLine($penDashed, [float]($ox + $x1 * $scaleX), [float]($oy - $y1 * $scaleY), [float]($ox + $x2 * $scaleX), [float]($oy - $y2 * $scaleY))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 4. M2 Q13: Pool and Concrete Path
# ==============================================================================
function Render-M2-Q13 {
    $outPath = Join-Path $imgDir "m2_q13_light.png"
    $w = 380; $h = 320
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penOuter = New-Object System.Drawing.Pen($cDark, 2.0)
    $penInner = New-Object System.Drawing.Pen($cDark, 1.8)
    $penDim = New-Object System.Drawing.Pen($cDark, 1.3)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $brushPath = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(241, 245, 249))
    $brushPool = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(219, 234, 254))
    $fontLabel = New-Object System.Drawing.Font("Arial", 11.5, [System.Drawing.FontStyle]::Bold)
    $fontDim = New-Object System.Drawing.Font("Arial", 10.5, [System.Drawing.FontStyle]::Italic)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Outer rectangle: concrete path
    # (40, 30, 300, 220)
    $g.FillRectangle($brushPath, 40, 30, 300, 220)
    $g.DrawRectangle($penOuter, 40, 30, 300, 220)

    # Inner rectangle: pool
    # Path width x = 35 px on each side
    # (75, 65, 230, 150)
    $g.FillRectangle($brushPool, 75, 65, 230, 150)
    $g.DrawRectangle($penInner, 75, 65, 230, 150)

    # Text inside pool
    $g.DrawString("pool", $fontLabel, $brush, [float]190, [float]130, $sfC)

    # Text concrete path
    $g.DrawString("concrete path", $fontDim, $brush, [float]170, [float]40, $sfC)

    # Dimension arrows for x ft:
    # On left: between x = 40 and x = 75 at y = 140
    $g.DrawLine($penDim, 40, 140, 75, 140)
    $g.DrawLine($penDim, 40, 136, 40, 144)
    $g.DrawLine($penDim, 75, 136, 75, 144)
    $g.DrawString("x ft", $fontDim, $brush, [float]57, [float]118, $sfC)

    # On top: between y = 30 and y = 65 at x = 275
    $g.DrawLine($penDim, 275, 30, 275, 65)
    $g.DrawLine($penDim, 271, 30, 279, 30)
    $g.DrawLine($penDim, 271, 65, 279, 65)
    $g.DrawString("x ft", $fontDim, $brush, [float]293, [float]40)

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, [float]($w/2), [float]275, $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 5. M2 Q18: Table of Cylinder Volumes
# ==============================================================================
function Render-M2-Q18 {
    $outPath = Join-Path $imgDir "m2_q18_light.png"
    $w = 460; $h = 180
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penTable = New-Object System.Drawing.Pen($cDark, 1.5)
    $brushHeader = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(241, 245, 249))
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontHeader = New-Object System.Drawing.Font("Arial", 11.5, [System.Drawing.FontStyle]::Bold)
    $fontCell = New-Object System.Drawing.Font("Times New Roman", 13.5, [System.Drawing.FontStyle]::Regular)
    $fontText = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Table bounds: (30, 25, 400, 130)
    # Header row height 42, 2 data rows 44 each
    $x0 = 30; $y0 = 25; $tw = 400; $th = 130
    $col1W = 230; $col2W = 170

    # Header fill
    $g.FillRectangle($brushHeader, $x0, $y0, $tw, 42)

    # Grid
    $g.DrawRectangle($penTable, $x0, $y0, $tw, $th)
    $g.DrawLine($penTable, $x0, ($y0 + 42), ($x0 + $tw), ($y0 + 42))
    $g.DrawLine($penTable, $x0, ($y0 + 86), ($x0 + $tw), ($y0 + 86))
    $g.DrawLine($penTable, ($x0 + $col1W), $y0, ($x0 + $col1W), ($y0 + $th))

    # Header text
    $g.DrawString("Volume (cubic units)", $fontHeader, $brush, [float]($x0 + $col1W + $col2W/2), [float]($y0 + 11), $sfC)

    # Row 1
    $g.DrawString("Right circular cylinder A", $fontText, $brush, [float]($x0 + 15), [float]($y0 + 54))
    $g.DrawString("392π", $fontCell, $brush, [float]($x0 + $col1W + $col2W/2), [float]($y0 + 52), $sfC)

    # Row 2
    $g.DrawString("Right circular cylinder B", $fontText, $brush, [float]($x0 + 15), [float]($y0 + 98))
    $g.DrawString("10,584π", $fontCell, $brush, [float]($x0 + $col1W + $col2W/2), [float]($y0 + 96), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

Render-Pipe "m1_q12_light.png"
Render-Pipe "m2_q19_light.png"
Render-M2-Q3
Render-M2-Q5
Render-M2-Q13
Render-M2-Q18
