Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "oct2025_int1_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)
$cLine = [System.Drawing.Color]::FromArgb(37, 99, 235)
$cLine2 = [System.Drawing.Color]::FromArgb(220, 38, 38)

# ==============================================================================
# 1. M1 Q7: System of Linear Equations (y = 4 and line through (0, -4) and (3, 4))
# ==============================================================================
function Render-M1-Q7 {
    $outPath = Join-Path $imgDir "m1_q7_light.png"
    $w = 420; $h = 420
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penL1 = New-Object System.Drawing.Pen($cLine, 2.2)
    $penL2 = New-Object System.Drawing.Pen($cLine2, 2.2)
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

    # Grid
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

    # Line 1: y = 4 (horizontal)
    $y4 = $oy - 4 * $scale
    $g.DrawLine($penL1, [float]($ox - 6 * $scale), [float]$y4, [float]($ox + 6 * $scale), [float]$y4)

    # Line 2: slope 8/3 through (0, -4) and (3, 4)
    # y = (8/3)x - 4 -> at y = -6, x = -0.75; at y = 6.5, x = 3.9375
    $xStart = -0.75; $yStart = -6.0
    $xEnd = 3.8; $yEnd = (8.0/3.0)*3.8 - 4.0
    $g.DrawLine($penL2, [float]($ox + $xStart * $scale), [float]($oy - $yStart * $scale), [float]($ox + $xEnd * $scale), [float]($oy - $yEnd * $scale))

    # Intersection dot at (3, 4)
    $brushDot = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))
    $ptX = $ox + 3 * $scale; $ptY = $oy - 4 * $scale
    $g.FillEllipse($brushDot, [float]($ptX - 4), [float]($ptY - 4), [float]8, [float]8)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 2. M1 Q12: Right Triangle JKL (JL = 35)
# ==============================================================================
function Render-M1-Q12 {
    $outPath = Join-Path $imgDir "m1_q12_light.png"
    $w = 380; $h = 320
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.0)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontLabel = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Bold)
    $fontNum = New-Object System.Drawing.Font("Times New Roman", 16, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Vertices:
    # L at (45, 240)
    # K at (320, 240)
    # J at (320, 45)
    $pL = New-Object System.Drawing.PointF(45, 240)
    $pK = New-Object System.Drawing.PointF(320, 240)
    $pJ = New-Object System.Drawing.PointF(320, 45)

    $pts = @($pL, $pK, $pJ)
    $g.DrawPolygon($pen, $pts)

    # Right angle box at K
    $box = 16
    $g.DrawRectangle($pen, (320 - $box), (240 - $box), $box, $box)

    # Vertex labels
    $g.DrawString("L", $fontLabel, $brush, [float]25, [float]235)
    $g.DrawString("K", $fontLabel, $brush, [float]328, [float]235)
    $g.DrawString("J", $fontLabel, $brush, [float]328, [float]35)

    # Side label 35 on hypotenuse
    $g.DrawString("35", $fontNum, $brush, [float]165, [float]115)

    # Note underneath
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, [float]($w / 2), [float]275, $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 3. M2 Q3: Parallel lines n and s cut by transversal t
# ==============================================================================
function Render-M2-Q3 {
    $outPath = Join-Path $imgDir "m2_q3_light.png"
    $w = 340; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 1.8)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontItalic = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontDegree = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Vertical line n at x = 120
    # Vertical line s at x = 230
    $g.DrawLine($pen, 120, 45, 120, 290)
    $g.DrawLine($pen, 230, 45, 230, 290)

    # Transversal t from (40, 45) to (310, 280) -> slope = 235 / 270 = 0.87
    $g.DrawLine($pen, 40, 45, 310, 280)

    # Labels for lines:
    $g.DrawString("n", $fontItalic, $brush, [float]115, [float]20)
    $g.DrawString("s", $fontItalic, $brush, [float]225, [float]20)
    $g.DrawString("t", $fontItalic, $brush, [float]30, [float]25)

    # Intersection at line n (x = 120): y = 45 + (120 - 40)*(235/270) = 114.6
    # x° is at top-left of intersection with n
    $g.DrawString("x°", $fontDegree, $brush, [float]95, [float]90)

    # Intersection at line s (x = 230): y = 45 + (230 - 40)*(235/270) = 210.3
    # y° is at top-right of intersection with s
    $g.DrawString("y°", $fontDegree, $brush, [float]240, [float]188)

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, [float]($w / 2), [float]320, $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 4. M2 Q20: Line k in xy-plane (slope 2/3, through (2, 0) and (8, 4))
# ==============================================================================
function Render-M2-Q20 {
    $outPath = Join-Path $imgDir "m2_q20_light.png"
    $w = 420; $h = 420
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penLine = New-Object System.Drawing.Pen($cLine, 2.2)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 12, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Coordinate mapping: x in [-10, 10], y in [-10, 6]
    # Center origin O:
    $ox = 210.0; $oy = 175.0
    $scale = 17.0

    # Grid lines
    for ($xi = -10; $xi -le 10; $xi++) {
        $x = $ox + $xi * $scale
        $g.DrawLine($penGrid, [float]$x, [float]($oy - 6 * $scale), [float]$x, [float]($oy + 10 * $scale))
    }
    for ($yi = -10; $yi -le 6; $yi++) {
        $y = $oy - $yi * $scale
        $g.DrawLine($penGrid, [float]($ox - 10 * $scale), [float]$y, [float]($ox + 10 * $scale), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]($ox - 10 * $scale - 12), [float]$oy, [float]($ox + 10 * $scale + 12), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]($oy + 10 * $scale + 12), [float]$ox, [float]($oy - 6 * $scale - 12))

    # Arrows
    $g.DrawLine($penAxis, [float]($ox + 10 * $scale + 12), [float]$oy, [float]($ox + 10 * $scale + 6), [float]($oy - 4))
    $g.DrawLine($penAxis, [float]($ox + 10 * $scale + 12), [float]$oy, [float]($ox + 10 * $scale + 6), [float]($oy + 4))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - 6 * $scale - 12), [float]($ox - 4), [float]($oy - 6 * $scale - 6))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - 6 * $scale - 12), [float]($ox + 4), [float]($oy - 6 * $scale - 6))

    # Labels
    $g.DrawString("O", $fontV, $brush, [float]($ox - 14), [float]($oy + 2))
    $g.DrawString("x", $fontV, $brush, [float]($ox + 10 * $scale + 15), [float]($oy - 8))
    $g.DrawString("y", $fontV, $brush, [float]($ox - 8), [float]($oy - 6 * $scale - 26))

    for ($xi = -10; $xi -le 10; $xi += 2) {
        if ($xi -ne 0) {
            $x = $ox + $xi * $scale
            $g.DrawString("$xi", $fontAxis, $brush, [float]$x, [float]($oy + 3), $sfC)
        }
    }
    for ($yi = -10; $yi -le 6; $yi += 2) {
        if ($yi -ne 0) {
            $y = $oy - $yi * $scale
            $g.DrawString("$yi", $fontAxis, $brush, [float]($ox - 4), [float]($y - 6), $sfR)
        }
    }

    # Line k: y = (2/3)x - 4/3
    # From x = -10 to x = 10:
    $yStart = (2.0/3.0)*(-10.0) - (4.0/3.0) # -8.0
    $yEnd   = (2.0/3.0)*(10.0)  - (4.0/3.0) # 5.333
    $g.DrawLine($penLine, [float]($ox - 10 * $scale), [float]($oy - $yStart * $scale), [float]($ox + 10 * $scale), [float]($oy - $yEnd * $scale))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 5. M2 Q21: Scatterplot and Line of Best Fit
# ==============================================================================
function Render-M2-Q21 {
    $outPath = Join-Path $imgDir "m2_q21_light.png"
    $w = 420; $h = 420
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penLine = New-Object System.Drawing.Pen($cLine, 2.0)
    $penDot = New-Object System.Drawing.Pen($cDark, 1.2)
    $brushDot = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(37, 99, 235))
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Regular)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 12, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Coordinate mapping:
    # x in [0, 10], y in [0, 110]
    $ox = 70.0; $oy = 360.0
    $gw = 300.0; $gh = 310.0
    $dx = $gw / 10.0; $dy = $gh / 110.0

    # Grid lines
    for ($xi = 1; $xi -le 10; $xi++) {
        $x = $ox + $xi * $dx
        $g.DrawLine($penGrid, [float]$x, [float]($oy - $gh), [float]$x, [float]$oy)
    }
    for ($yi = 10; $yi -le 110; $yi += 10) {
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

    for ($xi = 2; $xi -le 10; $xi += 2) {
        $x = $ox + $xi * $dx
        $g.DrawString("$xi", $fontAxis, $brush, [float]$x, [float]($oy + 4), $sfC)
    }
    for ($yi = 10; $yi -le 110; $yi += 10) {
        $y = $oy - $yi * $dy
        $g.DrawString("$yi", $fontAxis, $brush, [float]($ox - 6), [float]($y - 7), $sfR)
    }

    # Line of best fit from (0, 82) to (10, 96.5)
    $x1 = $ox + 0 * $dx; $y1 = $oy - 82.0 * $dy
    $x2 = $ox + 10 * $dx; $y2 = $oy - 96.5 * $dy
    $g.DrawLine($penLine, [float]$x1, [float]$y1, [float]$x2, [float]$y2)

    # 9 Points:
    # 5 above: (3.6, 91), (6.0, 94), (6.5, 95), (8.4, 98), (9.8, 100)
    # 4 below: (5.5, 87), (6.9, 89), (7.3, 90), (9.4, 93)
    $pts = @(
        @(3.6, 91.0),
        @(5.5, 87.0),
        @(6.0, 94.0),
        @(6.5, 95.0),
        @(6.9, 89.0),
        @(7.3, 90.0),
        @(8.4, 98.0),
        @(9.4, 93.0),
        @(9.8, 100.0)
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

Render-M1-Q7
Render-M1-Q12
Render-M2-Q3
Render-M2-Q20
Render-M2-Q21
