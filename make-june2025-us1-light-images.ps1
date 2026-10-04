Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "june2025_us1_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42) # Slate 900
$cGray = [System.Drawing.Color]::FromArgb(100, 116, 139) # Slate 500
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240) # Slate 200
$cAxis = [System.Drawing.Color]::FromArgb(71, 85, 105) # Slate 600
$cBlue = [System.Drawing.Color]::FromArgb(37, 99, 235) # Blue 600
$cBarFill = [System.Drawing.Color]::FromArgb(71, 85, 105)

# ==============================================================================
# 1. M1 Q15: Cubic graph y = f(x)
# ==============================================================================
function Render-M1Q15 {
    $outPath = Join-Path $imgDir "m1_q15_light.png"
    $w = 380; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.5)
    $penCurve = New-Object System.Drawing.Pen($cBlue, 2.4)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushGray = New-Object System.Drawing.SolidBrush($cGray)
    $brushWhite = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Italic)

    # Coordinate mapping: x from -8 to 8, y from -16 to 12
    $ox = 190.0
    $oy = 150.0
    $scaleX = 18.0
    $scaleY = 9.0

    # Grid lines
    for ($x = -8; $x -le 8; $x++) {
        $px = $ox + $x * $scaleX
        $g.DrawLine($penGrid, [float]$px, 20.0, [float]$px, 330.0)
    }
    for ($y = -16; $y -le 12; $y += 2) {
        $py = $oy - $y * $scaleY
        $g.DrawLine($penGrid, 30.0, [float]$py, 350.0, [float]$py)
    }

    # Axes
    $g.DrawLine($penAxis, 25.0, [float]$oy, 360.0, [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, 335.0, [float]$ox, 15.0)

    # Axis arrows
    $g.DrawLine($penAxis, 360.0, [float]$oy, 354.0, [float]($oy - 3))
    $g.DrawLine($penAxis, 360.0, [float]$oy, 354.0, [float]($oy + 3))
    $g.DrawLine($penAxis, [float]$ox, 15.0, [float]($ox - 3), 21.0)
    $g.DrawLine($penAxis, [float]$ox, 15.0, [float]($ox + 3), 21.0)

    $g.DrawString("x", $fontLabel, $brushDark, 362.0, [float]($oy - 8))
    $g.DrawString("y", $fontLabel, $brushDark, [float]($ox - 6), 2.0)
    $g.DrawString("O", $fontAxis, $brushDark, [float]($ox - 13), [float]($oy + 2))

    # X-axis ticks & labels
    for ($x = -8; $x -le 8; $x++) {
        if ($x -ne 0) {
            $px = $ox + $x * $scaleX
            $g.DrawString("$x", $fontAxis, $brushDark, [float]($px - 7), [float]($oy + 3))
        }
    }

    # Y-axis ticks & labels
    foreach ($y in @(-16, -12, -8, -4, 4, 8, 12)) {
        $py = $oy - $y * $scaleY
        $g.DrawString("$y", $fontAxis, $brushDark, [float]($ox + 4), [float]($py - 6))
    }

    # Cubic curve: smooth spline through points
    # (-3.5, 14), (-3, 0), (-2, -10), (-1.2, -14), (0, -4), (1, 0), (1.5, -4), (2.2, -16)
    $pts = @(
        (New-Object System.Drawing.PointF([float]($ox - 3.4 * $scaleX), [float]($oy - 14.0 * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox - 3.0 * $scaleX), [float]($oy - 0.0 * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox - 2.2 * $scaleX), [float]($oy - (-9.5) * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox - 1.4 * $scaleX), [float]($oy - (-13.0) * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox - 0.7 * $scaleX), [float]($oy - (-10.5) * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox - 0.0 * $scaleX), [float]($oy - (-4.0) * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox + 0.6 * $scaleX), [float]($oy - (-0.8) * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox + 1.0 * $scaleX), [float]($oy - 0.0 * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox + 1.4 * $scaleX), [float]($oy - (-3.0) * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox + 1.9 * $scaleX), [float]($oy - (-10.0) * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox + 2.3 * $scaleX), [float]($oy - (-17.0) * $scaleY)))
    )
    $g.DrawCurve($penCurve, $pts, 0.5)

    # Key points: (-3, 0), (0, -4), (1, 0)
    $keyPts = @(
        (New-Object System.Drawing.PointF([float]($ox - 3.0 * $scaleX), [float]($oy))),
        (New-Object System.Drawing.PointF([float]($ox), [float]($oy - (-4.0) * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox + 1.0 * $scaleX), [float]($oy)))
    )
    foreach ($pt in $keyPts) {
        $g.FillEllipse($brushDark, [float]($pt.X - 4.5), [float]($pt.Y - 4.5), 9.0, 9.0)
        $g.FillEllipse($brushWhite, [float]($pt.X - 2.5), [float]($pt.Y - 2.5), 5.0, 5.0)
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 2. M1 Q17: Right triangle ABC (AC = 14, C = 58 deg)
# ==============================================================================
function Render-M1Q17 {
    $outPath = Join-Path $imgDir "m1_q17_light.png"
    $w = 340; $h = 300
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushGray = New-Object System.Drawing.SolidBrush($cGray)
    $fontLabel = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 12.0, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Italic)

    # Triangle vertices
    $ax = 40.0;  $ay = 230.0
    $bx = 280.0; $by = 230.0
    $cx = 280.0; $cy = 30.0

    # Draw triangle
    $g.DrawLine($penLine, [float]$ax, [float]$ay, [float]$bx, [float]$by)
    $g.DrawLine($penLine, [float]$bx, [float]$by, [float]$cx, [float]$cy)
    $g.DrawLine($penLine, [float]$cx, [float]$cy, [float]$ax, [float]$ay)

    # Right angle square at B
    $sq = 14.0
    $g.DrawRectangle($penLine, [float]($bx - $sq), [float]($by - $sq), [float]$sq, [float]$sq)

    # Labels A, B, C
    $g.DrawString("A", $fontLabel, $brushDark, [float]($ax - 18), [float]($ay - 8))
    $g.DrawString("B", $fontLabel, $brushDark, [float]($bx + 6), [float]($by - 4))
    $g.DrawString("C", $fontLabel, $brushDark, [float]($cx + 6), [float]($cy - 8))

    # Angle 58 deg at C
    $penArc = New-Object System.Drawing.Pen($cDark, 1.2)
    $g.DrawArc($penArc, [float]($cx - 28), [float]($cy - 28), 56.0, 56.0, 90.0, 50.0)
    $g.DrawString("58°", $fontVal, $brushDark, [float]($cx - 42), [float]($cy + 24))

    # Hypotenuse label 14
    $g.DrawString("14", $fontVal, $brushDark, 140.0, 110.0)

    # Note
    $note = "Note: Figure not drawn to scale."
    $g.DrawString($note, $fontNote, $brushGray, 70.0, 265.0)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 3. M1 Q19: Intersecting triangles (AC = CD, angle EBC = 29 deg, ACD = 108 deg)
# ==============================================================================
function Render-M1Q19 {
    $outPath = Join-Path $imgDir "m1_q19_light.png"
    $w = 340; $h = 300
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushGray = New-Object System.Drawing.SolidBrush($cGray)
    $fontLabel = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 10.5, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Italic)

    # Coordinates
    $dx = 40.0;  $dy = 225.0
    $ax = 300.0; $ay = 225.0
    $ex = 230.0; $ey = 225.0
    $bx = 300.0; $by = 35.0
    $cx = 175.0; $cy = 133.0

    # Draw lines
    $g.DrawLine($penLine, [float]$dx, [float]$dy, [float]$ax, [float]$ay) # DA
    $g.DrawLine($penLine, [float]$dx, [float]$dy, [float]$bx, [float]$by) # DB
    $g.DrawLine($penLine, [float]$ax, [float]$ay, [float]$cx, [float]$cy) # AC
    $g.DrawLine($penLine, [float]$ex, [float]$ey, [float]$bx, [float]$by) # EB

    # Labels
    $g.DrawString("D", $fontLabel, $brushDark, [float]($dx - 18), [float]($dy - 8))
    $g.DrawString("A", $fontLabel, $brushDark, [float]($ax + 6), [float]($dy - 8))
    $g.DrawString("E", $fontLabel, $brushDark, [float]($ex - 12), [float]($ey + 5))
    $g.DrawString("B", $fontLabel, $brushDark, [float]($bx + 6), [float]($by - 8))
    $g.DrawString("C", $fontLabel, $brushDark, [float]($cx - 16), [float]($cy - 16))

    # Angle x deg at E (inside angle BEA)
    $penArc = New-Object System.Drawing.Pen($cDark, 1.2)
    $g.DrawArc($penArc, [float]($ex - 18), [float]($ey - 18), 36.0, 36.0, 290.0, 70.0)
    $g.DrawString("x°", $fontVal, $brushDark, [float]($ex + 6), [float]($ey - 20))

    # Note
    $note = "Note: Figure not drawn to scale."
    $g.DrawString($note, $fontNote, $brushGray, 70.0, 265.0)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 4. M1 Q22: Dot plot of Capacity (uF)
# ==============================================================================
function Render-M1Q22 {
    $outPath = Join-Path $imgDir "m1_q22_light.png"
    $w = 320; $h = 320
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penAxis = New-Object System.Drawing.Pen($cDark, 1.5)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontVal = New-Object System.Drawing.Font("Arial", 12.0, [System.Drawing.FontStyle]::Regular)
    $fontTitle = New-Object System.Drawing.Font("Arial", 12.0, [System.Drawing.FontStyle]::Regular)

    $baseY = 220.0
    $g.DrawLine($penAxis, 25.0, [float]$baseY, 295.0, [float]$baseY)

    # Categories: 2, 5, 8, 11, 14
    $cats = @(
        @{ val = 2;  count = 7; x = 55.0 },
        @{ val = 5;  count = 6; x = 105.0 },
        @{ val = 8;  count = 4; x = 155.0 },
        @{ val = 11; count = 6; x = 205.0 },
        @{ val = 14; count = 7; x = 255.0 }
    )

    $dotSpacing = 22.0
    $dotR = 5.0

    foreach ($c in $cats) {
        # Tick mark
        $g.DrawLine($penAxis, [float]$c.x, [float]($baseY - 5), [float]$c.x, [float]($baseY + 5))
        # Label
        $lbl = "$($c.val)"
        $sw = $g.MeasureString($lbl, $fontVal).Width
        $g.DrawString($lbl, $fontVal, $brushDark, [float]($c.x - $sw / 2), [float]($baseY + 8))

        # Dots
        for ($i = 0; $i -lt $c.count; $i++) {
            $dy = $baseY - 18.0 - ($i * $dotSpacing)
            $g.FillEllipse($brushDark, [float]($c.x - $dotR), [float]($dy - $dotR), [float]($dotR * 2), [float]($dotR * 2))
        }
    }

    # Axis Title
    $title = "Capacity (μF)"
    $tw = $g.MeasureString($title, $fontTitle).Width
    $g.DrawString($title, $fontTitle, $brushDark, [float]((320 - $tw) / 2), 265.0)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 5. M2 Q1: Bar chart of flower types
# ==============================================================================
function Render-M2Q1 {
    $outPath = Join-Path $imgDir "m2_q1_light.png"
    $w = 360; $h = 340
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.5)
    $penBar = New-Object System.Drawing.Pen($cDark, 1.2)
    $brushBar = New-Object System.Drawing.SolidBrush($cBarFill)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushGray = New-Object System.Drawing.SolidBrush($cGray)
    $fontAxis = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)
    $fontTitle = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Regular)

    $leftX = 75.0
    $rightX = 335.0
    $baseY = 240.0
    $topY = 40.0

    # Grid lines and Y labels (0 to 200, step 20)
    for ($val = 0; $val -le 200; $val += 20) {
        $py = $baseY - ($val / 200.0) * ($baseY - $topY)
        $g.DrawLine($penGrid, [float]$leftX, [float]$py, [float]$rightX, [float]$py)
        $lbl = "$val"
        $sw = $g.MeasureString($lbl, $fontAxis).Width
        $g.DrawString($lbl, $fontAxis, $brushDark, [float]($leftX - $sw - 5), [float]($py - 6))
    }

    # Axes
    $g.DrawLine($penAxis, [float]$leftX, [float]$baseY, [float]$rightX, [float]$baseY)
    $g.DrawLine($penAxis, [float]$leftX, [float]$baseY, [float]$leftX, [float]$topY)

    # Bars: daisy (60), orchid (100), tulip (190), lily (180), sunflower (170)
    $bars = @(
        @{ name = "daisy"; val = 60 },
        @{ name = "orchid"; val = 100 },
        @{ name = "tulip"; val = 190 },
        @{ name = "lily"; val = 180 },
        @{ name = "sunflower"; val = 170 }
    )

    $barW = 34.0
    $spacing = 16.0
    $startX = $leftX + 15.0

    for ($i = 0; $i -lt $bars.Count; $i++) {
        $b = $bars[$i]
        $bx = $startX + $i * ($barW + $spacing)
        $bh = ($b.val / 200.0) * ($baseY - $topY)
        $by = $baseY - $bh

        $g.FillRectangle($brushBar, [float]$bx, [float]$by, [float]$barW, [float]$bh)
        $g.DrawRectangle($penBar, [float]$bx, [float]$by, [float]$barW, [float]$bh)

        # Label rotated or angled
        $state = $g.Save()
        $g.TranslateTransform([float]($bx + $barW / 2), [float]($baseY + 8))
        $g.RotateTransform(40.0)
        $g.DrawString($b.name, $fontLabel, $brushDark, 0.0, 0.0)
        $g.Restore($state)
    }

    # Y-axis title
    $stateY = $g.Save()
    $g.TranslateTransform(18.0, 140.0)
    $g.RotateTransform(-90.0)
    $yTitle = "Number of flowers"
    $g.DrawString($yTitle, $fontTitle, $brushDark, 0.0, 0.0)
    $g.Restore($stateY)

    # X-axis title
    $xTitle = "Type of flower"
    $tw = $g.MeasureString($xTitle, $fontTitle).Width
    $g.DrawString($xTitle, $fontTitle, $brushDark, [float](($leftX + $rightX - $tw) / 2), 312.0)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 6. M2 Q2: Scatterplot with line of best fit
# ==============================================================================
function Render-M2Q2 {
    $outPath = Join-Path $imgDir "m2_q2_light.png"
    $w = 340; $h = 340
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.5)
    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushPoint = New-Object System.Drawing.SolidBrush($cBlue)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Italic)

    $ox = 45.0
    $oy = 285.0
    $scaleX = 5.6   # 0 to 45 = 252px
    $scaleY = 4.2   # 0 to 60 = 252px

    # Grid
    for ($x = 0; $x -le 45; $x += 5) {
        $px = $ox + $x * $scaleX
        $g.DrawLine($penGrid, [float]$px, 20.0, [float]$px, [float]$oy)
    }
    for ($y = 0; $y -le 60; $y += 5) {
        $py = $oy - $y * $scaleY
        $g.DrawLine($penGrid, [float]$ox, [float]$py, 310.0, [float]$py)
    }

    # Axes
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, 315.0, [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, 15.0)

    # Labels
    $g.DrawString("x", $fontLabel, $brushDark, 318.0, [float]($oy - 8))
    $g.DrawString("y", $fontLabel, $brushDark, [float]($ox - 6), 2.0)
    $g.DrawString("O", $fontAxis, $brushDark, [float]($ox - 14), [float]($oy + 2))

    # Ticks
    foreach ($x in @(15, 30, 45)) {
        $px = $ox + $x * $scaleX
        $g.DrawString("$x", $fontAxis, $brushDark, [float]($px - 8), [float]($oy + 4))
    }
    foreach ($y in @(15, 30, 45, 60)) {
        $py = $oy - $y * $scaleY
        $g.DrawString("$y", $fontAxis, $brushDark, [float]($ox - 22), [float]($py - 6))
    }

    # Line of best fit: roughly y = -0.85x + 53.75 -> from x = 10 (y = 45.25) to x = 40 (y = 19.75)
    $lx1 = $ox + 10.0 * $scaleX; $ly1 = $oy - 46.5 * $scaleY
    $lx2 = $ox + 41.0 * $scaleX; $ly2 = $oy - 19.5 * $scaleY
    $g.DrawLine($penLine, [float]$lx1, [float]$ly1, [float]$lx2, [float]$ly2)

    # Data points
    $pts = @(
        @(11.5, 45.0), @(13.0, 45.5), @(14.5, 43.5), @(15.5, 38.0), @(16.0, 40.5),
        @(22.5, 34.0), @(26.0, 29.5), @(30.0, 29.5), @(32.0, 25.0), @(34.0, 25.0),
        @(36.0, 28.0), @(38.5, 20.5)
    )
    foreach ($p in $pts) {
        $px = $ox + $p[0] * $scaleX
        $py = $oy - $p[1] * $scaleY
        $g.FillEllipse($brushPoint, [float]($px - 3.5), [float]($py - 3.5), 7.0, 7.0)
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 7. M2 Q6: Graph of y = f(x) - 9 = -5x - 1
# ==============================================================================
function Render-M2Q6 {
    $outPath = Join-Path $imgDir "m2_q6_light.png"
    $w = 340; $h = 340
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.5)
    $penLine = New-Object System.Drawing.Pen($cBlue, 2.4)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Italic)

    $ox = 170.0
    $oy = 170.0
    $scaleX = 32.0  # -4 to 4
    $scaleY = 22.0  # -6 to 6

    # Grid
    for ($x = -4; $x -le 4; $x++) {
        $px = $ox + $x * $scaleX
        $g.DrawLine($penGrid, [float]$px, 20.0, [float]$px, 320.0)
    }
    for ($y = -6; $y -le 6; $y++) {
        $py = $oy - $y * $scaleY
        $g.DrawLine($penGrid, 25.0, [float]$py, 315.0, [float]$py)
    }

    # Axes
    $g.DrawLine($penAxis, 20.0, [float]$oy, 325.0, [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, 325.0, [float]$ox, 15.0)

    # Arrows
    $g.DrawLine($penAxis, 325.0, [float]$oy, 319.0, [float]($oy - 3))
    $g.DrawLine($penAxis, 325.0, [float]$oy, 319.0, [float]($oy + 3))
    $g.DrawLine($penAxis, [float]$ox, 15.0, [float]($ox - 3), 21.0)
    $g.DrawLine($penAxis, [float]$ox, 15.0, [float]($ox + 3), 21.0)

    $g.DrawString("x", $fontLabel, $brushDark, 328.0, [float]($oy - 8))
    $g.DrawString("y", $fontLabel, $brushDark, [float]($ox - 6), 2.0)
    $g.DrawString("O", $fontAxis, $brushDark, [float]($ox - 13), [float]($oy + 2))

    # Ticks & labels
    for ($x = -4; $x -le 4; $x++) {
        if ($x -ne 0) {
            $px = $ox + $x * $scaleX
            $g.DrawString("$x", $fontAxis, $brushDark, [float]($px - 6), [float]($oy + 3))
        }
    }
    for ($y = -6; $y -le 6; $y++) {
        if ($y -ne 0) {
            $py = $oy - $y * $scaleY
            $g.DrawString("$y", $fontAxis, $brushDark, [float]($ox - 16), [float]($py - 6))
        }
    }

    # Line: y = -5x - 1
    # at y = 6 -> x = -7/5 = -1.4
    # at y = -6 -> x = 1
    $p1x = $ox + (-1.4) * $scaleX; $p1y = $oy - 6.0 * $scaleY
    $p2x = $ox + 1.0 * $scaleX;    $p2y = $oy - (-6.0) * $scaleY
    $g.DrawLine($penLine, [float]$p1x, [float]$p1y, [float]$p2x, [float]$p2y)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 8. M2 Q10: Right triangle with legs/hypotenuse (63 and 73)
# ==============================================================================
function Render-M2Q10 {
    $outPath = Join-Path $imgDir "m2_q10_light.png"
    $w = 340; $h = 300
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $penArc = New-Object System.Drawing.Pen($cDark, 1.2)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushGray = New-Object System.Drawing.SolidBrush($cGray)
    $fontVal = New-Object System.Drawing.Font("Arial", 12.0, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Italic)

    # Vertices
    $vx = 45.0;  $vy = 30.0   # top
    $blx = 45.0; $bly = 230.0  # bottom left
    $brx = 295.0; $bry = 230.0 # bottom right

    $g.DrawLine($penLine, [float]$blx, [float]$bly, [float]$brx, [float]$bry)
    $g.DrawLine($penLine, [float]$blx, [float]$bly, [float]$vx, [float]$vy)
    $g.DrawLine($penLine, [float]$vx, [float]$vy, [float]$brx, [float]$bry)

    # Right angle square at bottom left
    $sq = 14.0
    $g.DrawRectangle($penLine, [float]$blx, [float]($bly - $sq), [float]$sq, [float]$sq)

    # Angle x deg at top
    $g.DrawArc($penArc, [float]($vx - 22), [float]($vy - 22), 44.0, 44.0, 38.0, 52.0)
    $g.DrawString("x°", $fontVal, $brushDark, [float]($vx + 6), [float]($vy + 26))

    # Side length 63
    $g.DrawString("63", $fontVal, $brushDark, 160.0, 235.0)

    # Hypotenuse 73
    $g.DrawString("73", $fontVal, $brushDark, 180.0, 115.0)

    # Note
    $note = "Note: Figure not drawn to scale."
    $g.DrawString($note, $fontNote, $brushGray, 70.0, 270.0)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 9. M2 Q17: Semicircle on top of rectangle SNQR
# ==============================================================================
function Render-M2Q17 {
    $outPath = Join-Path $imgDir "m2_q17_light.png"
    $w = 380; $h = 240
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushGray = New-Object System.Drawing.SolidBrush($cGray)
    $brushWhite = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $fontLabel = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Italic)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Italic)

    # Rectangle dimensions
    $sx = 45.0;  $sy = 175.0
    $nx = 45.0;  $ny = 95.0
    $qx = 335.0; $qy = 95.0
    $rx = 335.0; $ry = 175.0
    $px = 190.0; $py = 95.0
    $ox = 117.5; $oy = 95.0
    $r = 72.5

    # Draw rectangle lines
    $g.DrawLine($penLine, [float]$sx, [float]$sy, [float]$rx, [float]$ry) # SR
    $g.DrawLine($penLine, [float]$sx, [float]$sy, [float]$nx, [float]$ny) # SN
    $g.DrawLine($penLine, [float]$rx, [float]$ry, [float]$qx, [float]$qy) # RQ
    $g.DrawLine($penLine, [float]$nx, [float]$ny, [float]$qx, [float]$qy) # NQ

    # Draw semicircle over NP
    $g.DrawArc($penLine, [float]($ox - $r), [float]($oy - $r), [float]($r * 2), [float]($r * 2), 180.0, 180.0)

    # Center O point
    $g.FillEllipse($brushDark, [float]($ox - 3.5), [float]($oy - 3.5), 7.0, 7.0)
    $g.FillEllipse($brushWhite, [float]($ox - 1.5), [float]($oy - 1.5), 3.0, 3.0)

    # Right angle squares at Q, R, S
    $sq = 12.0
    $g.DrawRectangle($penLine, [float]$sx, [float]($sy - $sq), [float]$sq, [float]$sq)
    $g.DrawRectangle($penLine, [float]($rx - $sq), [float]($ry - $sq), [float]$sq, [float]$sq)
    $g.DrawRectangle($penLine, [float]($qx - $sq), [float]$qy, [float]$sq, [float]$sq)

    # Labels N, O, P, Q, R, S
    $g.DrawString("N", $fontLabel, $brushDark, [float]($nx - 18), [float]($ny - 8))
    $g.DrawString("O", $fontLabel, $brushDark, [float]($ox - 5), [float]($oy + 6))
    $g.DrawString("P", $fontLabel, $brushDark, [float]($px - 5), [float]($py + 6))
    $g.DrawString("Q", $fontLabel, $brushDark, [float]($qx + 6), [float]($qy - 8))
    $g.DrawString("R", $fontLabel, $brushDark, [float]($rx + 6), [float]($ry - 8))
    $g.DrawString("S", $fontLabel, $brushDark, [float]($sx - 16), [float]($sy - 8))

    # Note
    $note = "Note: Figure not drawn to scale."
    $g.DrawString($note, $fontNote, $brushGray, 90.0, 205.0)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# Run all renders
Render-M1Q15
Render-M1Q17
Render-M1Q19
Render-M1Q22
Render-M2Q1
Render-M2Q2
Render-M2Q6
Render-M2Q10
Render-M2Q17
