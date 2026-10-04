Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "may2025_int1_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42) # Slate 900
$cGray = [System.Drawing.Color]::FromArgb(100, 116, 139) # Slate 500
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240) # Slate 200
$cAxis = [System.Drawing.Color]::FromArgb(71, 85, 105) # Slate 600
$cBlue = [System.Drawing.Color]::FromArgb(37, 99, 235) # Blue 600
$cBarFill = [System.Drawing.Color]::FromArgb(148, 163, 184) # Slate 400
$cShade = [System.Drawing.Color]::FromArgb(50, 37, 99, 235) # Translucent blue

# ==============================================================================
# 1. M1 Q9: Linear inequality y > 3x + 7
# ==============================================================================
function Render-M1Q9 {
    $outPath = Join-Path $imgDir "m1_q9_light.png"
    $w = 340; $h = 340
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.5)
    $penDashed = New-Object System.Drawing.Pen($cDark, 2.0)
    $penDashed.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $brushShade = New-Object System.Drawing.SolidBrush($cShade)
    $fontAxis = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)

    $ox = 200.0
    $oy = 290.0
    $scaleX = 26.0  # -6 to 4 = 10 units = 260px
    $scaleY = 18.0  # -1 to 14 = 15 units = 270px

    # Grid
    for ($x = -6; $x -le 4; $x += 2) {
        $px = $ox + $x * $scaleX
        $g.DrawLine($penGrid, [float]$px, 20.0, [float]$px, [float]$oy)
    }
    for ($y = 0; $y -le 14; $y += 2) {
        $py = $oy - $y * $scaleY
        $g.DrawLine($penGrid, [float]($ox - 6 * $scaleX), [float]$py, [float]($ox + 4 * $scaleX), [float]$py)
    }

    # Axes
    $g.DrawLine($penAxis, [float]($ox - 6 * $scaleX), [float]$oy, [float]($ox + 4 * $scaleX + 15), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, 15.0)

    # Labels
    for ($x = -6; $x -le 4; $x += 2) {
        $px = $ox + $x * $scaleX
        $lbl = "$x"
        $sw = $g.MeasureString($lbl, $fontAxis).Width
        $g.DrawString($lbl, $fontAxis, $brushDark, [float]($px - $sw / 2), [float]($oy + 4))
    }
    for ($y = 2; $y -le 14; $y += 2) {
        $py = $oy - $y * $scaleY
        $lbl = "$y"
        $sw = $g.MeasureString($lbl, $fontAxis).Width
        $g.DrawString($lbl, $fontAxis, $brushDark, [float]($ox - 6 * $scaleX - $sw - 4), [float]($py - 6))
    }

    # Shaded polygon: above y = 3x + 7
    # Boundary points: at top y = 14: x = (14-7)/3 = 7/3 = 2.333
    # At left x = -6: y = 3(-6)+7 = -11 -> enters bottom at y = -1: x = (-1-7)/3 = -8/3 = -2.667
    $poly = @(
        (New-Object System.Drawing.PointF([float]($ox - 6 * $scaleX), 20.0)),
        (New-Object System.Drawing.PointF([float]($ox + 2.333 * $scaleX), 20.0)),
        (New-Object System.Drawing.PointF([float]($ox - 2.667 * $scaleX), [float]($oy - (-1) * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox - 6 * $scaleX), [float]($oy - (-1) * $scaleY)))
    )
    $g.FillPolygon($brushShade, $poly)

    # Dashed boundary line: from (2.333, 14) to (-2.667, -1)
    $p1x = $ox + 2.333 * $scaleX; $p1y = $oy - 14.0 * $scaleY
    $p2x = $ox - 2.667 * $scaleX; $p2y = $oy - (-1.0) * $scaleY
    $g.DrawLine($penDashed, [float]$p1x, [float]$p1y, [float]$p2x, [float]$p2y)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 2. M1 Q15: Histograms Team A and Team B
# ==============================================================================
function Render-M1Q15 {
    $outPath = Join-Path $imgDir "m1_q15_light.png"
    $w = 340; $h = 420
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
    $fontAxis = New-Object System.Drawing.Font("Arial", 8.0, [System.Drawing.FontStyle]::Regular)
    $fontTitle = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Bold)
    $fontLabel = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)

    function Draw-Histo($title, $topY, $baseY, $data) {
        $leftX = 45.0
        $rightX = 315.0

        # Title
        $tw = $g.MeasureString($title, $fontTitle).Width
        $g.DrawString($title, $fontTitle, $brushDark, [float](($leftX + $rightX - $tw) / 2), [float]($topY - 22))

        # Y grid & ticks (0 to 50, step 10)
        for ($v = 0; $v -le 50; $v += 10) {
            $py = $baseY - ($v / 50.0) * ($baseY - $topY)
            $g.DrawLine($penGrid, [float]$leftX, [float]$py, [float]$rightX, [float]$py)
            $lbl = "$v"
            $sw = $g.MeasureString($lbl, $fontAxis).Width
            $g.DrawString($lbl, $fontAxis, $brushDark, [float]($leftX - $sw - 3), [float]($py - 5))
        }

        # Axes
        $g.DrawLine($penAxis, [float]$leftX, [float]$baseY, [float]$rightX, [float]$baseY)
        $g.DrawLine($penAxis, [float]$leftX, [float]$baseY, [float]$leftX, [float]$topY)

        # X bins: 15-20, 20-25, 25-30, 30-35, 35-40, 40-45, 45-50 (7 bins)
        $binW = ($rightX - $leftX) / 7.0
        for ($i = 0; $i -lt 7; $i++) {
            $bx = $leftX + $i * $binW
            $val = $data[$i]
            if ($val -gt 0) {
                $bh = ($val / 50.0) * ($baseY - $topY)
                $by = $baseY - $bh
                $g.FillRectangle($brushBar, [float]$bx, [float]$by, [float]$binW, [float]$bh)
                $g.DrawRectangle($penBar, [float]$bx, [float]$by, [float]$binW, [float]$bh)
            }
            # X tick
            $tickScore = 15 + $i * 5
            $tlbl = "$tickScore"
            $tsw = $g.MeasureString($tlbl, $fontAxis).Width
            $g.DrawString($tlbl, $fontAxis, $brushDark, [float]($bx - $tsw / 2), [float]($baseY + 3))
        }
        # Last tick (50)
        $g.DrawString("50", $fontAxis, $brushDark, [float]($rightX - 8), [float]($baseY + 3))

        # Y label rotated
        $stateY = $g.Save()
        $g.TranslateTransform(12.0, [float](($baseY + $topY) / 2 + 25))
        $g.RotateTransform(-90.0)
        $g.DrawString("Frequency", $fontLabel, $brushDark, 0.0, 0.0)
        $g.Restore($stateY)

        # X label
        $xlbl = "Score"
        $xsw = $g.MeasureString($xlbl, $fontLabel).Width
        $g.DrawString($xlbl, $fontLabel, $brushDark, [float](($leftX + $rightX - $xsw) / 2), [float]($baseY + 16))
    }

    # Team A: [0, 0, 45, 47, 44, 0, 0]
    Draw-Histo "Team A" 35.0 170.0 @(0, 0, 45, 47, 44, 0, 0)

    # Team B: [31, 22, 12, 2, 12, 22, 31]
    Draw-Histo "Team B" 245.0 380.0 @(31, 22, 12, 2, 12, 22, 31)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 3. M1 Q16: Circle on coordinate plane (center (0, 5), radius 3)
# ==============================================================================
function Render-M1Q16 {
    $outPath = Join-Path $imgDir "m1_q16_light.png"
    $w = 340; $h = 340
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.5)
    $penCircle = New-Object System.Drawing.Pen($cBlue, 2.2)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)

    $ox = 170.0
    $oy = 280.0
    $scaleX = 16.0  # -8 to 8
    $scaleY = 16.0  # -2 to 14

    # Grid
    for ($x = -8; $x -le 8; $x += 2) {
        $px = $ox + $x * $scaleX
        $g.DrawLine($penGrid, [float]$px, 20.0, [float]$px, 310.0)
    }
    for ($y = -2; $y -le 14; $y += 2) {
        $py = $oy - $y * $scaleY
        $g.DrawLine($penGrid, 20.0, [float]$py, 320.0, [float]$py)
    }

    # Axes
    $g.DrawLine($penAxis, 15.0, [float]$oy, 325.0, [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, 315.0, [float]$ox, 15.0)

    # Ticks & labels
    for ($x = -8; $x -le 8; $x += 2) {
        $px = $ox + $x * $scaleX
        $lbl = "$x"
        $sw = $g.MeasureString($lbl, $fontAxis).Width
        $g.DrawString($lbl, $fontAxis, $brushDark, [float]($px - $sw / 2), [float]($oy + 3))
    }
    for ($y = -2; $y -le 14; $y += 2) {
        if ($y -ne 0) {
            $py = $oy - $y * $scaleY
            $lbl = "$y"
            $sw = $g.MeasureString($lbl, $fontAxis).Width
            $g.DrawString($lbl, $fontAxis, $brushDark, [float]($ox - $sw - 3), [float]($py - 5))
        }
    }

    # Circle: center (0, 5), radius 3 -> cx = ox, cy = oy - 5 * scaleY, r = 3 * scaleY
    $cx = $ox
    $cy = $oy - 5.0 * $scaleY
    $cr = 3.0 * $scaleX
    $g.DrawEllipse($penCircle, [float]($cx - $cr), [float]($cy - $cr), [float]($cr * 2), [float]($cr * 2))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 4. M1 Q18: Line graph of total rainfall
# ==============================================================================
function Render-M1Q18 {
    $outPath = Join-Path $imgDir "m1_q18_light.png"
    $w = 340; $h = 320
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cAxis, 1.5)
    $penLine = New-Object System.Drawing.Pen($cBlue, 2.4)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Regular)

    $ox = 50.0
    $oy = 260.0
    $scaleX = 25.0  # 0 to 10 hrs = 250px
    $scaleY = 27.0  # 0 to 8 cm = 216px

    # Grid
    for ($x = 0; $x -le 10; $x += 2) {
        $px = $ox + $x * $scaleX
        $g.DrawLine($penGrid, [float]$px, 35.0, [float]$px, [float]$oy)
    }
    for ($y = 0; $y -le 8; $y++) {
        $py = $oy - $y * $scaleY
        $g.DrawLine($penGrid, [float]$ox, [float]$py, 310.0, [float]$py)
    }

    # Axes
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, 315.0, [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, 30.0)

    # Labels
    for ($x = 0; $x -le 10; $x += 2) {
        $px = $ox + $x * $scaleX
        $lbl = "$x"
        $sw = $g.MeasureString($lbl, $fontAxis).Width
        $g.DrawString($lbl, $fontAxis, $brushDark, [float]($px - $sw / 2), [float]($oy + 4))
    }
    for ($y = 0; $y -le 8; $y++) {
        $py = $oy - $y * $scaleY
        $lbl = "$y"
        $sw = $g.MeasureString($lbl, $fontAxis).Width
        $g.DrawString($lbl, $fontAxis, $brushDark, [float]($ox - $sw - 4), [float]($py - 5))
    }

    # Line graph: (0, 0) -> (2, 2) -> (4, 2) -> (10, 2.7)
    $pts = @(
        (New-Object System.Drawing.PointF([float]$ox, [float]$oy)),
        (New-Object System.Drawing.PointF([float]($ox + 2.0 * $scaleX), [float]($oy - 2.0 * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox + 4.0 * $scaleX), [float]($oy - 2.0 * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox + 10.0 * $scaleX), [float]($oy - 2.7 * $scaleY)))
    )
    $g.DrawLines($penLine, $pts)

    # Y label rotated
    $stateY = $g.Save()
    $g.TranslateTransform(14.0, 190.0)
    $g.RotateTransform(-90.0)
    $g.DrawString("Total rainfall (centimeters)", $fontLabel, $brushDark, 0.0, 0.0)
    $g.Restore($stateY)

    # X label
    $xlbl = "Time (hours)"
    $xsw = $g.MeasureString($xlbl, $fontLabel).Width
    $g.DrawString($xlbl, $fontLabel, $brushDark, [float](($ox + 310.0 - $xsw) / 2), [float]($oy + 20))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 5. M2 Q2: Parallel lines l and m with transversal k (x deg and 111 deg)
# ==============================================================================
function Render-M2Q2 {
    $outPath = Join-Path $imgDir "m2_q2_light.png"
    $w = 340; $h = 300
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontLabel = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Regular)

    $ly = 100.0
    $my = 220.0

    # Horizontal lines l and m
    $g.DrawLine($penLine, 40.0, [float]$ly, 280.0, [float]$ly)
    $g.DrawLine($penLine, 40.0, [float]$my, 280.0, [float]$my)

    # Transversal line k
    $g.DrawLine($penLine, 75.0, 45.0, 245.0, 275.0)

    # Intersection points
    # line l at y = 100: x = 75 + (100-45)*(245-75)/(275-45) = 75 + 55*(170)/230 = 75 + 40.65 = 115.65
    # line m at y = 220: x = 75 + (220-45)*(170)/230 = 75 + 175*170/230 = 75 + 129.35 = 204.35
    $ix_l = 115.65
    $ix_m = 204.35

    # Labels l, m, k
    $g.DrawString("l", $fontLabel, $brushDark, 285.0, [float]($ly - 8))
    $g.DrawString("m", $fontLabel, $brushDark, 285.0, [float]($my - 8))
    $g.DrawString("k", $fontLabel, $brushDark, 55.0, 35.0)

    # Angle x deg at l (top-right obtuse angle)
    $penArc = New-Object System.Drawing.Pen($cDark, 1.2)
    $g.DrawArc($penArc, [float]($ix_l - 22), [float]($ly - 22), 44.0, 44.0, 235.0, 125.0)
    $g.DrawString("x°", $fontVal, $brushDark, [float]($ix_l + 14), [float]($ly - 22))

    # Angle 111 deg at m (bottom-left obtuse angle)
    $g.DrawArc($penArc, [float]($ix_m - 22), [float]($my - 22), 44.0, 44.0, 55.0, 125.0)
    $g.DrawString("111°", $fontVal, $brushDark, [float]($ix_m - 46), [float]($my + 6))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 6. M2 Q3: Graph of y = -3/7 x - 5
# ==============================================================================
function Render-M2Q3 {
    $outPath = Join-Path $imgDir "m2_q3_light.png"
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
    $brushWhite = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.0, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 10.0, [System.Drawing.FontStyle]::Italic)

    $ox = 45.0
    $oy = 55.0
    $scaleX = 26.0  # 0 to 10
    $scaleY = 26.0  # 0 to -10

    # Grid
    for ($x = 0; $x -le 10; $x++) {
        $px = $ox + $x * $scaleX
        $g.DrawLine($penGrid, [float]$px, 25.0, [float]$px, 325.0)
    }
    for ($y = 0; $y -le 10; $y++) {
        $py = $oy + $y * $scaleY
        $g.DrawLine($penGrid, 25.0, [float]$py, 320.0, [float]$py)
    }

    # Axes
    $g.DrawLine($penAxis, 20.0, [float]$oy, 325.0, [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, 25.0, [float]$ox, 325.0)

    # Arrows
    $g.DrawLine($penAxis, 325.0, [float]$oy, 319.0, [float]($oy - 3))
    $g.DrawLine($penAxis, 325.0, [float]$oy, 319.0, [float]($oy + 3))
    $g.DrawString("x", $fontLabel, $brushDark, 328.0, [float]($oy - 8))
    $g.DrawString("y", $fontLabel, $brushDark, [float]($ox - 6), 8.0)
    $g.DrawString("O", $fontAxis, $brushDark, [float]($ox - 14), [float]($oy - 14))

    # Ticks
    for ($x = 2; $x -le 10; $x += 2) {
        $px = $ox + $x * $scaleX
        $g.DrawString("$x", $fontAxis, $brushDark, [float]($px - 5), [float]($oy - 16))
    }
    for ($y = 2; $y -le 10; $y += 2) {
        $py = $oy + $y * $scaleY
        $g.DrawString("-$y", $fontAxis, $brushDark, [float]($ox - 22), [float]($py - 6))
    }

    # Line: y = -3/7 x - 5 -> passes through (0, -5) and (7, -8)
    $lx1 = $ox + (-0.8) * $scaleX; $ly1 = $oy - (-4.65) * $scaleY
    $lx2 = $ox + 10.5 * $scaleX;   $ly2 = $oy - (-9.5) * $scaleY
    $g.DrawLine($penLine, [float]$lx1, [float]$ly1, [float]$lx2, [float]$ly2)

    # Key points: (0, -5) and (7, -8)
    $pts = @(
        (New-Object System.Drawing.PointF([float]$ox, [float]($oy + 5.0 * $scaleY))),
        (New-Object System.Drawing.PointF([float]($ox + 7.0 * $scaleX), [float]($oy + 8.0 * $scaleY)))
    )
    foreach ($p in $pts) {
        $g.FillEllipse($brushDark, [float]($p.X - 4.5), [float]($p.Y - 4.5), 9.0, 9.0)
        $g.FillEllipse($brushWhite, [float]($p.X - 2.5), [float]($p.Y - 2.5), 5.0, 5.0)
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 7. M2 Q4: Line graph of Melting temperature vs GC content
# ==============================================================================
function Render-M2Q4 {
    $outPath = Join-Path $imgDir "m2_q4_light.png"
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
    $fontAxis = New-Object System.Drawing.Font("Arial", 8.5, [System.Drawing.FontStyle]::Regular)
    $fontLabel = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Regular)

    $ox = 60.0
    $oy = 280.0
    $scaleX = 2.4   # 0 to 100% = 240px
    $scaleY = 4.6   # 60 to 110 deg C = 50 * 4.6 = 230px

    # Grid
    for ($x = 0; $x -le 100; $x += 10) {
        $px = $ox + $x * $scaleX
        $g.DrawLine($penGrid, [float]$px, 45.0, [float]$px, [float]$oy)
    }
    for ($y = 60; $y -le 110; $y += 5) {
        $py = $oy - ($y - 60) * $scaleY
        $g.DrawLine($penGrid, [float]$ox, [float]$py, 310.0, [float]$py)
    }

    # Axes
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, 315.0, [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, 35.0)

    # Ticks & labels
    for ($x = 0; $x -le 100; $x += 20) {
        $px = $ox + $x * $scaleX
        $lbl = "$x"
        $sw = $g.MeasureString($lbl, $fontAxis).Width
        $g.DrawString($lbl, $fontAxis, $brushDark, [float]($px - $sw / 2), [float]($oy + 4))
    }
    for ($y = 60; $y -le 110; $y += 10) {
        $py = $oy - ($y - 60) * $scaleY
        $lbl = "$y"
        $sw = $g.MeasureString($lbl, $fontAxis).Width
        $g.DrawString($lbl, $fontAxis, $brushDark, [float]($ox - $sw - 4), [float]($py - 5))
    }

    # Line: from (0, 64) to (100, 105)
    $p1x = $ox; $p1y = $oy - (64.0 - 60.0) * $scaleY
    $p2x = $ox + 100.0 * $scaleX; $p2y = $oy - (105.0 - 60.0) * $scaleY
    $g.DrawLine($penLine, [float]$p1x, [float]$p1y, [float]$p2x, [float]$p2y)

    # Y label rotated
    $stateY = $g.Save()
    $g.TranslateTransform(16.0, 220.0)
    $g.RotateTransform(-90.0)
    $g.DrawString("Melting temperature (°C)", $fontLabel, $brushDark, 0.0, 0.0)
    $g.Restore($stateY)

    # X label
    $xlbl = "GC content (%)"
    $xsw = $g.MeasureString($xlbl, $fontLabel).Width
    $g.DrawString($xlbl, $fontLabel, $brushDark, [float](($ox + 310.0 - $xsw) / 2), [float]($oy + 20))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# ==============================================================================
# 8. M2 Q10: Right rectangular pyramid
# ==============================================================================
function Render-M2Q10 {
    $outPath = Join-Path $imgDir "m2_q10_light.png"
    $w = 340; $h = 320
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penSolid = New-Object System.Drawing.Pen($cDark, 2.0)
    $penDash = New-Object System.Drawing.Pen($cDark, 1.4)
    $penDash.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontVal = New-Object System.Drawing.Font("Arial", 12.0, [System.Drawing.FontStyle]::Italic)

    # Vertices
    $apex = New-Object System.Drawing.PointF(205.0, 30.0)
    $frontLeft = New-Object System.Drawing.PointF(105.0, 175.0)
    $frontCenter = New-Object System.Drawing.PointF(175.0, 280.0)
    $frontRight = New-Object System.Drawing.PointF(215.0, 240.0)
    $backCenter = New-Object System.Drawing.PointF(150.0, 140.0)
    $baseCenter = New-Object System.Drawing.PointF(160.0, 205.0)

    # Dashed edges (hidden rear base and edges)
    $g.DrawLine($penDash, $frontLeft, $backCenter)
    $g.DrawLine($penDash, $backCenter, $frontRight)
    $g.DrawLine($penDash, $apex, $backCenter)

    # Height line (from apex down to base center)
    $g.DrawLine($penDash, $apex, $baseCenter)

    # Solid edges (front base and visible edges)
    $g.DrawLine($penSolid, $frontLeft, $frontCenter)
    $g.DrawLine($penSolid, $frontCenter, $frontRight)
    $g.DrawLine($penSolid, $apex, $frontLeft)
    $g.DrawLine($penSolid, $apex, $frontCenter)
    $g.DrawLine($penSolid, $apex, $frontRight)

    # Right angle marker at base center
    $g.DrawLine($penSolid, 160.0, 195.0, 153.0, 200.0)
    $g.DrawLine($penSolid, 153.0, 200.0, 153.0, 210.0)

    # Labels
    $g.DrawString("l", $fontVal, $brushDark, 125.0, 235.0)
    $g.DrawString("w", $fontVal, $brushDark, 200.0, 265.0)
    $g.DrawString("h", $fontVal, $brushDark, 170.0, 125.0)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Rendered $outPath"
}

# Run all renders
Render-M1Q9
Render-M1Q15
Render-M1Q16
Render-M1Q18
Render-M2Q2
Render-M2Q3
Render-M2Q4
Render-M2Q10
