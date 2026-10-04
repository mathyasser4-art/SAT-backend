Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "nov2025_int1_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)
$cGrid = [System.Drawing.Color]::FromArgb(226, 232, 240)
$cLine = [System.Drawing.Color]::FromArgb(37, 99, 235)

# ==============================================================================
# 1. M1 Q2: Parallel Lines p and r with Transversal t
# ==============================================================================
function Render-M1-Q2 {
    $outPath = Join-Path $imgDir "m1_q2_light.png"
    $w = 380; $h = 340
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.0)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontDeg = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 11, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Horizontal lines p and r
    $yP = 120.0; $yR = 210.0
    $g.DrawLine($pen, 30.0, [float]$yP, 330.0, [float]$yP)
    $g.DrawLine($pen, 30.0, [float]$yR, 330.0, [float]$yR)

    # Transversal t: from (40, 35) to (300, 295)
    $x1 = 40.0; $y1 = 35.0
    $x2 = 300.0; $y2 = 295.0
    $g.DrawLine($pen, [float]$x1, [float]$y1, [float]$x2, [float]$y2)

    # Intersections:
    # slope = 260 / 260 = 1.0
    # at yP = 120: xP = 40 + (120 - 35) = 125.0
    # at yR = 210: xR = 40 + (210 - 35) = 215.0
    $xP = 125.0; $xR = 215.0

    $deg = [char]176
    # x deg is top-left at line p
    $g.DrawString("x$deg", $fontDeg, $brush, [float]($xP - 32), [float]($yP - 22))

    # 72 deg is bottom-right at line p
    $g.DrawString("72$deg", $fontDeg, $brush, [float]($xP + 12), [float]($yP + 6))

    # Line labels
    $g.DrawString("t", $fontV, $brush, [float]($x1 - 4), [float]($y1 - 22))
    $g.DrawString("p", $fontV, $brush, 342.0, [float]($yP - 10))
    $g.DrawString("r", $fontV, $brush, 342.0, [float]($yR - 10))

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, [float]($w / 2), [float]($h - 22), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 2. M1 Q11: Cubic Polynomial Curve
# ==============================================================================
function Render-M1-Q11 {
    $outPath = Join-Path $imgDir "m1_q11_light.png"
    $w = 440; $h = 440
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penCurve = New-Object System.Drawing.Pen($cLine, 2.4)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontAxis = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Regular)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 12, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center
    $sfR = New-Object System.Drawing.StringFormat
    $sfR.Alignment = [System.Drawing.StringAlignment]::Far

    # Origin and step:
    # x in [-6, 6], y in [-8, 8]
    $ox = 220.0; $oy = 220.0
    $stepX = 26.0 # 6 * 26 = 156
    $stepY = 21.0 # 8 * 21 = 168

    # Grid
    for ($i = -6; $i -le 6; $i++) {
        $x = $ox + $i * $stepX
        $g.DrawLine($penGrid, [float]$x, [float]($oy - 8 * $stepY), [float]$x, [float]($oy + 8 * $stepY))
    }
    for ($j = -8; $j -le 8; $j++) {
        $y = $oy + $j * $stepY
        $g.DrawLine($penGrid, [float]($ox - 6 * $stepX), [float]$y, [float]($ox + 6 * $stepX), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]($ox - 6 * $stepX - 15), [float]$oy, [float]($ox + 6 * $stepX + 15), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]($oy + 8 * $stepY + 15), [float]$ox, [float]($oy - 8 * $stepY - 15))

    # Arrowheads
    $g.DrawLine($penAxis, [float]($ox + 6 * $stepX + 15), [float]$oy, [float]($ox + 6 * $stepX + 8), [float]($oy - 4))
    $g.DrawLine($penAxis, [float]($ox + 6 * $stepX + 15), [float]$oy, [float]($ox + 6 * $stepX + 8), [float]($oy + 4))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - 8 * $stepY - 15), [float]($ox - 4), [float]($oy - 8 * $stepY - 8))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - 8 * $stepY - 15), [float]($ox + 4), [float]($oy - 8 * $stepY - 8))

    # Ticks & labels
    $g.DrawString("O", $fontV, $brush, [float]($ox - 14), [float]($oy + 2))
    $g.DrawString("x", $fontV, $brush, [float]($ox + 6 * $stepX + 18), [float]($oy - 8))
    $g.DrawString("y", $fontV, $brush, [float]($ox - 8), [float]($oy - 8 * $stepY - 26))

    for ($i = -6; $i -le 6; $i += 2) {
        if ($i -ne 0) {
            $x = $ox + $i * $stepX
            $g.DrawString("$i", $fontAxis, $brush, [float]$x, [float]($oy + 4), $sfC)
        }
    }
    for ($j = -8; $j -le 8; $j += 2) {
        if ($j -ne 0) {
            $y = $oy - $j * $stepY
            $g.DrawString("$j", $fontAxis, $brush, [float]($ox - 4), [float]($y - 7), $sfR)
        }
    }

    # Plot cubic curve passing through roots x = -4, 0, 2
    # f(x) = -0.34 * x * (x + 4) * (x - 2)
    $pts = New-Object System.Collections.Generic.List[System.Drawing.PointF]
    for ($t = -4.8; $t -le 3.2; $t += 0.05) {
        $yVal = -0.34 * $t * ($t + 4.0) * ($t - 2.0)
        if ($yVal -ge -8.5 -and $yVal -le 8.5) {
            $px = $ox + $t * $stepX
            $py = $oy - $yVal * $stepY
            $pts.Add((New-Object System.Drawing.PointF([float]$px, [float]$py)))
        }
    }
    if ($pts.Count -gt 1) {
        $g.DrawCurve($penCurve, $pts.ToArray())
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 3. M1 Q14: Similar Triangles ABC and A'B'C'
# ==============================================================================
function Render-M1-Q14 {
    $outPath = Join-Path $imgDir "m1_q14_light.png"
    $w = 460; $h = 240
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.0)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 11, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Triangle ABC (smaller, left)
    $Ax = 40.0; $Ay = 170.0
    $Cx = 145.0; $Cy = 170.0
    $Bx = 92.5; $By = 80.0

    $pts1 = @(
        (New-Object System.Drawing.PointF($Ax, $Ay)),
        (New-Object System.Drawing.PointF($Bx, $By)),
        (New-Object System.Drawing.PointF($Cx, $Cy))
    )
    $g.DrawPolygon($pen, $pts1)

    $g.DrawString("A", $fontV, $brush, [float]($Ax - 20), [float]($Ay - 6))
    $g.DrawString("C", $fontV, $brush, [float]($Cx + 6), [float]($Cy - 6))
    $g.DrawString("B", $fontV, $brush, [float]($Bx - 6), [float]($By - 24))

    # Triangle A'B'C' (larger, right)
    $Apx = 210.0; $Apy = 170.0
    $Cpx = 390.0; $Cpy = 170.0
    $Bpx = 300.0; $Bpy = 50.0

    $pts2 = @(
        (New-Object System.Drawing.PointF($Apx, $Apy)),
        (New-Object System.Drawing.PointF($Bpx, $Bpy)),
        (New-Object System.Drawing.PointF($Cpx, $Cpy))
    )
    $g.DrawPolygon($pen, $pts2)

    $prime = [char]8242
    $g.DrawString("A$prime", $fontV, $brush, [float]($Apx - 26), [float]($Apy - 6))
    $g.DrawString("C$prime", $fontV, $brush, [float]($Cpx + 6), [float]($Cpy - 6))
    $g.DrawString("B$prime", $fontV, $brush, [float]($Bpx - 8), [float]($Bpy - 24))

    # Note
    $g.DrawString("Note: Figures not drawn to scale.", $fontNote, $brush, [float]($w / 2), [float]($h - 22), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 4. M1 Q20: Right Triangle QRS with side 37
# ==============================================================================
function Render-M1-Q20 {
    $outPath = Join-Path $imgDir "m1_q20_light.png"
    $w = 420; $h = 320
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.0)
    $thinPen = New-Object System.Drawing.Pen($cDark, 1.2)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontNum = New-Object System.Drawing.Font("Arial", 13, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 11, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Coordinates: S bottom-left, R bottom-right, Q top-right
    $Sx = 60.0; $Sy = 240.0
    $Rx = 360.0; $Ry = 240.0
    $Qx = 360.0; $Qy = 45.0

    $pts = @(
        (New-Object System.Drawing.PointF($Sx, $Sy)),
        (New-Object System.Drawing.PointF($Rx, $Ry)),
        (New-Object System.Drawing.PointF($Qx, $Qy))
    )
    $g.DrawPolygon($pen, $pts)

    # Right-angle mark at R
    $sq = 16.0
    $g.DrawRectangle($thinPen, [float]($Rx - $sq), [float]($Ry - $sq), [float]$sq, [float]$sq)

    # Labels
    $g.DrawString("S", $fontV, $brush, [float]($Sx - 20), [float]($Sy - 6))
    $g.DrawString("R", $fontV, $brush, [float]($Rx + 6), [float]($Ry - 6))
    $g.DrawString("Q", $fontV, $brush, [float]($Qx + 6), [float]($Qy - 12))
    $g.DrawString("37", $fontNum, $brush, [float](($Sx + $Rx)/2), [float]($Ry + 8), $sfC)

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, [float]($w / 2), [float]($h - 22), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 5. M2 Q2: Parallel Lines r and s with Transversal k
# ==============================================================================
function Render-M2-Q2 {
    $outPath = Join-Path $imgDir "m2_q2_light.png"
    $w = 380; $h = 380
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen($cDark, 2.0)
    $brush = New-Object System.Drawing.SolidBrush($cDark)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 15, [System.Drawing.FontStyle]::Italic)
    $fontDeg = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 11, [System.Drawing.FontStyle]::Regular)
    $sfC = New-Object System.Drawing.StringFormat
    $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Vertical lines r and s
    $xR = 145.0; $xS = 265.0
    $g.DrawLine($pen, [float]$xR, 45.0, [float]$xR, 325.0)
    $g.DrawLine($pen, [float]$xS, 45.0, [float]$xS, 325.0)

    # Transversal k: from (40, 50) to (350, 310)
    $x1 = 40.0; $y1 = 50.0
    $x2 = 350.0; $y2 = 310.0
    $g.DrawLine($pen, [float]$x1, [float]$y1, [float]$x2, [float]$y2)

    # Intersections
    # slope = 260 / 310 = 0.8387
    $yR = 50 + (145 - 40) * 0.8387 # 138.0
    $yS = 50 + (265 - 40) * 0.8387 # 238.7

    $deg = [char]176
    $g.DrawString("w$deg", $fontDeg, $brush, [float]($xR + 12), [float]($yR - 26))
    $g.DrawString("x$deg", $fontDeg, $brush, [float]($xR - 28), [float]($yR + 14))

    $g.DrawString("y$deg", $fontDeg, $brush, [float]($xS + 12), [float]($yS - 26))
    $g.DrawString("z$deg", $fontDeg, $brush, [float]($xS - 26), [float]($yS + 14))

    # Line labels
    $g.DrawString("k", $fontV, $brush, [float]($x1 - 18), [float]($y1 - 15))
    $g.DrawString("r", $fontV, $brush, [float]($xR - 6), 20.0)
    $g.DrawString("s", $fontV, $brush, [float]($xS - 6), 20.0)

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, [float]($w / 2), [float]($h - 20), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Created $outPath"
}

# ==============================================================================
# 6. M2 Q4: Scatterplot with Line of Best Fit
# ==============================================================================
function Render-M2-Q4 {
    $outPath = Join-Path $imgDir "m2_q4_light.png"
    $w = 460; $h = 420
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penGrid = New-Object System.Drawing.Pen($cGrid, 1.0)
    $penAxis = New-Object System.Drawing.Pen($cDark, 1.8)
    $penFit = New-Object System.Drawing.Pen($cLine, 2.2)
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
    # x in [0, 550], y in [0, 550]
    $ox = 75.0; $oy = 340.0
    $gw = 320.0; $gh = 280.0
    $dx = $gw / 550.0; $dy = $gh / 550.0

    # Grid lines every 50 up to 500
    for ($xi = 50; $xi -le 500; $xi += 50) {
        $x = $ox + $xi * $dx
        $g.DrawLine($penGrid, [float]$x, [float]($oy - 500 * $dy), [float]$x, [float]$oy)
    }
    for ($yi = 50; $yi -le 500; $yi += 50) {
        $y = $oy - $yi * $dy
        $g.DrawLine($penGrid, [float]$ox, [float]$y, [float]($ox + 500 * $dx), [float]$y)
    }

    # Axes
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]($ox + $gw + 15), [float]$oy)
    $g.DrawLine($penAxis, [float]$ox, [float]$oy, [float]$ox, [float]($oy - $gh - 15))

    # Arrowheads
    $g.DrawLine($penAxis, [float]($ox + $gw + 15), [float]$oy, [float]($ox + $gw + 8), [float]($oy - 4))
    $g.DrawLine($penAxis, [float]($ox + $gw + 15), [float]$oy, [float]($ox + $gw + 8), [float]($oy + 4))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - $gh - 15), [float]($ox - 4), [float]($oy - $gh - 8))
    $g.DrawLine($penAxis, [float]$ox, [float]($oy - $gh - 15), [float]($ox + 4), [float]($oy - $gh - 8))

    # Labels
    $g.DrawString("O", $fontV, $brush, [float]($ox - 14), [float]($oy + 2))
    $g.DrawString("x", $fontV, $brush, [float]($ox + $gw + 20), [float]($oy - 8))
    $g.DrawString("y", $fontV, $brush, [float]($ox - 8), [float]($oy - $gh - 26))

    for ($xi = 100; $xi -le 500; $xi += 100) {
        $x = $ox + $xi * $dx
        $g.DrawString("$xi", $fontAxis, $brush, [float]$x, [float]($oy + 4), $sfC)
    }
    for ($yi = 100; $yi -le 500; $yi += 100) {
        $y = $oy - $yi * $dy
        $g.DrawString("$yi", $fontAxis, $brush, [float]($ox - 4), [float]($y - 7), $sfR)
    }

    # Line of Best Fit: y = 0.6x (from x=0 to x=520)
    $lx1 = $ox; $ly1 = $oy
    $lx2 = $ox + 520.0 * $dx; $ly2 = $oy - (520.0 * 0.6) * $dy
    $g.DrawLine($penFit, [float]$lx1, [float]$ly1, [float]$lx2, [float]$ly2)

    # Scatter points
    $pts = @(
        @(50.0, 30.0),
        @(100.0, 90.0),
        @(150.0, 75.0),
        @(200.0, 120.0),
        @(250.0, 180.0),
        @(300.0, 145.0),
        @(350.0, 210.0),
        @(400.0, 195.0),
        @(450.0, 315.0),
        @(500.0, 295.0)
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

# Execute All
Render-M1-Q2
Render-M1-Q11
Render-M1-Q14
Render-M1-Q20
Render-M2-Q2
Render-M2-Q4
Write-Host "`nAll 6 Light-Mode Images for November 2025 INT 1 Rendered Successfully!"
