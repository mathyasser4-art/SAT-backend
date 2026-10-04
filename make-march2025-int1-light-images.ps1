Add-Type -AssemblyName System.Drawing

$outputDir = "march2025_int1_light_images"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

function Save-Bitmap($bmp, $filename) {
    $path = Join-Path $outputDir $filename
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Created $filename"
}

# 1. M1 Q1: Cost y vs Rings x
function Make-M1-Q1 {
    $width = 550
    $height = 550
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 75
    $top = 40
    $plotW = 420
    $plotH = 420
    $bottom = $top + $plotH
    $right = $left + $plotW

    $penGrid = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(226, 232, 240), 1.5)
    $penAxis = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $penLine = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(37, 99, 235), 3.0)
    $brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))
    $fontTick = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $fontAxis = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Italic)

    # Grid X: 0 to 100 in 10s
    for ($i = 0; $i -le 10; $i++) {
        $x = $left + ($i * $plotW / 10.0)
        $g.DrawLine($penGrid, $x, $top, $x, $bottom)
        if ($i -gt 0) {
            $txt = "$($i * 10)"
            $sz = $g.MeasureString($txt, $fontTick)
            $g.DrawString($txt, $fontTick, $brushText, ($x - $sz.Width/2), ($bottom + 6))
        }
    }

    # Grid Y: 0 to 300 in 50s (6 divisions)
    for ($j = 0; $j -le 6; $j++) {
        $val = $j * 50
        $y = $bottom - ($j * $plotH / 6.0)
        $g.DrawLine($penGrid, $left, $y, $right, $y)
        if ($j -gt 0) {
            $txt = "$val"
            $sz = $g.MeasureString($txt, $fontTick)
            $g.DrawString($txt, $fontTick, $brushText, ($left - $sz.Width - 6), ($y - $sz.Height/2))
        }
    }

    # Axes
    $g.DrawLine($penAxis, $left, $bottom, $right + 15, $bottom)
    $g.DrawLine($penAxis, $left, $bottom, $left, $top - 15)
    $g.DrawString("O", $fontTick, $brushText, ($left - 18), ($bottom + 5))
    $g.DrawString("x", $fontAxis, $brushText, ($right + 18), ($bottom - 8))
    $g.DrawString("y", $fontAxis, $brushText, ($left - 8), ($top - 32))

    # Line: y = 1.5x + 100
    # at x = 0: y = 100 -> pixel Y = bottom - (100 / 300) * plotH = bottom - 2/6 * plotH
    # at x = 100: y = 250 -> pixel Y = bottom - (250 / 300) * plotH = bottom - 5/6 * plotH
    $p0 = New-Object System.Drawing.PointF($left, ($bottom - 2 * $plotH / 6.0))
    $p1 = New-Object System.Drawing.PointF(($left + $plotW + 10), ($bottom - 2.575 * $plotH / 3.0))
    $g.DrawLine($penLine, $p0, $p1)

    Save-Bitmap $bmp "m1_q1_light.png"
}

# 2. M1 Q8: Triangle ACE with parallel BD
function Make-M1-Q8 {
    $width = 500
    $height = 460
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penTri = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $penSquare = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(71, 85, 105), 1.8)
    $brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))
    $fontLabel = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $fontNote = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Italic)

    # Coordinates:
    # E: (350, 350)
    # A: (120, 350)
    # C: (350, 50)
    $pE = New-Object System.Drawing.PointF(350, 350)
    $pA = New-Object System.Drawing.PointF(120, 350)
    $pC = New-Object System.Drawing.PointF(350, 50)

    # D is on CE: y = 200, x = 350
    # B is on AC: at y = 200, x = 350 - (350 - 50) / (350 - 50) * ...
    # line AC from (120, 350) to (350, 50):
    # dx = 230, dy = -300
    # at y = 200: t = (200 - 350) / -300 = 150 / 300 = 0.5
    # x = 120 + 0.5 * 230 = 235
    $pD = New-Object System.Drawing.PointF(350, 200)
    $pB = New-Object System.Drawing.PointF(235, 200)

    # Triangle ACE
    $g.DrawLine($penTri, $pA, $pE)
    $g.DrawLine($penTri, $pE, $pC)
    $g.DrawLine($penTri, $pC, $pA)

    # Segment BD
    $g.DrawLine($penTri, $pB, $pD)

    # Right angle at E:
    $sqE = [System.Drawing.PointF[]]@(
        (New-Object System.Drawing.PointF(350, 328)),
        (New-Object System.Drawing.PointF(328, 328)),
        (New-Object System.Drawing.PointF(328, 350))
    )
    $g.DrawLines($penSquare, $sqE)

    # Right angle at D (upper-left of D):
    $sqD = [System.Drawing.PointF[]]@(
        (New-Object System.Drawing.PointF(350, 178)),
        (New-Object System.Drawing.PointF(328, 178)),
        (New-Object System.Drawing.PointF(328, 200))
    )
    $g.DrawLines($penSquare, $sqD)

    # Labels
    $g.DrawString("A", $fontLabel, $brushText, 95, 345)
    $g.DrawString("E", $fontLabel, $brushText, 360, 345)
    $g.DrawString("C", $fontLabel, $brushText, 352, 22)
    $g.DrawString("B", $fontLabel, $brushText, 205, 185)
    $g.DrawString("D", $fontLabel, $brushText, 360, 185)

    # Note
    $note = "Note: Figure not drawn to scale."
    $szN = $g.MeasureString($note, $fontNote)
    $g.DrawString($note, $fontNote, $brushText, ((500 - $szN.Width)/2), 415)

    Save-Bitmap $bmp "m1_q8_light.png"
}

# 3. M1 Q21: Cone with apex A, base point B
function Make-M1-Q21 {
    $width = 500
    $height = 360
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penCone = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $penDashed = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(100, 116, 139), 2.0)
    $penDashed.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $brushDot = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(37, 99, 235))
    $brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))
    $fontLabel = New-Object System.Drawing.Font("Segoe UI", 17, [System.Drawing.FontStyle]::Bold)
    $fontNote = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Italic)

    $apexX = 250
    $apexY = 55
    $baseCx = 250
    $baseCy = 230
    $rx = 200
    $ry = 40

    # Draw cone slant edges to extreme left and right of ellipse
    $g.DrawLine($penCone, $apexX, $apexY, ($baseCx - $rx), $baseCy)
    $g.DrawLine($penCone, $apexX, $apexY, ($baseCx + $rx), $baseCy)

    # Ellipse base: top half dashed (180 to 360), bottom half solid (0 to 180)
    $g.DrawArc($penDashed, ($baseCx - $rx), ($baseCy - $ry), (2 * $rx), (2 * $ry), 180, 180)
    $g.DrawArc($penCone, ($baseCx - $rx), ($baseCy - $ry), (2 * $rx), (2 * $ry), 0, 180)

    # Point A at apex
    $g.FillEllipse($brushDot, ($apexX - 5), ($apexY - 5), 10, 10)
    $g.DrawString("A", $fontLabel, $brushText, ($apexX - 8), ($apexY - 35))

    # Point B on bottom-left boundary (e.g. angle 120 deg)
    # x = 250 + 200 * cos(135 deg) = 250 - 141 = 109
    # y = 230 + 40 * sin(135 deg) = 230 + 28 = 258
    $ptBx = 130
    $ptBy = 260
    $g.FillEllipse($brushDot, ($ptBx - 5), ($ptBy - 5), 10, 10)
    $g.DrawString("B", $fontLabel, $brushText, ($ptBx - 8), ($ptBy + 10))

    # Note
    $note = "Note: Figure not drawn to scale."
    $szN = $g.MeasureString($note, $fontNote)
    $g.DrawString($note, $fontNote, $brushText, ((500 - $szN.Width)/2), 320)

    Save-Bitmap $bmp "m1_q21_light.png"
}

# 4. M2 Q17: Graph of y = f(x) + 4 where f(x) = -6^x + 5 => y = -6^x + 9
function Make-M2-Q17 {
    $width = 500
    $height = 500
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 60
    $top = 40
    $plotW = 400
    $plotH = 400
    $bottom = $top + $plotH
    $right = $left + $plotW

    $penGrid = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(226, 232, 240), 1.5)
    $penAxis = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $penCurve = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(37, 99, 235), 3.0)
    $brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))
    $fontTick = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $fontAxis = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Italic)

    # X axis: -1 to 5 (6 units total span)
    # Origin X at x = 0: fraction = 1 / 6
    $originX = $left + (1.0 / 6.0) * $plotW
    # Y axis: -4 to 10 (14 units total span)
    # Origin Y at y = 0: fraction = 10 / 14 from top
    $originY = $top + (10.0 / 14.0) * $plotH

    # Grid lines X: -1 to 5
    for ($xVal = -1; $xVal -le 5; $xVal++) {
        $x = $originX + $xVal * ($plotW / 6.0)
        $g.DrawLine($penGrid, $x, $top, $x, $bottom)
        if ($xVal -ne 0) {
            $txt = "$xVal"
            $sz = $g.MeasureString($txt, $fontTick)
            $g.DrawString($txt, $fontTick, $brushText, ($x - $sz.Width/2), ($originY + 6))
        }
    }

    # Grid lines Y: -4 to 10 in steps of 2
    for ($yVal = -4; $yVal -le 10; $yVal += 2) {
        $y = $originY - $yVal * ($plotH / 14.0)
        $g.DrawLine($penGrid, $left, $y, $right, $y)
        if ($yVal -ne 0) {
            $txt = "$yVal"
            $sz = $g.MeasureString($txt, $fontTick)
            $g.DrawString($txt, $fontTick, $brushText, ($originX - $sz.Width - 6), ($y - $sz.Height/2))
        }
    }

    # Axes
    $g.DrawLine($penAxis, $left, $originY, $right + 15, $originY)
    $g.DrawLine($penAxis, $originX, $bottom, $originX, $top - 15)
    $g.DrawString("O", $fontTick, $brushText, ($originX - 16), ($originY + 5))
    $g.DrawString("x", $fontAxis, $brushText, ($right + 18), ($originY - 8))
    $g.DrawString("y", $fontAxis, $brushText, ($originX - 8), ($top - 32))

    # Curve: y = -6^x + 9
    # Sample points from x = -1 to x = 1.3
    $pts = New-Object System.Collections.Generic.List[System.Drawing.PointF]
    for ($xv = -1.0; $xv -le 1.35; $xv += 0.02) {
        $yv = -[Math]::Pow(6.0, $xv) + 9.0
        $px = $originX + $xv * ($plotW / 6.0)
        $py = $originY - $yv * ($plotH / 14.0)
        if ($py -ge ($top - 5) -and $py -le ($bottom + 5)) {
            $pts.Add((New-Object System.Drawing.PointF($px, $py)))
        }
    }
    $g.DrawCurve($penCurve, $pts.ToArray())

    Save-Bitmap $bmp "m2_q17_light.png"
}

# 5. M2 Q18: Triangles LMR and PQR meeting at R
function Make-M2-Q18 {
    $width = 560
    $height = 400
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penTri = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))
    $fontLabel = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $fontNote = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Italic)

    # Line LQ: horizontal line through middle
    $yMid = 180
    $pL = New-Object System.Drawing.PointF(50, $yMid)
    $pQ = New-Object System.Drawing.PointF(500, $yMid)
    $pR = New-Object System.Drawing.PointF(220, $yMid)

    # M is top-left: (135, 70)
    # P is bottom-right: (360, 310)
    # Notice slope of MR: (180 - 70) / (220 - 135) = 110 / 85 = 1.294
    # Slope of RP: (310 - 180) / (360 - 220) = 130 / 140 = 0.928 (approx continuous line MP)
    # Let's align MP perfectly so M, R, P are collinear:
    # If R = (220, 180), M = (130, 80) -> vector RM = (-90, -100) -> length approx sqrt(8100 + 10000) = 134 (represents 8 units)
    # Ratio RP/MR = 14/8 = 1.75
    # Then vector RP = 1.75 * (90, 100) = (157.5, 175)
    # P = (220 + 158, 180 + 175) = (378, 355)
    $pM = New-Object System.Drawing.PointF(130, 80)
    $pP = New-Object System.Drawing.PointF(378, 320)

    # Draw segments:
    # Line LQ
    $g.DrawLine($penTri, $pL, $pQ)
    # Line MP
    $g.DrawLine($penTri, $pM, $pP)
    # Triangle LMR: LM
    $g.DrawLine($penTri, $pL, $pM)
    # Triangle PQR: PQ
    $g.DrawLine($penTri, $pP, $pQ)

    # Labels
    $g.DrawString("L", $fontLabel, $brushText, 25, ($yMid - 15))
    $g.DrawString("Q", $fontLabel, $brushText, 510, ($yMid - 15))
    $g.DrawString("R", $fontLabel, $brushText, 215, ($yMid - 35))
    $g.DrawString("M", $fontLabel, $brushText, 120, 48)
    $g.DrawString("P", $fontLabel, $brushText, 370, 325)

    # Note
    $note = "Note: Figure not drawn to scale."
    $szN = $g.MeasureString($note, $fontNote)
    $g.DrawString($note, $fontNote, $brushText, ((560 - $szN.Width)/2), 365)

    Save-Bitmap $bmp "m2_q18_light.png"
}

Write-Host "Rendering all light-mode images for March 2025 · INT 1..."
Make-M1-Q1
Make-M1-Q8
Make-M1-Q21
Make-M2-Q17
Make-M2-Q18
Write-Host "All light-mode images generated successfully!"
