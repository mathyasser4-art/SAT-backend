Add-Type -AssemblyName System.Drawing

$outputDir = "may2025_int3_light_images"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

function Save-Bitmap($bmp, $filename) {
    $path = Join-Path $outputDir $filename
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Created $filename"
}

# 1. M1 Q17: Distance vs Time graph (same as INT2 M1 Q18)
function Make-M1-Q17 {
    $width = 600
    $height = 600
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $left = 80
    $top = 40
    $plotW = 460
    $plotH = 460
    $bottom = $top + $plotH
    $right = $left + $plotW

    $penGrid = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 226, 235), 1.5)
    $penAxis = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $penLine = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(37, 99, 235), 3.5)
    $brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))
    $fontAxis = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $fontLabel = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)

    for ($i = 0; $i -le 8; $i++) {
        $x = $left + ($i * $plotW / 8.0)
        $g.DrawLine($penGrid, $x, $top, $x, $bottom)
        $txt = "$i"
        $sz = $g.MeasureString($txt, $fontAxis)
        $g.DrawString($txt, $fontAxis, $brushText, ($x - $sz.Width / 2), ($bottom + 8))
    }

    for ($j = 0; $j -le 8; $j++) {
        $val = $j * 10
        $y = $bottom - ($j * $plotH / 8.0)
        $g.DrawLine($penGrid, $left, $y, $right, $y)
        $txt = "$val"
        $sz = $g.MeasureString($txt, $fontAxis)
        $g.DrawString($txt, $fontAxis, $brushText, ($left - $sz.Width - 8), ($y - $sz.Height / 2))
    }

    $g.DrawLine($penAxis, $left, $bottom, $right + 15, $bottom)
    $g.DrawLine($penAxis, $left, $bottom, $left, $top - 15)

    $p0 = New-Object System.Drawing.PointF($left, $bottom)
    $p1 = New-Object System.Drawing.PointF(($left + 1 * $plotW / 8.0), ($bottom - 6 * $plotH / 8.0))
    $p2 = New-Object System.Drawing.PointF(($left + 5 * $plotW / 8.0), ($bottom - 6 * $plotH / 8.0))
    $p3 = New-Object System.Drawing.PointF(($left + 6 * $plotW / 8.0), $bottom)

    $points = [System.Drawing.PointF[]]@($p0, $p1, $p2, $p3)
    $g.DrawLines($penLine, $points)

    $lblX = "Time (hours)"
    $szX = $g.MeasureString($lblX, $fontLabel)
    $g.DrawString($lblX, $fontLabel, $brushText, ($left + ($plotW - $szX.Width)/2), ($bottom + 35))

    $state = $g.Save()
    $lblY = "Distance (miles)"
    $szY = $g.MeasureString($lblY, $fontLabel)
    $g.TranslateTransform(25, ($top + ($plotH + $szY.Width)/2))
    $g.RotateTransform(-90)
    $g.DrawString($lblY, $fontLabel, $brushText, 0, 0)
    $g.Restore($state)

    Save-Bitmap $bmp "m1_q17_light.png"
}

# 2. M1 Q18: Frequency Table (Mass vs Frequency)
function Make-M1-Q18 {
    $width = 440
    $height = 300
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(203, 213, 225), 1.5)
    $penHeaderBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(148, 163, 184), 2.0)
    $brushHeaderBg = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(241, 245, 249))
    $brushRowAlt = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(248, 250, 252))
    $brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))

    $fontHeader = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
    $fontRow = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Regular)

    $x0 = 40
    $y0 = 30
    $wTotal = 360
    $hRow = 48
    $col1W = 180
    $col2W = 180

    # Draw header
    $g.FillRectangle($brushHeaderBg, $x0, $y0, $wTotal, $hRow)
    $g.DrawRectangle($penHeaderBorder, $x0, $y0, $wTotal, $hRow)
    $g.DrawLine($penHeaderBorder, ($x0 + $col1W), $y0, ($x0 + $col1W), ($y0 + $hRow))

    $szH1 = $g.MeasureString("Mass (grams)", $fontHeader)
    $g.DrawString("Mass (grams)", $fontHeader, $brushText, ($x0 + ($col1W - $szH1.Width)/2), ($y0 + ($hRow - $szH1.Height)/2))

    $szH2 = $g.MeasureString("Frequency", $fontHeader)
    $g.DrawString("Frequency", $fontHeader, $brushText, ($x0 + $col1W + ($col2W - $szH2.Width)/2), ($y0 + ($hRow - $szH2.Height)/2))

    # Data rows
    $rows = @(
        @("10", "12"),
        @("20", "6"),
        @("30", "8"),
        @("40", "9")
    )

    for ($r = 0; $r -lt $rows.Count; $r++) {
        $curY = $y0 + ($r + 1) * $hRow
        if ($r % 2 -eq 1) {
            $g.FillRectangle($brushRowAlt, $x0, $curY, $wTotal, $hRow)
        }
        $g.DrawRectangle($penBorder, $x0, $curY, $wTotal, $hRow)
        $g.DrawLine($penBorder, ($x0 + $col1W), $curY, ($x0 + $col1W), ($curY + $hRow))

        $val1 = $rows[$r][0]
        $szV1 = $g.MeasureString($val1, $fontRow)
        $g.DrawString($val1, $fontRow, $brushText, ($x0 + ($col1W - $szV1.Width)/2), ($curY + ($hRow - $szV1.Height)/2))

        $val2 = $rows[$r][1]
        $szV2 = $g.MeasureString($val2, $fontRow)
        $g.DrawString($val2, $fontRow, $brushText, ($x0 + $col1W + ($col2W - $szV2.Width)/2), ($curY + ($hRow - $szV2.Height)/2))
    }

    Save-Bitmap $bmp "m1_q18_light.png"
}

# 3. M2 Q2: Parallel lines j and k cut by transversal l (same as INT2)
function Make-M2-Q2 {
    $width = 650
    $height = 500
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))
    $fontLabel = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)

    $yJ = 150
    $yK = 320

    $g.DrawLine($penLine, 50, $yJ, 520, $yJ)
    $g.DrawLine($penLine, 50, $yK, 520, $yK)

    $g.DrawString("j", $fontLabel, $brushText, 540, ($yJ - 15))
    $g.DrawString("k", $fontLabel, $brushText, 540, ($yK - 15))

    $pTop = New-Object System.Drawing.PointF(450, 40)
    $pBottom = New-Object System.Drawing.PointF(70, 460)
    $g.DrawLine($penLine, $pTop, $pBottom)
    $g.DrawString("l", $fontLabel, $brushText, 460, 20)

    $intJ_x = 450 - (150 - 40) * (380.0 / 420.0)
    $intK_x = 450 - (320 - 40) * (380.0 / 420.0)

    $g.DrawString("w°", $fontVal, $brushText, ($intJ_x + 40), ($yJ - 38))
    $g.DrawString("x°", $fontVal, $brushText, ($intJ_x - 50), ($yJ + 12))

    $g.DrawString("54°", $fontVal, $brushText, ($intK_x + 35), ($yK - 38))
    $g.DrawString("y°", $fontVal, $brushText, ($intK_x - 55), ($yK + 15))
    $g.DrawString("z°", $fontVal, $brushText, ($intK_x + 15), ($yK + 15))

    Save-Bitmap $bmp "m2_q2_light.png"
}

Write-Host "Rendering light images for May 2025 · INT 3..."
Make-M1-Q17
Make-M1-Q18
Make-M2-Q2
Write-Host "All light images rendered successfully!"
