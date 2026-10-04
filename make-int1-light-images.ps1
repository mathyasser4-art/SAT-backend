Add-Type -AssemblyName System.Drawing

function Create-Q13-Light {
    param($outPath)
    $w = 560; $h = 560
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    # Margins and plot area
    # x: 0 to 6, y: 6 to 12.5
    $left = 80; $right = 490; $top = 60; $bottom = 480
    $plotW = $right - $left
    $plotH = $bottom - $top

    function MapX($x) { return $left + ($x / 6.0) * $plotW }
    function MapY($y) { return $bottom - (($y - 6.0) / 6.5) * $plotH }

    # Grid pen & Axis pen
    $gridPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(210, 218, 226), 1.5)
    $axisPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $axisPen.EndCap = [System.Drawing.Drawing2D.LineCap]::ArrowAnchor
    $linePen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)

    # Fonts & Brushes
    $fontLabel = New-Object System.Drawing.Font("Times New Roman", 16, [System.Drawing.FontStyle]::Italic)
    $fontNum = New-Object System.Drawing.Font("Arial", 13, [System.Drawing.FontStyle]::Regular)
    $textBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))
    $dotBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))

    # Vertical grid lines (x = 1 to 6)
    for ($xi = 1; $xi -le 6; $xi++) {
        $gx = MapX $xi
        $g.DrawLine($gridPen, [float]$gx, [float]$top, [float]$gx, [float]$bottom)
        $g.DrawString("$xi", $fontNum, $textBrush, [float]($gx - 6), [float]($bottom + 8))
    }

    # Horizontal grid lines (y = 6 to 12)
    for ($yi = 6; $yi -le 12; $yi++) {
        $gy = MapY $yi
        $g.DrawLine($gridPen, [float]$left, [float]$gy, [float]$right, [float]$gy)
        $g.DrawString("$yi", $fontNum, $textBrush, [float]($left - 32), [float]($gy - 8))
    }

    # Axes
    # Y-axis at x=0
    $yAxX = MapX 0
    $g.DrawLine($axisPen, [float]$yAxX, [float]($bottom + 5), [float]$yAxX, [float]($top - 25))
    $g.DrawString("y", $fontLabel, $textBrush, [float]($yAxX - 7), [float]($top - 50))
    $g.DrawString("0", $fontNum, $textBrush, [float]($yAxX - 16), [float]($bottom + 8))

    # X-axis at y=6
    $xAxY = MapY 6
    $g.DrawLine($axisPen, [float]($left - 5), [float]$xAxY, [float]($right + 25), [float]$xAxY)
    $g.DrawString("x", $fontLabel, $textBrush, [float]($right + 30), [float]($xAxY - 10))

    # Line of best fit from x=0, y=12.25 down to x=5.35, y=6
    $p1x = MapX 0; $p1y = MapY 12.25
    $p2x = MapX 5.35; $p2y = MapY 6.0
    $g.DrawLine($linePen, [float]$p1x, [float]$p1y, [float]$p2x, [float]$p2y)

    # Data points:
    $pts = @(
        @(0.0, 12.0),
        @(0.75, 11.0),
        @(1.0, 12.0),
        @(1.5, 10.25),
        @(2.0, 10.0),
        @(2.25, 9.25),
        @(3.0, 9.0),
        @(3.5, 8.0),
        @(3.75, 8.25),
        @(4.0, 7.0)
    )

    $dotRadius = 5.5
    foreach ($p in $pts) {
        $px = MapX $p[0]
        $py = MapY $p[1]
        $rect = New-Object System.Drawing.RectangleF([float]($px - $dotRadius), [float]($py - $dotRadius), [float]($dotRadius * 2), [float]($dotRadius * 2))
        $g.FillEllipse($dotBrush, $rect)
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
    Write-Host "Created $outPath"
}

function Create-Q14-Light {
    param($outPath)
    $w = 600; $h = 320
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $linePen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $fontLabel = New-Object System.Drawing.Font("Times New Roman", 17, [System.Drawing.FontStyle]::Italic)
    $fontAngle = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Regular)
    $textBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))

    # Line s (near vertical): from (90, 40) down to (85, 280)
    $g.DrawLine($linePen, 90, 40, 85, 280)
    $g.DrawString("s", $fontLabel, $textBrush, 85, 16)

    # Line t (sloping downward to right): from (20, 85) down-right to (540, 240)
    $g.DrawLine($linePen, 20, 85, 540, 240)
    $g.DrawString("t", $fontLabel, $textBrush, 545, 235)

    # Line r (sloping slightly upward to right): from (15, 245) up-right to (530, 200)
    $g.DrawLine($linePen, 15, 245, 530, 200)
    $g.DrawString("r", $fontLabel, $textBrush, 538, 192)

    # Angle labels
    # 106° at intersection of line s and line t (top-right of intersection around (89, 105))
    $g.DrawString("106°", $fontAngle, $textBrush, 98, 78)

    # 23° inside triangle at intersection of line r and line t (around (420, 210))
    $g.DrawString("23°", $fontAngle, $textBrush, 280, 185)

    # x° at intersection of line s and line r (bottom-left around (86, 238))
    $g.DrawString("x°", $fontLabel, $textBrush, 45, 208)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
    Write-Host "Created $outPath"
}

Create-Q13-Light "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\int1_m1_q13_light.png"
Create-Q14-Light "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\int1_m1_q14_light.png"
