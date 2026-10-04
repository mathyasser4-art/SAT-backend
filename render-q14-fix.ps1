Add-Type -AssemblyName System.Drawing

function Create-Q14-Light {
    param($outPath)
    $w = 600; $h = 320
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $deg = [char]176

    $linePen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $fontLabel = New-Object System.Drawing.Font("Times New Roman", 17, [System.Drawing.FontStyle]::Italic)
    $fontAngle = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Regular)
    $textBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))

    # Line s (vertical): from (100, 45) down to (95, 285)
    $g.DrawLine($linePen, 100, 45, 95, 285)
    $g.DrawString("s", $fontLabel, $textBrush, 93, 20)

    # Line t (sloping downward to right): from (25, 90) down-right to (545, 245)
    $g.DrawLine($linePen, 25, 90, 545, 245)
    $g.DrawString("t", $fontLabel, $textBrush, 550, 240)

    # Line r (sloping slightly upward to right): from (20, 255) up-right to (540, 205)
    $g.DrawLine($linePen, 20, 255, 540, 205)
    $g.DrawString("r", $fontLabel, $textBrush, 548, 196)

    # Angle labels
    # 106° at top-right of intersection of line s and line t (around (100, 112))
    $g.DrawString("106$deg", $fontAngle, $textBrush, 110, 85)

    # 23° inside triangle at intersection of line r and line t (around (410, 220))
    $g.DrawString("23$deg", $fontAngle, $textBrush, 280, 190)

    # x° at intersection of line s and line r (left of s, above r around (55, 220))
    $g.DrawString("x$deg", $fontLabel, $textBrush, 55, 220)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
    Write-Host "Created $outPath"
}

Create-Q14-Light "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\int1_m1_q14_light.png"
