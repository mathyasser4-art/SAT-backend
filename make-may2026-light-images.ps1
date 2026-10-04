Add-Type -AssemblyName System.Drawing

function Create-M1-Q7-Light {
    param($outPath)
    $w = 540; $h = 320
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $thinPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 1.8)
    $fontV = New-Object System.Drawing.Font("Times New Roman", 18, [System.Drawing.FontStyle]::Italic)
    $fontSub = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))

    # Triangle 1 (ABC)
    # A top-left, B top-right, C bottom
    $Ax = 90.0; $Ay = 60.0
    $Bx = 200.0; $By = 60.0
    $Cx = 145.0; $Cy = 205.0

    $pts1 = @(
        (New-Object System.Drawing.PointF($Ax, $Ay)),
        (New-Object System.Drawing.PointF($Bx, $By)),
        (New-Object System.Drawing.PointF($Cx, $Cy))
    )
    $g.DrawPolygon($pen, $pts1)

    # Angle arc at A: between AB (horizontal right) and AC (going down-right)
    # Angle AB is 0 deg. Angle AC: dy=145, dx=55 -> angle is ~69 deg
    $deg = [char]176
    $g.DrawArc($thinPen, ($Ax - 18), ($Ay - 18), 36, 36, 0, 69)
    $g.DrawString("60$deg", $fontSub, $brush, ($Ax + 14), ($Ay + 6))

    # Side AC label d
    $g.DrawString("d", $fontV, $brush, ($Ax - 2), ($Ay + 65))

    # Vertex labels
    $g.DrawString("A", $fontV, $brush, ($Ax - 22), ($Ay - 8))
    $g.DrawString("B", $fontV, $brush, ($Bx + 6), ($By - 8))
    $g.DrawString("C", $fontV, $brush, ($Cx - 8), ($Cy + 6))

    # Triangle 2 (XYZ) - larger
    # X top-left, Y top-right, Z bottom
    $Xx = 300.0; $Xy = 40.0
    $Yx = 480.0; $Yy = 40.0
    $Zx = 390.0; $Zy = 240.0

    $pts2 = @(
        (New-Object System.Drawing.PointF($Xx, $Xy)),
        (New-Object System.Drawing.PointF($Yx, $Yy)),
        (New-Object System.Drawing.PointF($Zx, $Zy))
    )
    $g.DrawPolygon($pen, $pts2)

    # Vertex labels
    $g.DrawString("X", $fontV, $brush, ($Xx - 24), ($Xy - 10))
    $g.DrawString("Y", $fontV, $brush, ($Yx + 6), ($Yy - 10))
    $g.DrawString("Z", $fontV, $brush, ($Zx - 8), ($Zy + 6))

    # Note
    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = [System.Drawing.StringAlignment]::Center
    $g.DrawString("Note: Figures not drawn to scale.", $fontNote, $brush, ($w / 2.0), 285.0, $sf)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
}

function Create-M1-Q8-Light {
    param($outPath)
    $w = 520; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $dashPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.0)
    $dashPen.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
    $thinPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 1.8)

    $fontV = New-Object System.Drawing.Font("Times New Roman", 18, [System.Drawing.FontStyle]::Italic)
    $fontLabel = New-Object System.Drawing.Font("Times New Roman", 16, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))

    $Ax = 70.0;  $Ay = 220.0
    $Bx = 250.0; $By = 70.0
    $Cx = 430.0; $Cy = 220.0
    $Dx = 250.0; $Dy = 220.0

    $pts = @(
        (New-Object System.Drawing.PointF($Ax, $Ay)),
        (New-Object System.Drawing.PointF($Bx, $By)),
        (New-Object System.Drawing.PointF($Cx, $Cy))
    )
    $g.DrawPolygon($pen, $pts)

    # Altitude line (dashed)
    $g.DrawLine($dashPen, $Bx, $By, $Dx, $Dy)

    # Right angle box at D (base)
    $sq = 14.0
    $g.DrawLine($thinPen, ($Dx - $sq), $Dy, ($Dx - $sq), ($Dy - $sq))
    $g.DrawLine($thinPen, ($Dx - $sq), ($Dy - $sq), $Dx, ($Dy - $sq))

    # Labels
    $g.DrawString("A", $fontV, $brush, ($Ax - 24), ($Ay - 10))
    $g.DrawString("B", $fontV, $brush, ($Bx - 7), ($By - 28))
    $g.DrawString("C", $fontV, $brush, ($Cx + 8), ($Cy - 10))
    $g.DrawString("h", $fontV, $brush, ($Dx + 8), (($By + $Dy) / 2.0 - 10))

    # Base label 10 cm
    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = [System.Drawing.StringAlignment]::Center
    $g.DrawString("10 cm", $fontLabel, $brush, $Dx, ($Dy + 12), $sf)

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, ($w / 2.0), 320.0, $sf)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
}

function Create-M1-Q9-Light {
    param($outPath)
    $w = 520; $h = 330
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $thinPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 1.8)

    $fontV = New-Object System.Drawing.Font("Times New Roman", 17, [System.Drawing.FontStyle]::Italic)
    $fontNum = New-Object System.Drawing.Font("Times New Roman", 17, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))

    # Right triangle:
    # Top-right apex: (410, 40)
    # Bottom-right corner: (410, 240)
    # Bottom-left vertex: (150, 240)
    $Tx = 410.0; $Ty = 40.0
    $Rx = 410.0; $Ry = 240.0
    $Lx = 150.0; $Ly = 240.0

    $pts = @(
        (New-Object System.Drawing.PointF($Tx, $Ty)),
        (New-Object System.Drawing.PointF($Rx, $Ry)),
        (New-Object System.Drawing.PointF($Lx, $Ly))
    )
    $g.DrawPolygon($pen, $pts)

    # Right angle box at R
    $sq = 14.0
    $g.DrawLine($thinPen, ($Rx - $sq), $Ry, ($Rx - $sq), ($Ry - $sq))
    $g.DrawLine($thinPen, ($Rx - $sq), ($Ry - $sq), $Rx, ($Ry - $sq))

    # Angle x deg at T (top apex)
    # Leg TR goes straight down (90 deg). Hypotenuse TL goes down-left: dx=-260, dy=200 -> angle ~ 142 deg
    $deg = [char]176
    $g.DrawArc($thinPen, ($Tx - 25), ($Ty - 25), 50, 50, 90, 52)
    $g.DrawString("x$deg", $fontV, $brush, ($Tx - 22), ($Ty + 28))

    # Labels
    # Leg 39 on right
    $g.DrawString("39", $fontNum, $brush, ($Rx + 12), (($Ty + $Ry) / 2.0 - 12))

    # Base 40 centered underneath
    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = [System.Drawing.StringAlignment]::Center
    $g.DrawString("40", $fontNum, $brush, (($Lx + $Rx) / 2.0), ($Ry + 12), $sf)

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, ($w / 2.0), 295.0, $sf)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
}

function Create-M1-Q18-Light {
    param($outPath)
    $w = 260; $h = 320
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.2)
    $fontHead = New-Object System.Drawing.Font("Times New Roman", 20, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Times New Roman", 18, [System.Drawing.FontStyle]::Regular)
    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))

    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = [System.Drawing.StringAlignment]::Center
    $sf.LineAlignment = [System.Drawing.StringAlignment]::Center

    $tblX = 40.0; $tblY = 30.0; $tblW = 180.0; $tblH = 260.0
    $colW = $tblW / 2.0
    $rowH = $tblH / 4.0

    # Outer rectangle
    $g.DrawRectangle($pen, $tblX, $tblY, $tblW, $tblH)

    # Vertical divider
    $g.DrawLine($pen, ($tblX + $colW), $tblY, ($tblX + $colW), ($tblY + $tblH))

    # Horizontal divider lines
    for ($i = 1; $i -le 3; $i++) {
        $ly = $tblY + $i * $rowH
        $g.DrawLine($pen, $tblX, $ly, ($tblX + $tblW), $ly)
    }

    # Header Row
    $g.DrawString("x", $fontHead, $brush, ($tblX + $colW * 0.5), ($tblY + $rowH * 0.5), $sf)
    $g.DrawString("y", $fontHead, $brush, ($tblX + $colW * 1.5), ($tblY + $rowH * 0.5), $sf)

    # Data Rows
    $minus = [char]8722
    $rows = @(
        @("${minus}2", "19"),
        @("0", "31"),
        @("2", "43")
    )

    for ($r = 0; $r -lt 3; $r++) {
        $cy = $tblY + ($r + 1.5) * $rowH
        $g.DrawString($rows[$r][0], $fontVal, $brush, ($tblX + $colW * 0.5), $cy, $sf)
        $g.DrawString($rows[$r][1], $fontVal, $brush, ($tblX + $colW * 1.5), $cy, $sf)
    }

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
}

function Create-M2-Q17-Light {
    param($outPath)
    $w = 480; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 2.5)
    $thinPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 23, 42), 1.8)

    $fontV = New-Object System.Drawing.Font("Times New Roman", 18, [System.Drawing.FontStyle]::Italic)
    $fontNum = New-Object System.Drawing.Font("Times New Roman", 17, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Times New Roman", 13, [System.Drawing.FontStyle]::Regular)
    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 23, 42))

    # Triangle ABC:
    # A at top-left: (90, 40)
    # B at bottom-left: (90, 260)
    # C at bottom-right: (410, 260)
    $Ax = 90.0;  $Ay = 40.0
    $Bx = 90.0;  $By = 260.0
    $Cx = 410.0; $Cy = 260.0

    $pts = @(
        (New-Object System.Drawing.PointF($Ax, $Ay)),
        (New-Object System.Drawing.PointF($Bx, $By)),
        (New-Object System.Drawing.PointF($Cx, $Cy))
    )
    $g.DrawPolygon($pen, $pts)

    # Right angle box at B
    $sq = 15.0
    $g.DrawLine($thinPen, ($Bx + $sq), $By, ($Bx + $sq), ($By - $sq))
    $g.DrawLine($thinPen, ($Bx + $sq), ($By - $sq), $Bx, ($By - $sq))

    # Vertex labels
    $g.DrawString("A", $fontV, $brush, ($Ax - 24), ($Ay - 10))
    $g.DrawString("B", $fontV, $brush, ($Bx - 24), ($By - 2))
    $g.DrawString("C", $fontV, $brush, ($Cx + 8), ($Cy - 2))

    # Hypotenuse 28
    $g.DrawString("28", $fontNum, $brush, (($Ax + $Cx) / 2.0 + 8), (($Ay + $Cy) / 2.0 - 24))

    # Note
    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = [System.Drawing.StringAlignment]::Center
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brush, ($w / 2.0), 320.0, $sf)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
}

# Run generation
Create-M1-Q7-Light "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\may26_m1_q7_light.png"
Create-M1-Q8-Light "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\may26_m1_q8_light.png"
Create-M1-Q9-Light "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\may26_m1_q9_light.png"
Create-M1-Q18-Light "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\may26_m1_q18_light.png"
Create-M2-Q17-Light "c:\Users\hp\Desktop\SAT\SAT-backend-master\SAT-backend-master\may26_m2_q17_light.png"

Write-Host "All 5 May 2026 INT 1 light mode images successfully rendered."
