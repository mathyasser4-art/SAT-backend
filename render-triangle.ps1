Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap 450, 400
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$g.Clear([System.Drawing.Color]::FromArgb(10, 10, 10))

$pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(235, 235, 235), 2.0)
$brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(240, 240, 240))
$fontSerif = New-Object System.Drawing.Font('Times New Roman', 20, [System.Drawing.FontStyle]::Italic)
$fontRegular = New-Object System.Drawing.Font('Times New Roman', 17, [System.Drawing.FontStyle]::Regular)
$fontNote = New-Object System.Drawing.Font('Times New Roman', 13, [System.Drawing.FontStyle]::Regular)

# Triangle coordinates
# Right angle at R: (150, 280)
# S at top: (150, 70) => RS = 210 (vertical)
# Q at right: (310, 280) => QR = 160 (horizontal, QR < RS: 160 < 210)
$pR = New-Object System.Drawing.PointF 150, 280
$pS = New-Object System.Drawing.PointF 150, 70
$pQ = New-Object System.Drawing.PointF 310, 280

# Draw triangle
$g.DrawLine($pen, $pR, $pS)
$g.DrawLine($pen, $pR, $pQ)
$g.DrawLine($pen, $pS, $pQ)

# Right angle square at R (150, 280)
$sqPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(235, 235, 235), 1.5)
$g.DrawRectangle($sqPen, 150, 260, 20, 20)

# Labels
$g.DrawString('S', $fontSerif, $brush, 140, 35)
$g.DrawString('R', $fontSerif, $brush, 120, 285)
$g.DrawString('Q', $fontSerif, $brush, 320, 275)

# Dimension 22 on side RS
$g.DrawString('22', $fontRegular, $brush, 105, 160)

# Note at bottom
$sf = New-Object System.Drawing.StringFormat
$sf.Alignment = [System.Drawing.StringAlignment]::Center
$g.DrawString('Note: Figure not drawn to scale.', $fontNote, $brush, 225, 360, $sf)

$g.Dispose()
$bmp.Save('triangle_q20.png', [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host 'Rendered triangle_q20.png successfully!'
