Add-Type -AssemblyName System.Drawing

$width = 200
$height = 250
$bmp = New-Object System.Drawing.Bitmap $width, $height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$g.Clear([System.Drawing.Color]::White)

$penBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 40, 40), 1.5)
$brushHeaderBg = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(240, 240, 240))
$brushText = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(20, 20, 20))
$fontHeader = New-Object System.Drawing.Font('Times New Roman', 14, [System.Drawing.FontStyle]'Bold, Italic')
$fontRow = New-Object System.Drawing.Font('Times New Roman', 13, [System.Drawing.FontStyle]::Regular)

# Table layout
$x0 = 15
$y0 = 15
$w = 170
$h = 220
$col1W = 60
$col2W = 110
$rowH = 44

# Fill header background
$g.FillRectangle($brushHeaderBg, $x0, $y0, $w, $rowH)

# Draw horizontal lines
for ($i = 0; $i -le 5; $i++) {
    $y = $y0 + $i * $rowH
    $g.DrawLine($penBorder, $x0, $y, ($x0 + $w), $y)
}

# Draw vertical lines
$g.DrawLine($penBorder, $x0, $y0, $x0, ($y0 + $h))
$g.DrawLine($penBorder, ($x0 + $col1W), $y0, ($x0 + $col1W), ($y0 + $h))
$g.DrawLine($penBorder, ($x0 + $w), $y0, ($x0 + $w), ($y0 + $h))

$sf = New-Object System.Drawing.StringFormat
$sf.Alignment = [System.Drawing.StringAlignment]::Center
$sf.LineAlignment = [System.Drawing.StringAlignment]::Center

# Header text
$g.DrawString('x', $fontHeader, $brushText, ($x0 + $col1W / 2), ($y0 + $rowH / 2), $sf)
$g.DrawString('f(x)', $fontHeader, $brushText, ($x0 + $col1W + $col2W / 2), ($y0 + $rowH / 2), $sf)

# Rows data
$data = @(
    @('1', '7,000'),
    @('2', '2,800'),
    @('3', '1,120'),
    @('4', '448')
)

for ($i = 0; $i -lt 4; $i++) {
    $cy = $y0 + ($i + 1) * $rowH + $rowH / 2
    $g.DrawString($data[$i][0], $fontRow, $brushText, ($x0 + $col1W / 2), $cy, $sf)
    $g.DrawString($data[$i][1], $fontRow, $brushText, ($x0 + $col1W + $col2W / 2), $cy, $sf)
}

$g.Dispose()
$bmp.Save('us2_m1_q11_light.png', [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host "Generated crisp us2_m1_q11_light.png"
