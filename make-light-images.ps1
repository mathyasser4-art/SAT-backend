Add-Type -AssemblyName System.Drawing

function InvertToLightMode($inputPath, $outputPath) {
    $src = [System.Drawing.Bitmap]::FromFile((Resolve-Path $inputPath))
    $rect = New-Object System.Drawing.Rectangle(0, 0, $src.Width, $src.Height)
    $dest = New-Object System.Drawing.Bitmap($src.Width, $src.Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    
    $srcData = $src.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $destData = $dest.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::WriteOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    
    $bytes = [Math]::Abs($srcData.Stride) * $src.Height
    $rgbValues = New-Object byte[] $bytes
    [System.Runtime.InteropServices.Marshal]::Copy($srcData.Scan0, $rgbValues, 0, $bytes)
    
    for ($i = 0; $i -lt $bytes; $i += 4) {
        # Format is B, G, R, A
        $b = $rgbValues[$i]
        $g = $rgbValues[$i + 1]
        $r = $rgbValues[$i + 2]
        
        # Invert colors
        $rgbValues[$i] = 255 - $b
        $rgbValues[$i + 1] = 255 - $g
        $rgbValues[$i + 2] = 255 - $r
        # Keep alpha unchanged (or 255)
        $rgbValues[$i + 3] = 255
    }
    
    [System.Runtime.InteropServices.Marshal]::Copy($rgbValues, 0, $destData.Scan0, $bytes)
    $src.UnlockBits($srcData)
    $dest.UnlockBits($destData)
    $src.Dispose()
    
    $dest.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $dest.Dispose()
    Write-Host "Converted $inputPath -> $outputPath (Light Mode)"
}

# Convert Q4, Q7, Q21, Q22
InvertToLightMode "q4.png" "q4_light.png"
InvertToLightMode "q7.png" "q7_light.png"
InvertToLightMode "q21.png" "q21_light.png"
InvertToLightMode "q22.png" "q22_light.png"

# Re-render Q20 directly in clean crisp vector light mode
$bmp = New-Object System.Drawing.Bitmap 450, 400
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$g.Clear([System.Drawing.Color]::White)

$pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(20, 20, 20), 2.0)
$brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(15, 15, 15))
$fontSerif = New-Object System.Drawing.Font('Times New Roman', 20, [System.Drawing.FontStyle]::Italic)
$fontRegular = New-Object System.Drawing.Font('Times New Roman', 17, [System.Drawing.FontStyle]::Regular)
$fontNote = New-Object System.Drawing.Font('Times New Roman', 13, [System.Drawing.FontStyle]::Regular)

$pR = New-Object System.Drawing.PointF 150, 280
$pS = New-Object System.Drawing.PointF 150, 70
$pQ = New-Object System.Drawing.PointF 310, 280

$g.DrawLine($pen, $pR, $pS)
$g.DrawLine($pen, $pR, $pQ)
$g.DrawLine($pen, $pS, $pQ)

$sqPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(20, 20, 20), 1.5)
$g.DrawRectangle($sqPen, 150, 260, 20, 20)

$g.DrawString('S', $fontSerif, $brush, 140, 35)
$g.DrawString('R', $fontSerif, $brush, 120, 285)
$g.DrawString('Q', $fontSerif, $brush, 320, 275)
$g.DrawString('22', $fontRegular, $brush, 105, 160)

$sf = New-Object System.Drawing.StringFormat
$sf.Alignment = [System.Drawing.StringAlignment]::Center
$g.DrawString('Note: Figure not drawn to scale.', $fontNote, $brush, 225, 360, $sf)

$g.Dispose()
$bmp.Save('q20_light.png', [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host "Generated q20_light.png (Light Mode)"
