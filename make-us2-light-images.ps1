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
        $b = $rgbValues[$i]
        $g = $rgbValues[$i + 1]
        $r = $rgbValues[$i + 2]
        
        # Invert colors
        $rgbValues[$i] = 255 - $b
        $rgbValues[$i + 1] = 255 - $g
        $rgbValues[$i + 2] = 255 - $r
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

InvertToLightMode "us2_m1_q8.png" "us2_m1_q8_light.png"
InvertToLightMode "us2_m1_q11.png" "us2_m1_q11_light.png"
InvertToLightMode "us2_m1_q12.png" "us2_m1_q12_light.png"
InvertToLightMode "us2_m1_q14.png" "us2_m1_q14_light.png"
InvertToLightMode "us2_m1_q15.png" "us2_m1_q15_light.png"
InvertToLightMode "us2_m2_q3.png" "us2_m2_q3_light.png"
InvertToLightMode "us2_m2_q5.png" "us2_m2_q5_light.png"
InvertToLightMode "us2_m2_q20.png" "us2_m2_q20_light.png"
