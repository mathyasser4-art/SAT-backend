Add-Type -AssemblyName System.Drawing

$imgDir = Join-Path $PSScriptRoot "sep2025_us1_images"
if (!(Test-Path $imgDir)) { New-Item -ItemType Directory -Path $imgDir | Out-Null }

$cDark = [System.Drawing.Color]::FromArgb(15, 23, 42)

# ==============================================================================
# 1. M1 Q2: Parallel horizontal lines r and s cut by transversal t
# ==============================================================================
function Render-M1Q2 {
    $outPath = Join-Path $imgDir "m1_q2_light.png"
    $w = 400; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penLine = New-Object System.Drawing.Pen($cDark, 2.0)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontLabel = New-Object System.Drawing.Font("Arial", 11.5, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 10.5, [System.Drawing.FontStyle]::Regular)

    # Horizontal parallel lines r and s
    $leftX = 40.0; $rightX = 350.0
    $ry = 120.0; $sy = 230.0
    $g.DrawLine($penLine, [float]$leftX, [float]$ry, [float]$rightX, [float]$ry)
    $g.DrawLine($penLine, [float]$leftX, [float]$sy, [float]$rightX, [float]$sy)

    # Transversal line t: positive slope (e.g. from (50, 330) to (340, 40))
    $t1x = 55.0;  $t1y = 330.0
    $t2x = 345.0; $t2y = 40.0
    $g.DrawLine($penLine, [float]$t1x, [float]$t1y, [float]$t2x, [float]$t2y)

    # Intersection at line r: (rx, ry)
    # y = ry = 120 -> x = 55 + (120 - 330) * (345 - 55) / (40 - 330) = 55 + (-210) * (290) / (-290) = 55 + 210 = 265
    $ix_r = 265.0
    # Intersection at line s: (sx, sy)
    # y = sy = 230 -> x = 55 + (230 - 330) * 1 = 155.0
    $ix_s = 155.0

    # Labels r, s, t
    $g.DrawString("r", $fontLabel, $brushDark, [float]($rightX + 15), [float]($ry - 10))
    $g.DrawString("s", $fontLabel, $brushDark, [float]($rightX + 15), [float]($sy - 10))
    $g.DrawString("t", $fontLabel, $brushDark, [float]($t2x + 10), [float]($t2y - 15))

    # Angle labels at line r
    $g.DrawString("103°", $fontVal, $brushDark, [float]($ix_r - 48), [float]($ry - 24))
    $g.DrawString("77°", $fontVal, $brushDark, [float]($ix_r + 15), [float]($ry - 24))

    # Angle labels at line s
    $g.DrawString("a°", $fontVal, $brushDark, [float]($ix_s + 20), [float]($sy - 22))
    $g.DrawString("77°", $fontVal, $brushDark, [float]($ix_s - 45), [float]($sy + 8))

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

# ==============================================================================
# 2. M1 Q13: Right triangle QRS with sides 4, 9, c
# ==============================================================================
function Render-M1Q13 {
    $outPath = Join-Path $imgDir "m1_q13_light.png"
    $w = 380; $h = 360
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::White)

    $penTri = New-Object System.Drawing.Pen($cDark, 2.2)
    $penBox = New-Object System.Drawing.Pen($cDark, 1.5)
    $brushDark = New-Object System.Drawing.SolidBrush($cDark)
    $fontLabel = New-Object System.Drawing.Font("Arial", 11.5, [System.Drawing.FontStyle]::Italic)
    $fontVal = New-Object System.Drawing.Font("Arial", 11.0, [System.Drawing.FontStyle]::Regular)
    $fontNote = New-Object System.Drawing.Font("Arial", 9.5, [System.Drawing.FontStyle]::Italic)
    $sfC = New-Object System.Drawing.StringFormat; $sfC.Alignment = [System.Drawing.StringAlignment]::Center

    # Vertices
    # Q at top-left (70, 50)
    # R at bottom-left (70, 275)
    # S at bottom-right (335, 275)
    $qx = 70.0; $qy = 50.0
    $rx = 70.0; $ry = 275.0
    $sx = 335.0; $sy = 275.0

    # Draw triangle
    $g.DrawLine($penTri, [float]$qx, [float]$qy, [float]$rx, [float]$ry)
    $g.DrawLine($penTri, [float]$rx, [float]$ry, [float]$sx, [float]$sy)
    $g.DrawLine($penTri, [float]$sx, [float]$sy, [float]$qx, [float]$qy)

    # Right angle marker at R
    $sq = 18.0
    $g.DrawLine($penBox, [float]$rx, [float]($ry - $sq), [float]($rx + $sq), [float]($ry - $sq))
    $g.DrawLine($penBox, [float]($rx + $sq), [float]($ry - $sq), [float]($rx + $sq), [float]$ry)

    # Vertex labels Q, R, S
    $g.DrawString("Q", $fontLabel, $brushDark, [float]($qx - 15), [float]($qy - 22))
    $g.DrawString("R", $fontLabel, $brushDark, [float]($rx - 20), [float]($ry + 2))
    $g.DrawString("S", $fontLabel, $brushDark, [float]($sx + 5), [float]($sy + 2))

    # Side lengths
    $g.DrawString("4", $fontVal, $brushDark, [float]($rx - 24), [float](($qy + $ry)/2 - 10))
    $g.DrawString("9", $fontVal, $brushDark, [float](($rx + $sx)/2 - 5), [float]($ry + 8))
    $g.DrawString("c", $fontLabel, $brushDark, [float](($qx + $sx)/2 + 5), [float](($qy + $sy)/2 - 18))

    # Angle y deg at S
    $g.DrawString("y°", $fontVal, $brushDark, [float]($sx - 48), [float]($sy - 24))

    # Note
    $g.DrawString("Note: Figure not drawn to scale.", $fontNote, $brushDark, [float]($w / 2), [float]($h - 25), $sfC)

    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

Render-M1Q2
Render-M1Q13
