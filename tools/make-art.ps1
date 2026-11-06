# Turns the generated artwork (white background) into web-ready PNGs with a transparent background.
#   & tools\make-art.ps1 -In logo.png -Out docs\img\logo-emblem.png -Width 900
# Only the white that is connected to the image border counts as background (flood fill), so white inside the
# picture (belly, goggles, eye) stays. Edge pixels are un-mixed from white (alpha = how far from white), so there is
# no white fringe on a dark page. Then the picture is cropped to its content (+ a small margin) and scaled.
param([Parameter(Mandatory)][string]$In, [Parameter(Mandatory)][string]$Out, [int]$Width = 900, [int]$Threshold = 200)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -ReferencedAssemblies System.Drawing.Common, System.Drawing.Primitives, System.Collections, System.Runtime.InteropServices, System.Private.Windows.GdiPlus -TypeDefinition @'
using System; using System.Collections.Generic; using System.Drawing; using System.Drawing.Imaging; using System.Runtime.InteropServices;
public static class Art {
  public static Bitmap Cutout(Bitmap src, int threshold) {
    var bmp = src.Clone(new Rectangle(0, 0, src.Width, src.Height), PixelFormat.Format32bppArgb);
    int w = bmp.Width, h = bmp.Height;
    var data = bmp.LockBits(new Rectangle(0, 0, w, h), ImageLockMode.ReadWrite, PixelFormat.Format32bppArgb);
    var px = new byte[data.Stride * h]; Marshal.Copy(data.Scan0, px, 0, px.Length);
    Func<int, int, int> idx = (x, y) => y * data.Stride + x * 4;
    Func<int, int> white = i => Math.Min(px[i], Math.Min(px[i + 1], px[i + 2]));
    var bg = new bool[w * h]; var q = new Queue<int>();
    for (int x = 0; x < w; x++) { q.Enqueue(x); q.Enqueue((h - 1) * w + x); }
    for (int y = 0; y < h; y++) { q.Enqueue(y * w); q.Enqueue(y * w + w - 1); }
    while (q.Count > 0) {
      int p = q.Dequeue(); if (bg[p]) continue;
      int x = p % w, y = p / w; if (white(idx(x, y)) < threshold) continue;
      bg[p] = true;
      if (x > 0) q.Enqueue(p - 1); if (x < w - 1) q.Enqueue(p + 1); if (y > 0) q.Enqueue(p - w); if (y < h - 1) q.Enqueue(p + w);
    }
    // Background and its edge: alpha from how far from white; colour un-mixed from white.
    for (int y = 0; y < h; y++) for (int x = 0; x < w; x++) {
      int p = y * w + x; bool edge = bg[p];
      if (!edge) { // a pixel next to the background is an edge pixel too
        if ((x > 0 && bg[p - 1]) || (x < w - 1 && bg[p + 1]) || (y > 0 && bg[p - w]) || (y < h - 1 && bg[p + w])) edge = true;
      }
      if (!edge) continue;
      int i = idx(x, y); int wv = white(i); int a = 255 - wv;
      if (!bg[p]) a = Math.Max(a, 160);
      if (a <= 0) { px[i + 3] = 0; continue; }
      for (int c = 0; c < 3; c++) { int v = (px[i + c] - 255 + a) * 255 / a; px[i + c] = (byte)Math.Max(0, Math.Min(255, v)); }
      px[i + 3] = (byte)a;
    }
    Marshal.Copy(px, 0, data.Scan0, px.Length); bmp.UnlockBits(data);
    return bmp;
  }
  public static Rectangle Content(Bitmap bmp) {
    int w = bmp.Width, h = bmp.Height, x0 = w, y0 = h, x1 = 0, y1 = 0;
    var data = bmp.LockBits(new Rectangle(0, 0, w, h), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
    var px = new byte[data.Stride * h]; Marshal.Copy(data.Scan0, px, 0, px.Length); bmp.UnlockBits(data);
    for (int y = 0; y < h; y++) for (int x = 0; x < w; x++) if (px[y * data.Stride + x * 4 + 3] > 12) { if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y; }
    int m = (int)(0.03 * Math.Max(x1 - x0, y1 - y0));
    x0 = Math.Max(0, x0 - m); y0 = Math.Max(0, y0 - m); x1 = Math.Min(w - 1, x1 + m); y1 = Math.Min(h - 1, y1 + m);
    return new Rectangle(x0, y0, x1 - x0 + 1, y1 - y0 + 1);
  }
}
'@
$src = [System.Drawing.Bitmap]::new((Resolve-Path $In).Path)
$cut = [Art]::Cutout($src, $Threshold); $src.Dispose()
$r = [Art]::Content($cut)
$height = [int]([math]::Round($r.Height * $Width / $r.Width))
$outBmp = [System.Drawing.Bitmap]::new($Width, $height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g = [System.Drawing.Graphics]::FromImage($outBmp)
$g.InterpolationMode = 'HighQualityBicubic'; $g.SmoothingMode = 'HighQuality'; $g.PixelOffsetMode = 'HighQuality'; $g.CompositingQuality = 'HighQuality'
$g.DrawImage($cut, [System.Drawing.Rectangle]::new(0, 0, $Width, $height), $r, [System.Drawing.GraphicsUnit]::Pixel)
$g.Dispose(); $cut.Dispose()
$full = [IO.Path]::GetFullPath($Out); New-Item -ItemType Directory -Force (Split-Path $full) | Out-Null
$outBmp.Save($full, [System.Drawing.Imaging.ImageFormat]::Png); $outBmp.Dispose()
"{0}: {1} x {2}, {3:N0} KB" -f $full, $Width, $height, ((Get-Item $full).Length / 1KB)
