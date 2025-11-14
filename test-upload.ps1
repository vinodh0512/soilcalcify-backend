# Create a test PNG file
$pngData = [byte[]] @(
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  # IHDR chunk start
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,  # 1x1 pixel
    0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,  # bit depth, color type, etc.
    0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,  # IDAT chunk
    0x54, 0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,  # IEND chunk
    0xAE, 0x42, 0x60, 0x82
)

[System.IO.File]::WriteAllBytes("test-avatar.png", $pngData)
Write-Host "Created test-avatar.png"

# Test the upload with Invoke-RestMethod
try {
    Write-Host "Testing upload to backend..."
    
    # You'll need to replace YOUR_TEST_TOKEN with an actual JWT token
    $headers = @{
        "Authorization" = "Bearer YOUR_TEST_TOKEN"
    }
    
    $filePath = "test-avatar.png"
    $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
    $fileEnc = [System.Text.Encoding]::GetEncoding('UTF-8').GetString($fileBytes)
    
    $boundary = [System.Guid]::NewGuid().ToString()
    $LF = "`r`n"
    
    $bodyLines = (
        "--$boundary",
        "Content-Disposition: form-data; name=`"file`"; filename=`"test-avatar.png`"",
        "Content-Type: image/png",
        "",
        $fileEnc,
        "--$boundary--"
    ) -join $LF
    
    $response = Invoke-RestMethod -Uri "http://localhost:8090/api/me/upload" -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $bodyLines -Headers $headers
    
    Write-Host "Upload successful! Response: $response"
} catch {
    Write-Host "Upload failed: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
        Write-Host "Response: $responseBody"
    }
}

# Clean up
Remove-Item -Force "test-avatar.png"