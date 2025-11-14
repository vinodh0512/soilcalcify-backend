const fs = require('fs');
const path = require('path');

async function testProfileUpload() {
  try {
    // Create a simple PNG file for testing
    const testFile = path.join(__dirname, 'test-avatar.png');
    
    // Minimal valid PNG file (1x1 pixel)
    const pngData = Buffer.from([
      0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
      0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk start
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 pixel
      0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, // bit depth, color type, etc.
      0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, // IDAT chunk
      0x54, 0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0x00,
      0xFF, 0xFF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND chunk
      0xAE, 0x42, 0x60, 0x82
    ]);
    
    fs.writeFileSync(testFile, pngData);
    
    console.log('Created test PNG file:', testFile);
    console.log('File size:', fs.statSync(testFile).size, 'bytes');
    
    // Test file type detection locally first
    const { fileTypeFromFile } = require('file-type');
    const fileType = await fileTypeFromFile(testFile);
    console.log('Local file type detection:', fileType);
    
    // Clean up
    fs.unlinkSync(testFile);
    console.log('Test completed successfully!');
    
  } catch (error) {
    console.error('Test failed:', error.message);
  }
}

testProfileUpload();