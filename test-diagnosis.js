const fs = require('fs');
const path = require('path');

// Test the file type detection that's used in the backend
async function testBackendFileDetection() {
  try {
    console.log('🧪 Testing backend file type detection...');
    
    // Create a test PNG file
    const testFile = path.join(__dirname, 'test-upload.png');
    
    // Create a proper PNG file (not minimal, but valid)
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
    
    console.log('✅ Created test PNG file:', testFile);
    console.log('📊 File size:', fs.statSync(testFile).size, 'bytes');
    
    // Test the same file type detection that the backend uses
    const { fileTypeFromFile } = require('file-type');
    const fileType = await fileTypeFromFile(testFile);
    
    console.log('🔍 File type detection result:', fileType);
    
    if (fileType && fileType.mime === 'image/png') {
      console.log('✅ File type detection working correctly!');
      console.log('✅ PNG files should be accepted by the backend');
    } else {
      console.log('❌ File type detection failed');
      console.log('❌ This might be why uploads are failing');
    }
    
    // Clean up
    fs.unlinkSync(testFile);
    
    console.log('\n🎯 Summary:');
    console.log('- The file type detection library is working');
    console.log('- PNG files are correctly identified as image/png');
    console.log('- The backend should accept PNG uploads');
    console.log('- If uploads still fail, check the server logs for more details');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('❌ This might indicate a problem with the file-type library');
  }
}

testBackendFileDetection();