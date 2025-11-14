const fs = require('fs');
const path = require('path');
const { fileTypeFromFile } = require('file-type');

// Function to analyze any image file
async function analyzeImage(filePath) {
  console.log(`🔍 Analyzing file: ${filePath}`);
  
  try {
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      console.log(`❌ File not found: ${filePath}`);
      return { error: 'File not found' };
    }
    
    // Get file stats
    const stats = fs.statSync(filePath);
    console.log(`📊 File size: ${(stats.size / 1024).toFixed(2)} KB`);
    console.log(`📅 Modified: ${stats.mtime}`);
    
    // Read first few bytes to check file signature
    const buffer = Buffer.alloc(256);
    const fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buffer, 0, 256, 0);
    fs.closeSync(fd);
    
    console.log(`🔢 First 16 bytes (hex): ${buffer.slice(0, 16).toString('hex')}`);
    
    // Check for common file signatures
    const signatures = {
      'PNG': [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
      'JPG': [0xFF, 0xD8, 0xFF],
      'PDF': [0x25, 0x50, 0x44, 0x46],
      'WEBP': [0x52, 0x49, 0x46, 0x46]
    };
    
    for (const [format, signature] of Object.entries(signatures)) {
      const matches = signature.every((byte, i) => buffer[i] === byte);
      if (matches) {
        console.log(`✅ File signature matches: ${format}`);
        break;
      }
    }
    
    // Test file-type detection
    const fileType = await fileTypeFromFile(filePath);
    console.log(`🔍 File-type detection result:`, fileType);
    
    if (!fileType) {
      console.log(`⚠️  Could not detect file type - file might be corrupted or unsupported`);
      return { error: 'Could not detect file type' };
    }
    
    // Check if it's an allowed type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
    if (!allowedTypes.includes(fileType.mime)) {
      console.log(`❌ File type ${fileType.mime} is not allowed`);
      console.log(`✅ Allowed types: ${allowedTypes.join(', ')}`);
      return { error: 'Invalid file type', detectedType: fileType.mime };
    }
    
    console.log(`✅ File type ${fileType.mime} is allowed`);
    return {
      success: true,
      fileType: fileType,
      size: stats.size,
      mimeType: fileType.mime
    };
    
  } catch (error) {
    console.error(`❌ Error analyzing file:`, error.message);
    return { error: error.message };
  }
}

// Function to create a test PNG file that should definitely work
function createTestPortrait() {
  // Create a minimal but valid PNG file
  const pngData = Buffer.from([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
    0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
    0x49, 0x48, 0x44, 0x52, // IHDR
    0x00, 0x00, 0x01, 0x00, // width: 256 pixels
    0x00, 0x00, 0x01, 0x00, // height: 256 pixels
    0x08, 0x02, 0x00, 0x00, 0x00, // bit depth, color type, compression, filter, interlace
    0x90, 0x77, 0x53, 0xDE, // CRC
    0x00, 0x00, 0x00, 0x0C, // IDAT chunk length
    0x49, 0x44, 0x41, 0x54, // IDAT
    0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, // compressed data
    0x00, 0x00, 0x00, 0x00, // IEND chunk length
    0x49, 0x45, 0x4E, 0x44, // IEND
    0xAE, 0x42, 0x60, 0x82  // CRC
  ]);
  
  const testPath = path.join(__dirname, 'portrait-test.png');
  fs.writeFileSync(testPath, pngData);
  console.log(`🖼️  Created test portrait image: ${testPath}`);
  return testPath;
}

// Main function
async function main() {
  console.log('🔧 Image File Diagnostic Tool');
  console.log('=============================');
  
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log('Usage: node diagnose-image.js <path-to-your-image>');
    console.log('\nCreating a test portrait image that should work...');
    
    const testPath = createTestPortrait();
    const result = await analyzeImage(testPath);
    
    if (result.success) {
      console.log('\n✅ Test image analysis successful!');
      console.log('This image should upload successfully to your profile.');
      console.log(`Try uploading: ${testPath}`);
    }
    
  } else {
    // Analyze the user's image
    const imagePath = path.resolve(args[0]);
    console.log(`Analyzing your image: ${imagePath}`);
    
    const result = await analyzeImage(imagePath);
    
    if (result.success) {
      console.log('\n✅ Your image file is valid and should upload successfully!');
      console.log(`File type: ${result.fileType.ext} (${result.fileType.mime})`);
      console.log(`File size: ${(result.size / 1024).toFixed(2)} KB`);
      
      if (result.size > 5 * 1024 * 1024) {
        console.log('⚠️  Warning: File size exceeds 5MB limit. Please resize or compress.');
      }
      
    } else {
      console.log('\n❌ Your image file has issues:');
      console.log(`Problem: ${result.error}`);
      
      if (result.detectedType) {
        console.log(`Detected type: ${result.detectedType} (not allowed)`);
      }
      
      console.log('\n💡 Suggestions:');
      console.log('- Make sure the file is a valid JPG, PNG, WebP, or PDF');
      console.log('- Try opening and re-saving the image in an image editor');
      console.log('- Check if the file is corrupted or incomplete');
      console.log('- Ensure the file extension matches the actual format');
    }
  }
}

// Run the diagnostic
main().catch(console.error);