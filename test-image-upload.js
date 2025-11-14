const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const axios = require('axios');

// Helper function to test file upload with any image
async function testImageUpload(imagePath, description = 'test image') {
  console.log(`🧪 Testing upload of ${description}...`);
  console.log(`📁 File path: ${imagePath}`);
  
  try {
    // Check if file exists
    if (!fs.existsSync(imagePath)) {
      console.log(`❌ File not found: ${imagePath}`);
      return;
    }
    
    // Check file stats
    const stats = fs.statSync(imagePath);
    console.log(`📊 File size: ${(stats.size / 1024).toFixed(2)} KB`);
    console.log(`📅 Modified: ${stats.mtime}`);
    
    // Test file type detection first
    const { fileTypeFromFile } = require('file-type');
    const fileType = await fileTypeFromFile(imagePath);
    console.log(`🔍 Detected file type:`, fileType);
    
    if (!fileType) {
      console.log(`⚠️  Could not detect file type - file might be corrupted or unsupported`);
      return;
    }
    
    // Check if it's an allowed type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
    if (!allowedTypes.includes(fileType.mime)) {
      console.log(`❌ File type ${fileType.mime} is not allowed. Allowed types: ${allowedTypes.join(', ')}`);
      return;
    }
    
    console.log(`✅ File type ${fileType.mime} is allowed`);
    
    // Now test actual upload
    console.log(`🔑 Testing authentication...`);
    
    // Login with our test user
    const loginData = {
      email: 'testupload@example.com',
      password: 'test123'
    };
    
    const loginResponse = await axios.post('http://localhost:8090/api/login', loginData);
    const token = loginResponse.data.token;
    console.log('✅ Login successful');
    
    // Create form data
    const formData = new FormData();
    formData.append('file', fs.createReadStream(imagePath), {
      filename: path.basename(imagePath),
      contentType: fileType.mime
    });
    
    console.log(`📤 Uploading ${description}...`);
    
    // Upload the file
    const uploadResponse = await axios.post('http://localhost:8090/api/me/upload', formData, {
      headers: {
        ...formData.getHeaders(),
        'Authorization': `Bearer ${token}`
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });
    
    console.log('✅ Upload successful!');
    console.log('📋 Response:', uploadResponse.data);
    
    // Test getting user info to see if avatar was updated
    console.log('🔍 Checking user profile...');
    const userResponse = await axios.get('http://localhost:8090/api/me', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    console.log('✅ User profile retrieved');
    console.log('📋 Avatar URL:', userResponse.data.user?.avatar_url);
    
    return {
      success: true,
      fileType: fileType,
      uploadResponse: uploadResponse.data,
      avatarUrl: userResponse.data.user?.avatar_url
    };
    
  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Headers:', error.response.headers);
    }
    return {
      success: false,
      error: error.response?.data || error.message
    };
  }
}

// Helper function to create a test image if needed
function createTestImage() {
  const testPng = Buffer.from([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
    0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
    0x54, 0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,
    0xAE, 0x42, 0x60, 0x82
  ]);
  
  const testPath = path.join(__dirname, 'test-portrait.png');
  fs.writeFileSync(testPath, testPng);
  console.log(`🖼️  Created test image: ${testPath}`);
  return testPath;
}

// Main function
async function main() {
  console.log('🚀 Image Upload Troubleshooting Tool');
  console.log('=====================================');
  
  // Check command line arguments
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log('Usage: node test-image-upload.js <path-to-image>');
    console.log('Creating and testing with a sample image...');
    
    const testPath = createTestImage();
    const result = await testImageUpload(testPath, 'sample PNG image');
    
    if (result.success) {
      console.log('\n🎉 Sample image upload test completed successfully!');
      console.log('Your profile photo upload functionality is working correctly.');
    } else {
      console.log('\n❌ Sample image upload test failed.');
      console.log('There may be an issue with the upload system.');
    }
    
    // Clean up
    try {
      fs.unlinkSync(testPath);
      console.log('🧹 Cleaned up test file');
    } catch {}
    
  } else {
    // Test with the provided image
    const imagePath = path.resolve(args[0]);
    const result = await testImageUpload(imagePath, 'your image');
    
    if (result.success) {
      console.log('\n🎉 Your image upload test completed successfully!');
      console.log('The issue might be with the specific file or frontend integration.');
    } else {
      console.log('\n❌ Your image upload test failed.');
      console.log('This indicates there may be an issue with the file or upload system.');
    }
  }
}

// Run the main function
main().catch(console.error);