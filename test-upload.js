const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const axios = require('axios');

// Create a minimal valid PNG file for testing
const pngSignature = Buffer.from([
  0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
  0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
  0x49, 0x48, 0x44, 0x52, // IHDR
  0x00, 0x00, 0x00, 0x01, // width: 1
  0x00, 0x00, 0x00, 0x01, // height: 1
  0x08, 0x02, 0x00, 0x00, 0x00, // bit depth, color type, compression, filter, interlace
  0x90, 0x77, 0x53, 0xDE, // CRC
  0x00, 0x00, 0x00, 0x0C, // IDAT chunk length
  0x49, 0x44, 0x41, 0x54, // IDAT
  0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, // compressed data
  0x00, 0x00, 0x00, 0x00, // IEND chunk length
  0x49, 0x45, 0x4E, 0x44, // IEND
  0xAE, 0x42, 0x60, 0x82  // CRC
]);

async function testUpload() {
  console.log('🧪 Starting comprehensive upload test...');
  
  try {
    // First, let's test authentication
    console.log('🔑 Testing authentication...');
    
    // Try to login first to get a valid JWT token
    const loginData = {
      email: 'testupload@example.com',
      password: 'test123'
    };
    
    let token;
    try {
      const loginResponse = await axios.post('http://localhost:8090/api/login', loginData);
      token = loginResponse.data.token;
      console.log('✅ Login successful, token obtained');
    } catch (error) {
      console.log('❌ Login failed:', error.response?.data || error.message);
      return;
    }
    
    // Create test PNG file
    const testFilePath = path.join(__dirname, 'test-avatar.png');
    fs.writeFileSync(testFilePath, pngSignature);
    console.log('✅ Test PNG file created');
    
    // Create form data
    const formData = new FormData();
    formData.append('file', fs.createReadStream(testFilePath), {
      filename: 'test-avatar.png',
      contentType: 'image/png'
    });
    
    console.log('📤 Uploading file...');
    
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
    console.log('📋 Response data:', uploadResponse.data);
    
    // Test getting the avatar
    console.log('🔍 Testing user info retrieval...');
    const userResponse = await axios.get('http://localhost:8090/api/me', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    console.log('✅ User info retrieval successful!');
    console.log('📋 User data:', userResponse.data);
    
    // Clean up
    fs.unlinkSync(testFilePath);
    console.log('🧹 Test file cleaned up');
    
    console.log('\n🎉 All tests passed! Profile photo upload is working correctly.');
    
  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Headers:', error.response.headers);
    }
  }
}

// Run the test
testUpload();