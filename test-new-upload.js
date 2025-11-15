const fs = require('fs');
const axios = require('axios');
const path = require('path');

async function testNewUpload() {
  console.log('🧪 Testing new image upload endpoint...');
  
  try {
    // First, login to get auth token
    console.log('🔑 Logging in...');
    const loginResponse = await axios.post('http://localhost:8091/api/login', {
      email: 'testupload@example.com',
      password: 'test123'
    });
    
    const token = loginResponse.data.token;
    console.log('✅ Login successful, token received');
    
    // Create a simple test image (1x1 red PNG)
    const testImagePath = path.join(__dirname, 'test-red-dot.png');
    
    // Create a minimal 1x1 red PNG in base64
    const redDotBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==';
    const base64Data = `data:image/png;base64,${redDotBase64}`;
    
    console.log('📤 Uploading test image...');
    
    // Upload using the new endpoint
    const uploadResponse = await axios.post('http://localhost:8091/api/me/image', {
      image_data: base64Data,
      image_type: 'avatar',
      mime_type: 'image/png'
    }, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    
    console.log('✅ Upload response:', uploadResponse.data);
    
    // Test retrieval
    const imageId = uploadResponse.data.id;
    console.log(`🖼️  Testing retrieval of image ${imageId}...`);
    
    const imageResponse = await axios.get(`http://localhost:8091/api/me/image/${imageId}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    console.log('✅ Image retrieval successful');
    console.log('📊 Response headers:', imageResponse.headers['content-type']);
    
    // Clean up test file
    if (fs.existsSync(testImagePath)) {
      fs.unlinkSync(testImagePath);
    }
    
    console.log('🎉 All tests passed! Image upload and persistence working correctly.');
    
  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Headers:', error.response.headers);
    }
  }
}

testNewUpload();