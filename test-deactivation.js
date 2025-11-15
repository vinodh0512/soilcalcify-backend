const axios = require('axios');

async function testMultipleUploads() {
  console.log('🧪 Testing multiple image uploads (deactivation behavior)...');
  
  try {
    // Login to get auth token
    const loginResponse = await axios.post('http://localhost:8091/api/login', {
      email: 'testupload@example.com',
      password: 'test123'
    });
    
    const token = loginResponse.data.token;
    console.log('✅ Login successful');
    
    // Create test images
    const redDotBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==';
    const blueDotBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
    
    console.log('\n📤 Uploading first image (red dot)...');
    const upload1 = await axios.post('http://localhost:8091/api/me/image', {
      image_data: `data:image/png;base64,${redDotBase64}`,
      image_type: 'avatar',
      mime_type: 'image/png'
    }, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    console.log('✅ First upload:', upload1.data);
    
    console.log('\n📤 Uploading second image (blue dot)...');
    const upload2 = await axios.post('http://localhost:8091/api/me/image', {
      image_data: `data:image/png;base64,${blueDotBase64}`,
      image_type: 'avatar',
      mime_type: 'image/png'
    }, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    console.log('✅ Second upload:', upload2.data);
    
    console.log('\n🔍 Testing retrieval of both images...');
    
    // Test first image (should be deactivated)
    try {
      const image1Response = await axios.get(`http://localhost:8091/api/me/image/${upload1.data.id}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      console.log('❌ First image still accessible (unexpected)');
    } catch (error) {
      if (error.response?.status === 404) {
        console.log('✅ First image correctly deactivated (404)');
      } else {
        console.log('❌ Unexpected error for first image:', error.response?.status);
      }
    }
    
    // Test second image (should be active)
    try {
      const image2Response = await axios.get(`http://localhost:8091/api/me/image/${upload2.data.id}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      console.log('✅ Second image correctly active and accessible');
    } catch (error) {
      console.log('❌ Second image not accessible:', error.response?.status);
    }
    
    console.log('\n🎉 Deactivation behavior test completed!');
    
  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
  }
}

testMultipleUploads();