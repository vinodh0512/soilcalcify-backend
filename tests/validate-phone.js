const assert = require('assert')

function validatePhoneE164(phone) {
  const p = String(phone || '').trim()
  return /^\+[1-9]\d{1,14}$/.test(p)
}

const valid = ['+12025550123', '+447911123456', '+918888888888']
const invalid = ['2025550123', '+012345', '+1abc', '+1234567890123456']

for (const v of valid) assert.ok(validatePhoneE164(v), `Expected valid: ${v}`)
for (const v of invalid) assert.ok(!validatePhoneE164(v), `Expected invalid: ${v}`)

console.log('Phone E.164 validation tests passed')