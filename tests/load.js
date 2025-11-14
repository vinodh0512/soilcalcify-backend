// Simple load test: concurrent signup requests
// Run with: npm run load

const http = require('node:http')
const fetch = global.fetch || require('node-fetch')
const { app } = require('../server')

async function main() {
  const server = http.createServer(app)
  await new Promise((resolve) => server.listen(0, resolve))
  const { port } = server.address()
  const base = `http://127.0.0.1:${port}`

  // Get CSRF token
  const tokenRes = await fetch(`${base}/api/csrf-token`)
  const tokenJson = await tokenRes.json()
  const token = tokenJson.token
  const cookie = tokenRes.headers.get('set-cookie')

  const total = 25
  const runners = Array.from({ length: total }).map((_, i) => {
    const body = {
      name: `LoadTester ${i}`,
      email: `loadtester${i}@example.com`,
      password: 'P@ssw0rd1234',
    }
    return fetch(`${base}/api/signup`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': token,
        'cookie': cookie || `${'csrfToken'}=${token}`,
      },
      body: JSON.stringify(body),
    }).then((res) => ({ status: res.status }))
  })

  const start = Date.now()
  const results = await Promise.all(runners)
  const ms = Date.now() - start
  const summary = results.reduce((acc, r) => {
    acc[r.status] = (acc[r.status] || 0) + 1
    return acc
  }, {})
  console.log(`Load test finished in ${ms}ms. Status summary:`, summary)
  server.close()
}

main().catch((err) => {
  console.error('Load test error:', err)
  process.exit(1)
})