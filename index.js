// Production entrypoint for Railway
const path = require('path')
const dotenv = require('dotenv')
dotenv.config({ path: path.join(__dirname, '.env') })

const { app } = require('./server')

const PORT = process.env.PORT || 5000

function listenWithRetry(startPort, maxAttempts) {
  return new Promise((resolve, reject) => {
    let current = startPort
    let remaining = Math.max(Number(maxAttempts) || 1, 1)
    function attempt() {
      const server = app.listen(current, '0.0.0.0', () => resolve({ server, port: current }))
      server.on('error', (err) => {
        if (err && err.code === 'EADDRINUSE' && remaining > 0) {
          remaining -= 1
          current += 1
          attempt()
        } else {
          reject(err)
        }
      })
    }
    attempt()
  })
}

listenWithRetry(Number(PORT), 10)
  .then(({ port }) => {
    console.log(`SoilCalcify backend listening on http://localhost:${port}`)
  })
  .catch((err) => {
    console.error('Server start failed:', err?.message || String(err))
    process.exit(1)
  })