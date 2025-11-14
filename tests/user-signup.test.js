// Unit and integration tests for signup using Node's built-in test runner
// Run with: npm run test

const { test, before, after, strictEqual } = require('node:test')
const assert = require('node:assert')
const http = require('node:http')
const fetch = global.fetch || require('node-fetch')

const { app, userExists, createUser } = require('../server')

// Mock pool for unit tests
function makeMockPool({ exists = false, failInsert = false } = {}) {
  return {
    execute: async (sql, params) => {
      if (/SELECT/i.test(sql)) {
        return [exists ? [{ id: 1 }] : []]
      }
      if (/INSERT/i.test(sql)) {
        if (failInsert) {
          const err = new Error('Duplicate entry')
          err.code = 'ER_DUP_ENTRY'
          throw err
        }
        return [{ insertId: 123 }]
      }
      return [[]]
    },
  }
}

test('userExists returns false when no record', async () => {
  const pool = makeMockPool({ exists: false })
  const result = await userExists(pool, 'noreply@example.com')
  assert.strictEqual(result, false)
})

test('userExists returns true when record exists', async () => {
  const pool = makeMockPool({ exists: true })
  const result = await userExists(pool, 'exists@example.com')
  assert.strictEqual(result, true)
})

test('createUser returns insertId', async () => {
  const pool = makeMockPool()
  const id = await createUser(pool, { name: 'Test', email: 't@example.com', passwordHash: 'hash' })
  assert.strictEqual(id, 123)
})

test('createUser duplicate error surfaces with code', async () => {
  const pool = makeMockPool({ failInsert: true })
  await assert.rejects(() => createUser(pool, { name: 'Test', email: 't@example.com', passwordHash: 'hash' }), { code: 'ER_DUP_ENTRY' })
})

// Lightweight integration test (requires running server instance)
test('GET /health responds ok', async (t) => {
  const server = http.createServer(app)
  await new Promise((resolve) => server.listen(0, resolve))
  const { port } = server.address()
  const res = await fetch(`http://127.0.0.1:${port}/health`)
  assert.strictEqual(res.status, 200)
  const json = await res.json()
  assert.strictEqual(json.status, 'ok')
  server.close()
})

test('CSRF token endpoint issues token', async () => {
  const server = http.createServer(app)
  await new Promise((resolve) => server.listen(0, resolve))
  const { port } = server.address()
  const res = await fetch(`http://127.0.0.1:${port}/api/csrf-token`)
  assert.strictEqual(res.status, 200)
  const json = await res.json()
  assert.ok(json.token)
  server.close()
})