const { test, strictEqual, ok } = require('node:test')
const assert = require('node:assert')

const { saveCalculationHistory, getCalculationHistory } = require('../server')

// Mock connection and pool for transactional insert
function makeMockConn({ failInsert = false } = {}) {
  const calls = []
  return {
    calls,
    beginTransaction: async () => { calls.push('begin') },
    commit: async () => { calls.push('commit') },
    rollback: async () => { calls.push('rollback') },
    release: () => { calls.push('release') },
    execute: async (sql, params) => {
      calls.push({ sql, params })
      if (/INSERT/i.test(sql)) {
        if (failInsert) throw new Error('Insert failed')
        return [{ insertId: 987 }]
      }
      return [[]]
    },
  }
}

function makeMockPool(conn) {
  return {
    getConnection: async () => conn,
    execute: async (sql, params) => {
      // simulate SELECT queries for history and count
      if (/SELECT id, user_id, params, result, performed_at/i.test(sql)) {
        return [[
          { id: 3, user_id: 1, params: '{"a":1}', result: '{"ok":true}', performed_at: new Date().toISOString() },
          { id: 2, user_id: 1, params: '{"b":2}', result: '{"ok":true}', performed_at: new Date().toISOString() },
        ]]
      }
      if (/SELECT COUNT\(\*\)/i.test(sql)) {
        return [[{ total: 2 }]]
      }
      return [[]]
    },
  }
}

test('saveCalculationHistory inserts and returns id', async () => {
  const conn = makeMockConn()
  const pool = makeMockPool(conn)
  const id = await saveCalculationHistory(pool, { userId: 1, params: { x: 1 }, result: { y: 2 } })
  assert.strictEqual(id, 987)
  assert.ok(conn.calls.find(c => c === 'begin'))
  assert.ok(conn.calls.find(c => c === 'commit'))
  assert.ok(conn.calls.find(c => c === 'release'))
})

test('saveCalculationHistory rolls back on error', async () => {
  const conn = makeMockConn({ failInsert: true })
  const pool = makeMockPool(conn)
  await assert.rejects(() => saveCalculationHistory(pool, { userId: 1, params: {}, result: {} }))
  assert.ok(conn.calls.find(c => c === 'rollback'))
  assert.ok(conn.calls.find(c => c === 'release'))
})

test('getCalculationHistory returns items with pagination', async () => {
  const pool = makeMockPool(makeMockConn())
  const data = await getCalculationHistory(pool, { userId: 1, limit: 20, page: 1 })
  assert.strictEqual(Array.isArray(data.items), true)
  assert.strictEqual(data.items.length, 2)
  assert.strictEqual(data.limit, 20)
  assert.strictEqual(data.page, 1)
  assert.strictEqual(data.total, 2)
})

test('getCalculationHistory caps limit to 100', async () => {
  const pool = makeMockPool(makeMockConn())
  const data = await getCalculationHistory(pool, { userId: 1, limit: 999, page: 1 })
  assert.strictEqual(data.limit, 100)
})