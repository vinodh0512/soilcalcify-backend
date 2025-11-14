function sanitizeText(str, { maxLen = 255 } = {}) {
  if (typeof str !== 'string') return ''
  let s = str.trim().replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ')
  if (s.length > maxLen) s = s.slice(0, maxLen)
  return s
}

async function getById(pool, id) {
  const [rows] = await pool.execute(
    'SELECT id, name, email, first_name, last_name, phone, company, title, bio, location, website_url, twitter_url, linkedin_url, github_url, updated_at FROM users WHERE id = ? LIMIT 1',
    [id]
  )
  return rows && rows[0] ? rows[0] : null
}

async function updateProfile(pool, id, fields) {
  const updates = []
  const params = []
  for (const [k, v] of Object.entries(fields)) {
    if (typeof v === 'string') {
      updates.push(`${k} = ?`)
      params.push(sanitizeText(v))
    } else if (v === null) {
      updates.push(`${k} = NULL`)
    }
  }
  if (!updates.length) return false
  params.push(id)
  const [res] = await pool.execute(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params)
  return res && res.affectedRows > 0
}


async function searchByName(pool, q, { limit = 20, offset = 0 } = {}) {
  const like = `%${sanitizeText(q, { maxLen: 50 })}%`
  const [rows] = await pool.execute(
    'SELECT id, first_name, last_name, email FROM users WHERE first_name LIKE ? OR last_name LIKE ? ORDER BY last_name ASC, first_name ASC LIMIT ? OFFSET ?',
    [like, like, limit, offset]
  )
  return rows || []
}

module.exports = { getById, updateProfile, searchByName }