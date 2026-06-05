// =====================================================================
// routes/labDemos.js  —  KCA Lab Demos
// Mount in server.js:
//
//   const labDemos = require('./routes/labDemos');
//   app.use('/api', labDemos(pool, auth, adminOnly));
//
//   pool      = your mysql2/promise pool (has .query returning [rows])
//   auth      = middleware that sets req.user from the JWT (kca_token)
//   adminOnly = middleware that 403s non-admins
//
// Requires:  npm i @aws-sdk/client-s3 @aws-sdk/s3-request-presigner
// Env vars:  AWS_REGION, KCA_LAB_BUCKET   (credentials via EC2 IAM role)
// =====================================================================

const express = require('express');
const crypto = require('crypto');
const {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
  DeleteObjectCommand,
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const REGION = process.env.AWS_REGION || 'us-east-1';
const BUCKET = process.env.KCA_LAB_BUCKET || 'kca-lab-demos';
const PLAY_URL_TTL = 60 * 60 * 2;   // playback links valid 2h
const UPLOAD_URL_TTL = 60 * 15;     // upload links valid 15m

// Credentials resolve automatically from the EC2 instance IAM role.
const s3 = new S3Client({ region: REGION });

function slugify(str) {
  return String(str || 'video')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
}

// Optional: flip this to read req.user.is_subscribed / req.user.plan from
// however your JWT encodes subscription. Returns true if the user may watch
// premium content. Free demos ignore this entirely.
function hasPremiumAccess(user) {
  if (!user) return false;
  return Boolean(user.is_admin || user.is_subscribed || user.subscribed || user.premium);
}

module.exports = function labDemos(pool, auth, adminOnly) {
  const router = express.Router();

  // ---- helper: run a query and return rows -------------------------
  const q = async (sql, params = []) => {
    const [rows] = await pool.query(sql, params);
    return rows;
  };

  // =================================================================
  // STUDENT ENDPOINTS  (require login)
  // =================================================================

  // List published demos (catalog). Un-published topics are also returned
  // but flagged is_published=0 so the UI can show "Coming soon".
  router.get('/lab-demos', auth, async (req, res) => {
    try {
      const rows = await q(
        `SELECT id, topic_number, title, category, description,
                duration_seconds, is_published, is_premium
           FROM lab_demos
          ORDER BY sort_order ASC, topic_number ASC`
      );
      res.json(rows);
    } catch (err) {
      console.error('[lab-demos] list error:', err);
      res.status(500).json({ error: 'Failed to load lab demos' });
    }
  });

  // Get a short-lived presigned playback URL for one demo.
  router.get('/lab-demos/:id/play', auth, async (req, res) => {
    try {
      const rows = await q(
        `SELECT id, title, s3_key, is_published, is_premium
           FROM lab_demos WHERE id = ? LIMIT 1`,
        [req.params.id]
      );
      const demo = rows[0];
      if (!demo) return res.status(404).json({ error: 'Demo not found' });
      if (!demo.is_published || !demo.s3_key)
        return res.status(409).json({ error: 'This demo is not available yet' });
      if (demo.is_premium && !hasPremiumAccess(req.user))
        return res.status(403).json({ error: 'Subscription required for this demo' });

      const url = await getSignedUrl(
        s3,
        new GetObjectCommand({ Bucket: BUCKET, Key: demo.s3_key }),
        { expiresIn: PLAY_URL_TTL }
      );
      res.json({ url, title: demo.title, expiresIn: PLAY_URL_TTL });
    } catch (err) {
      console.error('[lab-demos] play error:', err);
      res.status(500).json({ error: 'Failed to generate playback link' });
    }
  });

  // =================================================================
  // ADMIN ENDPOINTS
  // =================================================================

  // Full list incl. unpublished + s3_key (for the admin panel).
  router.get('/admin/lab-demos', auth, adminOnly, async (req, res) => {
    try {
      const rows = await q(
        `SELECT id, topic_number, title, category, description, s3_key,
                duration_seconds, is_published, is_premium, sort_order,
                created_at, updated_at
           FROM lab_demos
          ORDER BY sort_order ASC, topic_number ASC`
      );
      res.json(rows);
    } catch (err) {
      console.error('[lab-demos] admin list error:', err);
      res.status(500).json({ error: 'Failed to load demos' });
    }
  });

  // Request a presigned PUT URL so the browser uploads the video
  // DIRECTLY to S3 (the file never touches the EC2 box).
  // body: { id, filename, contentType }
  router.post('/admin/lab-demos/presign-upload', auth, adminOnly, async (req, res) => {
    try {
      const { id, filename, contentType } = req.body || {};
      if (!id || !filename)
        return res.status(400).json({ error: 'id and filename are required' });

      const rows = await q(`SELECT topic_number, title FROM lab_demos WHERE id = ?`, [id]);
      const demo = rows[0];
      if (!demo) return res.status(404).json({ error: 'Demo not found' });

      const ext = (filename.split('.').pop() || 'mp4').toLowerCase().replace(/[^a-z0-9]/g, '');
      const rand = crypto.randomBytes(4).toString('hex');
      const key = `lab-demos/${String(demo.topic_number).padStart(2, '0')}-${slugify(demo.title)}-${rand}.${ext}`;
      const type = contentType || 'video/mp4';

      const uploadUrl = await getSignedUrl(
        s3,
        new PutObjectCommand({ Bucket: BUCKET, Key: key, ContentType: type }),
        { expiresIn: UPLOAD_URL_TTL }
      );
      res.json({ uploadUrl, key, contentType: type, expiresIn: UPLOAD_URL_TTL });
    } catch (err) {
      console.error('[lab-demos] presign-upload error:', err);
      res.status(500).json({ error: 'Failed to create upload link' });
    }
  });

  // Update a demo (used after upload to save the key + publish, and to edit).
  // body: any of { title, category, description, s3_key, duration_seconds,
  //                is_published, is_premium, sort_order }
  router.put('/admin/lab-demos/:id', auth, adminOnly, async (req, res) => {
    try {
      const allowed = ['title', 'category', 'description', 's3_key',
        'duration_seconds', 'is_published', 'is_premium', 'sort_order'];
      const sets = [];
      const vals = [];
      for (const f of allowed) {
        if (Object.prototype.hasOwnProperty.call(req.body, f)) {
          sets.push(`${f} = ?`);
          vals.push(req.body[f]);
        }
      }
      if (!sets.length) return res.status(400).json({ error: 'Nothing to update' });
      vals.push(req.params.id);
      await q(`UPDATE lab_demos SET ${sets.join(', ')} WHERE id = ?`, vals);
      const rows = await q(`SELECT * FROM lab_demos WHERE id = ?`, [req.params.id]);
      res.json(rows[0]);
    } catch (err) {
      console.error('[lab-demos] update error:', err);
      res.status(500).json({ error: 'Failed to update demo' });
    }
  });

  // Create a brand-new demo (beyond the seeded 23).
  router.post('/admin/lab-demos', auth, adminOnly, async (req, res) => {
    try {
      const { topic_number, title, category, description, sort_order } = req.body || {};
      if (!title || !category)
        return res.status(400).json({ error: 'title and category are required' });
      const next = topic_number || (
        (await q(`SELECT COALESCE(MAX(topic_number),0)+1 AS n FROM lab_demos`))[0].n
      );
      const result = await q(
        `INSERT INTO lab_demos (topic_number, title, category, description, sort_order)
         VALUES (?, ?, ?, ?, ?)`,
        [next, title, category, description || '', sort_order || next]
      );
      const rows = await q(`SELECT * FROM lab_demos WHERE id = ?`, [result.insertId]);
      res.status(201).json(rows[0]);
    } catch (err) {
      console.error('[lab-demos] create error:', err);
      res.status(500).json({ error: 'Failed to create demo' });
    }
  });

  // Delete a demo (and best-effort remove the S3 object).
  router.delete('/admin/lab-demos/:id', auth, adminOnly, async (req, res) => {
    try {
      const rows = await q(`SELECT s3_key FROM lab_demos WHERE id = ?`, [req.params.id]);
      const demo = rows[0];
      if (!demo) return res.status(404).json({ error: 'Demo not found' });
      if (demo.s3_key) {
        try {
          await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: demo.s3_key }));
        } catch (e) {
          console.warn('[lab-demos] S3 delete warning:', e.message);
        }
      }
      await q(`DELETE FROM lab_demos WHERE id = ?`, [req.params.id]);
      res.json({ ok: true });
    } catch (err) {
      console.error('[lab-demos] delete error:', err);
      res.status(500).json({ error: 'Failed to delete demo' });
    }
  });

  return router;
};
