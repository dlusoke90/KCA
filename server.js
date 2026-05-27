require('dotenv').config();
const express = require('express');
const mysql   = require('mysql2/promise');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const stripe   = require('stripe')(process.env.STRIPE_SECRET_KEY);
const cors    = require('cors');
const helmet  = require('helmet');
const rateLimit = require('express-rate-limit');
const path    = require('path');

const app = express();
const nodemailer = require('nodemailer');
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.json());

// Clean URLs - redirect .html to clean version
app.use((req, res, next) => {
  if (req.path.endsWith('.html')) {
    const clean = req.path.slice(0, -5);
    const qs = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    return res.redirect(301, clean + qs);
  }
  next();
});

// Serve clean URLs - map /login -> /login.html etc
app.use((req, res, next) => {
  const ext = require('path').extname(req.path);
  if (!ext && req.path !== '/') {
    const filePath = require('path').join(__dirname, 'public', req.path + '.html');
    require('fs').access(filePath, require('fs').constants.F_OK, (err) => {
      if (!err) return res.sendFile(filePath);
      next();
    });
  } else {
    next();
  }
});

app.use(express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
app.use('/api/auth', authLimiter);

const pool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     process.env.DB_PORT || 3306,
  user:     process.env.DB_USER || 'kcauser',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'kca_db',
  waitForConnections: true,
  connectionLimit: 10
});

const JWT_SECRET = process.env.JWT_SECRET || 'kca-secret';

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Session expired. Please log in again.' }); }
}


function getInstallmentDueDate(yearMonth, offsetMonths) {
  const [year, month] = yearMonth.split('-').map(Number);
  const d = new Date(year, month - 1 + offsetMonths, 15);
  return d.toISOString().split('T')[0];
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}


const crypto = require('crypto');


app.post('/api/webhooks/stripe', express.raw({type:'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET); }
  catch (err) { return res.status(400).send(`Webhook Error: ${err.message}`); }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const { user_id, course_id, enrollment_id } = session.metadata;
    try {
      await pool.query("UPDATE payments SET status='paid', paid_at=NOW() WHERE stripe_session_id=?", [session.id]);
      await pool.query("UPDATE enrollments SET status='approved' WHERE id=?", [enrollment_id]);
      const [[course]] = await pool.query('SELECT * FROM courses WHERE id=?', [course_id]);
      const remaining = parseFloat(course.price) - parseFloat(course.registration_fee);
      if (remaining > 0 && course.installments > 0 && course.payment_start_month) {
        const amt = (remaining / course.installments).toFixed(2);
        for (let i = 0; i < course.installments; i++) {
          const dueDate = getInstallmentDueDate(course.payment_start_month, i);
          await pool.query('INSERT INTO payments (user_id,course_id,enrollment_id,amount,type,installment_number,status,due_date) VALUES (?,?,?,?,?,?,?,?)',
            [user_id, course_id, enrollment_id, amt, 'installment', i+1, 'pending', dueDate]);
        }
      }
      const [[student]] = await pool.query('SELECT full_name, email FROM users WHERE id=?', [user_id]);
      mailer.sendMail({ from: process.env.EMAIL_USER, to: student.email, subject: 'KCA — Enrollment Confirmed!',
        html: `<h2>Hi ${student.full_name}!</h2><p>Payment received. You are now enrolled in <b>${course.title}</b>. Welcome to KCA!</p>` }).catch(e=>console.error(e.message));
      mailer.sendMail({ from: process.env.EMAIL_USER, to: process.env.EMAIL_USER, subject: 'KCA — New Paid Enrollment',
        html: `<h2>New Paid Enrollment</h2><p><b>Student:</b> ${student.full_name}</p><p><b>Course:</b> ${course.title}</p><p><b>Paid:</b> $${course.registration_fee}</p>` }).catch(e=>console.error(e.message));
    } catch(e) { console.error('Webhook error:', e); }
  }
  res.json({ received: true });
});
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  try {
    const [users] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (!users.length) return res.json({ message: 'If that email exists, a reset link has been sent.' });
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hour
    await pool.query('DELETE FROM password_resets WHERE email = ?', [email]);
    await pool.query('INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)', [email, token, expires]);
    const resetLink = `https://kca-cloudnet.com/reset.html?token=${token}&email=${encodeURIComponent(email)}`;
    await mailer.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'KCA — Password Reset Request',
      html: `<h2>Password Reset</h2><p>You requested a password reset for your KCA account.</p><p>Click the link below to reset your password. This link expires in 1 hour.</p><p><a href="${resetLink}" style="background:#0e8a78;color:#fff;padding:.6rem 1.2rem;border-radius:6px;text-decoration:none">Reset My Password</a></p><br><p>If you did not request this, ignore this email.</p><p>Best regards,<br><b>KCA Team</b></p>`
    });
    res.json({ message: 'If that email exists, a reset link has been sent.' });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Failed to process request' }); }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, token, password } = req.body;
  if (!email || !token || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  try {
    const [rows] = await pool.query('SELECT * FROM password_resets WHERE email = ? AND token = ? AND expires_at > NOW()', [email, token]);
    if (!rows.length) return res.status(400).json({ error: 'Invalid or expired reset link. Please request a new one.' });
    const bcrypt = require('bcryptjs');
    const hash = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password_hash = ? WHERE email = ?', [hash, email]);
    await pool.query('DELETE FROM password_resets WHERE email = ?', [email]);
    res.json({ message: 'Password reset successfully! You can now log in.' });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Reset failed' }); }
});

const multer = require('multer');

// ══════════════════════════════════════════════════════════
//  ALL MULTER INSTANCES — declared here, never inline
// ══════════════════════════════════════════════════════════

// Ticket single image upload
const ticketStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, '/var/www/kca/public/uploads/tickets'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: ticketStorage, limits: { fileSize: 5 * 1024 * 1024 } });

// Ticket multi-image upload
const uploadTicketFields = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, '/var/www/kca/public/uploads/tickets'),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + Math.random().toString(36).slice(2,7) + path.extname(file.originalname))
  }),
  limits: { fileSize: 5 * 1024 * 1024 }
}).fields([{ name: 'image', maxCount: 1 }, { name: 'extra_images', maxCount: 5 }]);


// Comment image upload
const commentStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, '/var/www/kca/public/uploads/comments'),
  filename: (req, file, cb) => cb(null, 'c_' + Date.now() + '_' + Math.random().toString(36).slice(2,7) + path.extname(file.originalname).toLowerCase())
});
const uploadComment = multer({
  storage: commentStorage,
  fileFilter: (req, file, cb) => {
    ['image/jpeg','image/jpg','image/png','image/gif','image/webp'].includes(file.mimetype)
      ? cb(null, true) : cb(new Error('Images only'));
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});

// Assignment file upload
const assignmentStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, '/var/www/kca/public/uploads/assignments'),
  filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname.replace(/\s/g,'_'))
});
const uploadAssignment = multer({ storage: assignmentStorage, limits: { fileSize: 20 * 1024 * 1024 } });


// ══════════════════════════════════════════════════════════

function getUsername(full_name) {
  if(!full_name) return 'deleted-user';
  const parts = full_name.trim().split(' ');
  const first = (parts[0]||'user').toLowerCase();
  const last = (parts[1]||'').toLowerCase();
  return last ? first + '-' + last : first;
}



// Get all tickets
app.get('/api/tickets', auth, async (req, res) => {
  try {
    const { queue, status } = req.query;
    let q = `SELECT t.*, u.full_name as creator_name,
             (SELECT COUNT(*) FROM ticket_comments WHERE ticket_id=t.id) as comment_count
             FROM tickets t LEFT JOIN users u ON t.created_by=u.id WHERE 1=1`;
    const params = [];
    if (queue) { q += ' AND t.queue=?'; params.push(queue); }
    if (status) { q += ' AND t.status=?'; params.push(status); }
    q += ' ORDER BY t.created_at DESC';
    const [rows] = await pool.query(q, params);
    rows.forEach(r => r.username = getUsername(r.creator_name));
    res.json(rows);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch tickets' }); }
});

// Get ticket stats
app.get('/api/tickets/stats', auth, async (req, res) => {
  try {
    const [[{total}]] = await pool.query('SELECT COUNT(*) as total FROM tickets');
    const [[{assigned}]] = await pool.query("SELECT COUNT(*) as assigned FROM tickets WHERE status='assigned'");
    const [[{wip}]] = await pool.query("SELECT COUNT(*) as wip FROM tickets WHERE status='work_in_progress'");
    const [[{resolved}]] = await pool.query("SELECT COUNT(*) as resolved FROM tickets WHERE status='resolved'");
    const [queues] = await pool.query('SELECT queue, COUNT(*) as count FROM tickets GROUP BY queue');
    res.json({ total, assigned, wip, resolved, queues });
  } catch(e) { res.status(500).json({ error: 'Failed to fetch stats' }); }
});


// Get single ticket
app.get('/api/tickets/:id', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT t.*, u.full_name as creator_name FROM tickets t
       JOIN users u ON t.created_by=u.id WHERE t.id=?`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Ticket not found' });
    const ticket = rows[0];
    ticket.username = getUsername(ticket.creator_name);
    const [comments] = await pool.query(
      `SELECT tc.*, u.full_name as user_name, u.role
       FROM ticket_comments tc JOIN users u ON tc.user_id=u.id
       WHERE tc.ticket_id=? ORDER BY tc.created_at DESC`, [req.params.id]);
    comments.forEach(c => c.username = getUsername(c.user_name));
    ticket.comments = comments;
    res.json(ticket);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch ticket' }); }
});

// Create ticket
app.post('/api/tickets', auth, upload.single('image'), async (req, res) => {
  const { title, description, queue } = req.body;
  if (!title || !queue) return res.status(400).json({ error: 'Title and queue are required' });
  try {
    // Check enrollment
    const [enrollments] = await pool.query(
      "SELECT e.id FROM enrollments e JOIN courses c ON e.course_id=c.id WHERE e.user_id=? AND e.status='approved'",
      [req.user.id]);
    if (!enrollments.length && req.user.role !== 'admin')
      return res.status(403).json({ error: 'You must be enrolled in a course to create tickets' });
    const ticket_no = 'KCA-' + Date.now().toString().slice(-6);
    const image_path = req.file ? '/uploads/tickets/' + req.file.filename : null;
    const [result] = await pool.query(
      'INSERT INTO tickets (ticket_no, title, description, queue, status, created_by, image_path) VALUES (?,?,?,?,?,?,?)',
      [ticket_no, title, description||'', queue, 'assigned', req.user.id, image_path]);
    // Notify admin
    mailer.sendMail({
      from: process.env.EMAIL_USER, to: process.env.EMAIL_USER,
      subject: `KCA Ticket ${ticket_no} — ${title}`,
      html: `<h2>New Support Ticket</h2><p><b>Ticket:</b> ${ticket_no}</p><p><b>Title:</b> ${title}</p><p><b>Queue:</b> ${queue}</p><p><a href="https://kca-cloudnet.com/ticket-view.html?id=${result.insertId}">View Ticket →</a></p>`
    }).catch(e => console.error(e));
    // Notify Net-PS team only if ticket created by dlngunza
    if (req.user.email && req.user.email.toLowerCase().startsWith('dlngunza')) {
      try {
        const [netpsMembers] = await pool.query(
          'SELECT u.email FROM netps_members nm JOIN users u ON u.id = nm.user_id'
        );
        if (netpsMembers.length) {
          const netpsEmails = netpsMembers.map(m => m.email).join(',');
          mailer.sendMail({
            from: process.env.EMAIL_USER,
            to: netpsEmails,
            subject: 'KCA Net-PS Ticket ' + ticket_no + ' - ' + title,
            html: '<h2>New Net-PS Ticket</h2><p><b>Ticket:</b> ' + ticket_no + '</p><p><b>Title:</b> ' + title + '</p><p><b>Queue:</b> ' + queue + '</p><p><a href="https://kca-cloudnet.com/ticket-view.html?id=' + result.insertId + '">View Ticket</a></p>'
          }).catch(e => console.error('Net-PS notify error:', e.message));
        }
      } catch(netpsErr) { console.error('Net-PS email error:', netpsErr.message); }
    }
    res.status(201).json({ message: 'Ticket created!', id: result.insertId, ticket_no });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Failed to create ticket' }); }
});


// Add comment
app.post('/api/tickets/:id/comments', auth, uploadComment.single('comment_image'), async (req, res) => {
  const { comment, command_output } = req.body;
  const image_path = req.file ? '/uploads/comments/'+req.file.filename : null;
  if (!comment && !command_output && !image_path) return res.status(400).json({ error: 'Comment, command output, or image required' });
  try {
    await pool.query(
      'INSERT INTO ticket_comments (ticket_id, user_id, comment, command_output, image_path) VALUES (?,?,?,?,?)',
      [req.params.id, req.user.id, comment||'', command_output||'', req.file ? '/uploads/comments/'+req.file.filename : null]);
    // Auto set to WIP when commented
    await pool.query("UPDATE tickets SET status='work_in_progress' WHERE id=? AND status='assigned'", [req.params.id]);
    // Notify ticket creator about new comment (skip if commenting on own ticket)
    try {
      const [[ticketInfo]] = await pool.query(
        `SELECT t.title, t.ticket_no, u.email, u.full_name
         FROM tickets t JOIN users u ON t.created_by=u.id WHERE t.id=?`, [req.params.id]
      );
      if (ticketInfo && ticketInfo.email !== req.user.email) {
        mailer.sendMail({
          from: process.env.EMAIL_USER,
          to: ticketInfo.email,
          subject: `KCA — New Reply on Ticket ${ticketInfo.ticket_no}`,
          html: `<h2>Hi ${ticketInfo.full_name},</h2>
                 <p>There is a new reply on your support ticket:</p>
                 <p><b>Ticket:</b> ${ticketInfo.ticket_no} — ${ticketInfo.title}</p>
                 <p><a href="https://kca-cloudnet.com/ticket-view.html?id=${req.params.id}" style="background:#0e8a78;color:#fff;padding:.5rem 1rem;border-radius:6px;text-decoration:none">View Reply →</a></p>
                 <br><p>Best regards,<br><b>KCA Team</b><br>kca-cloudnet.com</p>`
        }).catch(e => console.error('Comment notify email error:', e.message));
      }
    } catch(emailErr) { console.error('Comment email fetch error:', emailErr.message); }
    // Notify Net-PS team on every new comment
    try {
      const [netpsMembers] = await pool.query(
        'SELECT u.email FROM netps_members nm JOIN users u ON u.id = nm.user_id'
      );
      if (netpsMembers.length) {
        const [[ticketRef]] = await pool.query(
          'SELECT ticket_no, title FROM tickets WHERE id=?', [req.params.id]
        );
        const netpsEmails = netpsMembers.map(m => m.email).filter(e => e !== req.user.email).join(',');
        if (netpsEmails && ticketRef) {
          mailer.sendMail({
            from: process.env.EMAIL_USER,
            to: netpsEmails,
            subject: 'KCA Net-PS — New Reply on Ticket ' + ticketRef.ticket_no,
            html: '<h2>New Comment on Ticket</h2><p><b>Ticket:</b> ' + ticketRef.ticket_no + ' — ' + ticketRef.title + '</p><p><b>Commented by:</b> ' + (req.user.full_name || req.user.email) + '</p><p><a href="https://kca-cloudnet.com/ticket-view.html?id=' + req.params.id + '">View Ticket</a></p>'
          }).catch(e => console.error('Net-PS comment notify error:', e.message));
        }
      }
    } catch(netpsCommentErr) { console.error('Net-PS comment email error:', netpsCommentErr.message); }
    res.status(201).json({ message: 'Comment added!' });
  } catch(e) { res.status(500).json({ error: 'Failed to add comment' }); }
});

// Update status
app.put('/api/tickets/:id/status', auth, async (req, res) => {
  const { status } = req.body;
  if (!['assigned','work_in_progress','resolved'].includes(status))
    return res.status(400).json({ error: 'Invalid status' });
  try {
    await pool.query('UPDATE tickets SET status=? WHERE id=?', [status, req.params.id]);
    res.json({ message: `Ticket status updated to ${status}` });
  } catch(e) { res.status(500).json({ error: 'Update failed' }); }
});

app.delete('/api/tickets/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM ticket_comments WHERE ticket_id = ?', [req.params.id]);
    await pool.query('DELETE FROM tickets WHERE id = ?', [req.params.id]);
    res.json({ message: 'Ticket deleted successfully' });
  } catch(e) { res.status(500).json({ error: 'Delete failed' }); }
});

// Delete selected tickets by IDs (admin only)
app.delete('/api/tickets/delete/selected', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { ids } = req.body;
  if (!ids || !ids.length) return res.status(400).json({ error: 'No ticket IDs provided' });
  try {
    const placeholders = ids.map(() => '?').join(',');
    await pool.query(`DELETE FROM tickets WHERE id IN (${placeholders})`, ids);
    res.json({ message: `${ids.length} ticket(s) deleted successfully` });
  } catch(e) { res.status(500).json({ error: 'Delete failed' }); }
});
// Move ticket to different queue
app.put('/api/tickets/:id/queue', auth, async (req, res) => {
  const { queue } = req.body;
  if (!queue) return res.status(400).json({ error: 'Queue is required' });
  try {
    await pool.query('UPDATE tickets SET queue=? WHERE id=?', [queue, req.params.id]);
    res.json({ message: `Ticket moved to ${queue}` });
  } catch(e) { res.status(500).json({ error: 'Move failed' }); }
});
app.post('/api/auth/register', async (req, res) => {
  const { full_name, email, password, phone, country } = req.body;
  if (!full_name || !email || !password) return res.status(400).json({ error: 'Full name, email and password are required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  try {
    const hash = await bcrypt.hash(password, 12);
    await pool.query("INSERT INTO users (full_name, email, password_hash, phone, country, status) VALUES (?, ?, ?, ?, ?, 'approved')",
      [full_name.trim(), email.toLowerCase().trim(), hash, phone || null, country || null]);
    res.status(201).json({ message: 'Registration successful! You can now log in.' });
    mailer.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      subject: 'KCA — New Student Registration',
      html: '<h2>New Student Registered</h2><p><b>Name:</b> '+full_name+'</p><p><b>Email:</b> '+email+'</p><p><b>Country:</b> '+(req.body.country||'N/A')+'</p><p>Log in to your <a href="https://kca-cloudnet.com/admin.html">Admin Dashboard</a> to view.</p>'
    }).catch(e => console.error('Email error:', e.message));
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'This email address is already registered' });
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email.toLowerCase().trim()]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid email or password' });
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
    // account auto-approved on registration
    if (user.status === 'rejected') return res.status(403).json({ error: 'Your account was not approved. Contact support.' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.full_name }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { id: user.id, name: user.full_name, email: user.email, role: user.role } });
  } catch (e) {
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, full_name, email, phone, country, status, role, created_at FROM users WHERE id = ?', [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch { res.status(500).json({ error: 'Failed to fetch profile' }); }
});

app.get('/api/courses', auth, async (req, res) => {
  try {
    const [courses] = await pool.query('SELECT * FROM courses WHERE is_active = 1 ORDER BY sort_order');
    res.json(courses);
  } catch { res.status(500).json({ error: 'Failed to fetch courses' }); }
});

app.post('/api/enrollments', auth, async (req, res) => {
  const { course_id } = req.body;
  if (!course_id) return res.status(400).json({ error: 'course_id is required' });
  try {
    const [existing] = await pool.query('SELECT id FROM enrollments WHERE user_id = ? AND course_id = ?', [req.user.id, course_id]);
    if (existing.length) return res.status(409).json({ error: 'Already enrolled in this course' });
    await pool.query('INSERT INTO enrollments (user_id, course_id, status) VALUES (?, ?, \'pending\')', [req.user.id, course_id]);
    res.status(201).json({ message: 'Enrollment submitted! Awaiting admin approval.' });
    // Fetch student and course details for emails
    try {
      const [[student]] = await pool.query('SELECT full_name, email, phone FROM users WHERE id = ?', [req.user.id]);
      const [[course]] = await pool.query('SELECT title FROM courses WHERE id = ?', [course_id]);
      const courseName = course ? course.title : 'Unknown Course';
      // Email to admin
      mailer.sendMail({
        from: process.env.EMAIL_USER,
        to: process.env.EMAIL_USER,
        subject: 'KCA — New Enrollment Request',
        html: '<h2>New Enrollment Request</h2><p><b>Student:</b> '+student.full_name+'</p><p><b>Email:</b> '+student.email+'</p><p><b>Phone:</b> '+(student.phone||'Not provided')+'</p><p><b>Course:</b> '+courseName+'</p><p><b>Status:</b> Pending Admin Approval</p><p><a href="https://kca-cloudnet.com/admin.html">Review in Admin Dashboard →</a></p>'
      }).catch(e => console.error('Admin email error:', e.message));
      // Email to student
      mailer.sendMail({
        from: process.env.EMAIL_USER,
        to: student.email,
        subject: 'KCA — Enrollment Request Received',
        html: '<h2>Hi '+student.full_name+',</h2><p>Thank you for enrolling in <b>'+courseName+'</b> at Kuwaha Cloud Academy.</p><p>We have received your registration request and our team will review it shortly. You will be notified by email once the process is completed.</p><br><p>Best regards,<br><b>KCA Team</b><br>kca-cloudnet.com</p>'
      }).catch(e => console.error('Student email error:', e.message));
    } catch(emailErr) { console.error('Email fetch error:', emailErr.message); }
  } catch { res.status(500).json({ error: 'Enrollment failed.' }); }
});

app.get('/api/enrollments/me', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT e.id, e.status, e.enrolled_at, c.id as course_id, c.title, c.description, c.category, c.level, c.duration, c.badge_color
       FROM enrollments e JOIN courses c ON e.course_id = c.id WHERE e.user_id = ? ORDER BY e.enrolled_at DESC`, [req.user.id]);
    res.json(rows);
  } catch { res.status(500).json({ error: 'Failed to fetch enrollments' }); }
});

app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  try {
    const [[{ total_students }]] = await pool.query("SELECT COUNT(*) as total_students FROM users WHERE role='student'");
    const [[{ pending }]]        = await pool.query("SELECT COUNT(*) as pending FROM enrollments WHERE status='pending'");
    const [[{ approved }]]       = await pool.query("SELECT COUNT(*) as approved FROM enrollments WHERE status='approved'");
    const [[{ rejected }]]       = await pool.query("SELECT COUNT(*) as rejected FROM enrollments WHERE status='rejected'");
    const [[{ total_enrollments }]] = await pool.query("SELECT COUNT(*) as total_enrollments FROM enrollments");
    res.json({ total_students, pending, approved, rejected, total_enrollments });
  } catch { res.status(500).json({ error: 'Failed to fetch stats' }); }
});


app.get('/api/admin/students/export', auth, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT full_name, email, phone, country, status, created_at FROM users WHERE role='student' ORDER BY created_at DESC"
    );
    const csv = [
      'Full Name,Email,Phone,Country,Status,Registered',
      ...rows.map(r => `"${r.full_name}","${r.email}","${r.phone||''}","${r.country||''}","${r.status}","${new Date(r.created_at).toLocaleDateString()}"`)
    ].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=KCA_Students.csv');
    res.send(csv);
  } catch(e) { res.status(500).json({ error: 'Export failed' }); }
});
app.get('/api/admin/students', auth, adminOnly, async (req, res) => {
  try {
    const { status, search } = req.query;
    let q = "SELECT id, full_name, email, phone, country, status, created_at FROM users WHERE role='student'";
    const params = [];
    if (status && ['pending','approved','rejected'].includes(status)) { q += ' AND status = ?'; params.push(status); }
    if (search) { q += ' AND (full_name LIKE ? OR email LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
    q += ' ORDER BY created_at DESC';
    const [rows] = await pool.query(q, params);
    res.json(rows);
  } catch { res.status(500).json({ error: 'Failed to fetch students' }); }
});


app.post('/api/admin/enrollments/bulk-drop', auth, adminOnly, async (req, res) => {
  const { ids } = req.body;
  if (!ids || !ids.length) return res.status(400).json({ error: 'No enrollments selected' });
  try {
    await pool.query('DELETE FROM enrollments WHERE id IN (?)', [ids]);
    res.json({ message: `${ids.length} student(s) dropped successfully` });
  } catch { res.status(500).json({ error: 'Bulk drop failed' }); }
});
app.delete('/api/admin/enrollments/:id', auth, adminOnly, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM enrollments WHERE id = ?', [req.params.id]);
    if (!result.affectedRows) return res.status(404).json({ error: 'Enrollment not found' });
    res.json({ message: 'Student dropped from course successfully' });
  } catch { res.status(500).json({ error: 'Drop failed' }); }
});
app.delete('/api/admin/students/:id', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('UPDATE tickets SET created_by = NULL WHERE created_by = ?', [req.params.id]);
    await pool.query('UPDATE ticket_comments SET user_id = NULL WHERE user_id = ?', [req.params.id]);
    await pool.query('DELETE FROM enrollments WHERE user_id = ?', [req.params.id]);
    const [result] = await pool.query('DELETE FROM users WHERE id = ? AND role = "student"', [req.params.id]);
    if (!result.affectedRows) return res.status(404).json({ error: 'Student not found' });
    res.json({ message: 'Student deleted successfully' });
  } catch { res.status(500).json({ error: 'Delete failed' }); }
});
app.put('/api/admin/students/:id/status', auth, adminOnly, async (req, res) => {
  const { status } = req.body;
  if (!['approved','rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    const [result] = await pool.query('UPDATE users SET status = ? WHERE id = ? AND role = "student"', [status, req.params.id]);
    if (!result.affectedRows) return res.status(404).json({ error: 'Student not found' });
    res.json({ message: `Student ${status} successfully` });
  } catch { res.status(500).json({ error: 'Update failed' }); }
});

app.put('/api/admin/enrollments/:id/status', auth, adminOnly, async (req, res) => {
  const { status } = req.body;
  if (!['approved','rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    const [result] = await pool.query('UPDATE enrollments SET status = ? WHERE id = ?', [status, req.params.id]);
    if (!result.affectedRows) return res.status(404).json({ error: 'Enrollment not found' });
    // Send email to student on approval or rejection
    try {
      const [[enrollment]] = await pool.query(
        'SELECT u.full_name, u.email, c.title FROM enrollments e JOIN users u ON e.user_id=u.id JOIN courses c ON e.course_id=c.id WHERE e.id=?',
        [req.params.id]
      );
      if(enrollment) {
        const subject = status==='approved' ? 'KCA — Enrollment Approved! 🎉' : 'KCA — Enrollment Update';
        const html = status==='approved'
          ? '<h2>Hi '+enrollment.full_name+',</h2><p>Great news! Your enrollment in <b>'+enrollment.title+'</b> has been <b style="color:#3ecf6e">approved</b>.</p><p>You can now start learning:</p><p><a href="https://kca-cloudnet.com/dashboard.html" style="background:#0e8a78;color:#fff;padding:.6rem 1.2rem;border-radius:6px;text-decoration:none">▶ Start Learning</a></p><br><p>Best regards,<br><b>KCA Team</b></p>'
          : '<h2>Hi '+enrollment.full_name+',</h2><p>Unfortunately your enrollment in <b>'+enrollment.title+'</b> was <b style="color:#ff4d4d">not approved</b> at this time.</p><p>Please contact us at <a href="mailto:davidngu38@gmail.com">davidngu38@gmail.com</a> for more information.</p><br><p>Best regards,<br><b>KCA Team</b></p>';
        mailer.sendMail({ from: process.env.EMAIL_USER, to: enrollment.email, subject, html })
          .catch(e => console.error('Approval email error:', e.message));
      }
    } catch(e) { console.error('Email fetch error:', e.message); }
    res.json({ message: `Enrollment ${status} successfully` });
  } catch { res.status(500).json({ error: 'Update failed' }); }
});
app.get('/api/admin/enrollments', auth, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT e.id, e.status, e.enrolled_at, u.full_name, u.email, c.title as course, c.category
       FROM enrollments e JOIN users u ON e.user_id = u.id JOIN courses c ON e.course_id = c.id
       ORDER BY e.enrolled_at DESC`);
    res.json(rows);
  } catch { res.status(500).json({ error: 'Failed to fetch enrollments' }); }
});


app.get('/api/admin/course-enrollments', auth, adminOnly, async (req, res) => {
  try {
    const { course_id } = req.query;
    if (course_id) {
      const [rows] = await pool.query(
        `SELECT u.id, u.full_name, u.email, u.phone, u.country, u.status as account_status,
                e.status as enrollment_status, e.enrolled_at
         FROM enrollments e
         JOIN users u ON e.user_id = u.id
         WHERE e.course_id = ?
         ORDER BY e.enrolled_at DESC`, [course_id]);
      res.json(rows);
    } else {
      const [rows] = await pool.query(
        `SELECT c.id, c.title, c.category,
                COUNT(e.id) as total,
                SUM(e.status='approved') as approved,
                SUM(e.status='pending') as pending
         FROM courses c
         LEFT JOIN enrollments e ON c.id = e.course_id
         WHERE c.is_active = 1
         GROUP BY c.id
         ORDER BY total DESC`);
      res.json(rows);
    }
  } catch(e) { console.error(e); res.status(500).json({ error: 'Failed to fetch course enrollments' }); }
});


app.put('/api/admin/courses/:id/pricing', auth, adminOnly, async (req, res) => {
  const { price, registration_fee, installments, payment_start_month } = req.body;
  try {
    await pool.query('UPDATE courses SET price=?,registration_fee=?,installments=?,payment_start_month=? WHERE id=?',
      [parseFloat(price)||0, parseFloat(registration_fee)||0, parseInt(installments)||3, payment_start_month||null, req.params.id]);
    res.json({ message: 'Pricing updated' });
  } catch(e) { res.status(500).json({ error: 'Failed to update pricing' }); }
});
app.get('/api/admin/courses-pricing', auth, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id,title,category,price,registration_fee,installments,payment_start_month FROM courses WHERE is_active=1 ORDER BY sort_order');
    res.json(rows);
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});
app.get('/api/admin/payments', auth, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT p.*,u.full_name,u.email,u.phone,c.title as course_name FROM payments p JOIN users u ON p.user_id=u.id JOIN courses c ON p.course_id=c.id ORDER BY p.created_at DESC`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});
app.post('/api/payments/checkout', auth, async (req, res) => {
  const { course_id } = req.body;
  try {
    const [[course]] = await pool.query('SELECT * FROM courses WHERE id=? AND is_active=1', [course_id]);
    if (!course) return res.status(404).json({ error: 'Course not found' });
    const [[student]] = await pool.query('SELECT full_name,email FROM users WHERE id=?', [req.user.id]);
    const [existing] = await pool.query('SELECT id FROM enrollments WHERE user_id=? AND course_id=?', [req.user.id, course_id]);
    if (existing.length) return res.status(409).json({ error: 'Already enrolled in this course' });
    if (!course.price || parseFloat(course.price) <= 0) return res.status(400).json({ error: 'no_price' });
    const regFee = parseFloat(course.registration_fee) > 0 ? parseFloat(course.registration_fee) : parseFloat(course.price);
    const [enroll] = await pool.query("INSERT INTO enrollments (user_id,course_id,status) VALUES (?,?,'pending')", [req.user.id, course_id]);
    const remaining = parseFloat(course.price) - parseFloat(course.registration_fee);
    const instDesc = remaining > 0 ? ` + ${course.installments} monthly installments of $${(remaining/course.installments).toFixed(2)}` : '';
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{ price_data: { currency: 'usd', product_data: { name: `${course.title} — Registration Fee`, description: `KCA Enrollment. Total: $${course.price}${instDesc}.` }, unit_amount: Math.round(regFee * 100) }, quantity: 1 }],
      mode: 'payment', customer_email: student.email,
      success_url: `${process.env.CLIENT_URL}/payment-success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL}/payment-cancel.html`,
      metadata: { user_id: String(req.user.id), course_id: String(course_id), enrollment_id: String(enroll.insertId) }
    });
    await pool.query("INSERT INTO payments (user_id,course_id,enrollment_id,stripe_session_id,amount,type,status) VALUES (?,?,?,?,?,'registration','pending')",
      [req.user.id, course_id, enroll.insertId, session.id, regFee]);
    res.json({ url: session.url });
  } catch(e) { console.error('Checkout error:', e); res.status(500).json({ error: 'Checkout failed' }); }
});
app.get('/api/payments/my-plan', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT p.*,c.title as course_name FROM payments p JOIN courses c ON p.course_id=c.id WHERE p.user_id=? ORDER BY p.course_id,p.type DESC,p.installment_number`, [req.user.id]);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});
app.get('/api/health', async (req, res) => {
  try { await pool.query('SELECT 1'); res.json({ status: 'ok', db: 'connected' }); }
  catch { res.status(500).json({ status: 'error', db: 'disconnected' }); }
});


// Separate upload handler for assignments

// ─── ASSIGNMENTS ────────────────────────────────────────────
app.post('/api/assignments', auth, uploadAssignment.single('file'), async (req, res) => {
  if (!['admin','instructor'].includes(req.user.role)) return res.status(403).json({ error: 'Instructor access required' });
  const { title, description, course } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });
  const file_path = req.file ? '/uploads/assignments/' + req.file.filename : null;
  const file_type = req.file ? req.file.mimetype : null;
  const course_id = course ? parseInt(course) : null;
  try {
    await pool.query(
      'INSERT INTO assignments (title, description, file_path, file_type, course_id, created_by) VALUES (?,?,?,?,?,?)',
      [title, description||null, file_path, file_type, course_id, req.user.id]
    );
    // Notify enrolled students about new assignment
    try {
      const targetCourseId = course_id;
      let studentRows = [];
      if (targetCourseId) {
        [studentRows] = await pool.query(
          `SELECT u.full_name, u.email FROM users u
           JOIN enrollments e ON u.id=e.user_id
           WHERE e.course_id=? AND e.status='approved'
             AND EXISTS (SELECT 1 FROM class_sessions cs WHERE cs.status='open'
               AND DATE(e.enrolled_at) BETWEEN cs.start_date AND cs.end_date)`,
          [targetCourseId]
        );
      } else {
        // No course filter — notify all students in the open session
        [studentRows] = await pool.query(
          `SELECT DISTINCT u.full_name, u.email FROM users u
           JOIN enrollments e ON u.id=e.user_id
           WHERE e.status='approved'
             AND EXISTS (SELECT 1 FROM class_sessions cs WHERE cs.status='open'
               AND DATE(e.enrolled_at) BETWEEN cs.start_date AND cs.end_date)`
        );
      }
      studentRows.forEach(student => {
        mailer.sendMail({
          from: process.env.EMAIL_USER,
          to: student.email,
          subject: `KCA — New Assignment Posted: ${title}`,
          html: `<h2>Hi ${student.full_name},</h2>
                 <p>A new assignment has been posted on <b>Kuwaha Cloud Academy</b>:</p>
                 <h3 style="color:#0e8a78">${title}</h3>
                 ${description ? `<p>${description}</p>` : ''}
                 <p><a href="https://kca-cloudnet.com/assignments.html" style="background:#0e8a78;color:#fff;padding:.5rem 1rem;border-radius:6px;text-decoration:none">View Assignment →</a></p>
                 <br><p>Best regards,<br><b>KCA Team</b><br>kca-cloudnet.com</p>`
        }).catch(e => console.error('New assignment student email error:', e.message));
      });
    } catch(emailErr) { console.error('New assignment email fetch error:', emailErr.message); }
    res.json({ message: 'Assignment created successfully' });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Failed to create assignment' }); }
});

app.get('/api/assignments', auth, async (req, res) => {
  try {
    let rows;
    if (['admin','instructor'].includes(req.user.role)) {
      [rows] = await pool.query(
        `SELECT a.*, c.title as course_name, u.full_name as instructor_name,
         (SELECT COUNT(*) FROM assignment_submissions WHERE assignment_id=a.id) as submission_count
         FROM assignments a
         LEFT JOIN users u ON a.created_by=u.id
         LEFT JOIN courses c ON a.course_id=c.id
         ORDER BY a.created_at DESC`
      );
    } else {
      const [enrollments] = await pool.query(
        "SELECT course_id FROM enrollments WHERE user_id=? AND status='approved'", [req.user.id]
      );
      const courseIds = enrollments.map(e => e.course_id);
      if (!courseIds.length) return res.json([]);
      const placeholders = courseIds.map(() => '?').join(',');
      [rows] = await pool.query(
        `SELECT a.*, c.title as course_name, u.full_name as instructor_name,
         (SELECT file_path FROM assignment_submissions WHERE assignment_id=a.id AND student_id=?) as my_submission,
         (SELECT reply_text FROM assignment_submissions WHERE assignment_id=a.id AND student_id=?) as my_reply,
         (SELECT instructor_reply FROM assignment_submissions WHERE assignment_id=a.id AND student_id=?) as instructor_reply
         FROM assignments a
         LEFT JOIN users u ON a.created_by=u.id
         LEFT JOIN courses c ON a.course_id=c.id
         WHERE a.course_id IN (${placeholders}) OR a.course_id IS NULL
         ORDER BY a.created_at DESC`,
        [req.user.id, req.user.id, req.user.id, ...courseIds]
      );
    }
    res.json(rows);
  } catch(e) { console.error(e); res.status(500).json({ error: 'Failed to fetch assignments' }); }
});

app.delete('/api/assignments/:id', auth, async (req, res) => {
  if (!['admin','instructor'].includes(req.user.role)) return res.status(403).json({ error: 'Instructor access required' });
  try {
    await pool.query('DELETE FROM assignments WHERE id=?', [req.params.id]);
    res.json({ message: 'Assignment deleted' });
  } catch(e) { res.status(500).json({ error: 'Failed to delete assignment' }); }
});

app.post('/api/assignments/:id/submit', auth, uploadAssignment.single('file'), async (req, res) => {
  const { reply_text } = req.body;
  const file_path = req.file ? '/uploads/assignments/' + req.file.filename : null;
  try {
    const [existing] = await pool.query(
      'SELECT id FROM assignment_submissions WHERE assignment_id=? AND student_id=?',
      [req.params.id, req.user.id]
    );
    if (existing.length) {
      await pool.query(
        'UPDATE assignment_submissions SET reply_text=?, file_path=?, submitted_at=NOW() WHERE assignment_id=? AND student_id=?',
        [reply_text||null, file_path, req.params.id, req.user.id]
      );
    } else {
      await pool.query(
        'INSERT INTO assignment_submissions (assignment_id, student_id, reply_text, file_path) VALUES (?,?,?,?)',
        [req.params.id, req.user.id, reply_text||null, file_path]
      );
    }
    // ── NOTIFICATION PATCHES ── assignment submission
    try {
      const [[asgn]] = await pool.query(
        'SELECT a.title, u.full_name, u.email FROM assignments a JOIN users u ON u.id=? WHERE a.id=?',
        [req.user.id, req.params.id]
      );
      if (asgn) {
        // Notify admin
        mailer.sendMail({
          from: process.env.EMAIL_USER,
          to: process.env.EMAIL_USER,
          subject: `KCA — Assignment Submitted: ${asgn.title}`,
          html: `<h2>Assignment Submission Received</h2>
                 <p><b>Student:</b> ${asgn.full_name} (${asgn.email})</p>
                 <p><b>Assignment:</b> ${asgn.title}</p>
                 <p><a href="https://kca-cloudnet.com/instructor.html" style="background:#0e8a78;color:#fff;padding:.5rem 1rem;border-radius:6px;text-decoration:none">View in Instructor Portal →</a></p>`
        }).catch(e => console.error('Admin submission email error:', e.message));
        // Notify student confirmation
        mailer.sendMail({
          from: process.env.EMAIL_USER,
          to: asgn.email,
          subject: `KCA — Submission Received: ${asgn.title}`,
          html: `<h2>Hi ${asgn.full_name},</h2>
                 <p>Your submission for <b>${asgn.title}</b> has been received successfully.</p>
                 <p>Your instructor will review it and get back to you soon.</p>
                 <br><p>Best regards,<br><b>KCA Team</b><br>kca-cloudnet.com</p>`
        }).catch(e => console.error('Student submission email error:', e.message));
      }
    } catch(emailErr) { console.error('Submission email fetch error:', emailErr.message); }
    res.json({ message: 'Submission saved successfully' });
  } catch(e) { res.status(500).json({ error: 'Failed to submit' }); }
});

app.get('/api/assignments/:id/submissions', auth, async (req, res) => {
  if (!['admin','instructor'].includes(req.user.role)) return res.status(403).json({ error: 'Instructor access required' });
  try {
    const [rows] = await pool.query(
      `SELECT s.*, u.full_name, u.email FROM assignment_submissions s
       JOIN users u ON s.student_id=u.id WHERE s.assignment_id=? ORDER BY s.submitted_at DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch submissions' }); }
});

// Instructor reply to submission
app.put('/api/assignments/:id/submissions/:studentId/reply', auth, async (req, res) => {
  if (!['admin','instructor'].includes(req.user.role)) return res.status(403).json({ error: 'Instructor access required' });
  const { instructor_reply } = req.body;
  if (!instructor_reply) return res.status(400).json({ error: 'Reply cannot be empty' });
  try {
    await pool.query(
      'UPDATE assignment_submissions SET instructor_reply=?, replied_at=NOW() WHERE assignment_id=? AND student_id=?',
      [instructor_reply, req.params.id, req.params.studentId]
    );
    res.json({ message: 'Reply sent successfully' });
  } catch(e) { res.status(500).json({ error: 'Failed to send reply' }); }
});
// ─── END ASSIGNMENTS ─────────────────────────────────────────


// ─── NET-PS TEAM ─────────────────────────────────────────────

// Multi-image upload handler for tickets


// Create ticket (multi-image override — replaces existing POST /api/tickets)
app.post('/api/tickets/create', auth, (req, res) => {
  uploadTicketFields(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });
    const { title, description, queue, command_output } = req.body;
    if (!title || !queue) return res.status(400).json({ error: 'Title and queue are required' });
    try {
      const [enrollments] = await pool.query(
        "SELECT e.id FROM enrollments e WHERE e.user_id=? AND e.status='approved'", [req.user.id]);
      if (!enrollments.length && req.user.role !== 'admin')
        return res.status(403).json({ error: 'You must be enrolled in a course to create tickets' });
      const ticket_no = 'KCA-' + Date.now().toString().slice(-6);
      const image_path = req.files?.image?.[0] ? '/uploads/tickets/' + req.files.image[0].filename : null;
      const extra = req.files?.extra_images?.map(f => '/uploads/tickets/' + f.filename) || [];
      const extra_images = extra.length ? JSON.stringify(extra) : null;

      // Auto-assign to a Net-PS member if queue is Net-PS
      let assigned_to = null;
      if (queue === 'Net-PS') {
        const [members] = await pool.query(
          'SELECT nm.user_id FROM netps_members nm ORDER BY (SELECT COUNT(*) FROM tickets WHERE assigned_to=nm.user_id AND status != "resolved") ASC LIMIT 1'
        );
        if (members.length) assigned_to = members[0].user_id;
      }

      const [result] = await pool.query(
        'INSERT INTO tickets (ticket_no, title, description, queue, status, created_by, image_path, extra_images, assigned_to, command_output) VALUES (?,?,?,?,?,?,?,?,?,?)',
        [ticket_no, title, description || '', queue, 'assigned', req.user.id, image_path, extra_images, assigned_to, command_output || '']);
      // Notify admin always
      mailer.sendMail({
        from: process.env.EMAIL_USER, to: process.env.EMAIL_USER,
        subject: `KCA Ticket ${ticket_no} — ${title}`,
        html: `<h2>New Support Ticket</h2><p><b>Ticket:</b> ${ticket_no}</p><p><b>Title:</b> ${title}</p><p><b>Queue:</b> ${queue}</p><p><a href="https://kca-cloudnet.com/ticket-view.html?id=${result.insertId}">View Ticket →</a></p>`
      }).catch(e => console.error(e));
      // If Net-PS queue — notify all Net-PS members + confirm to student
      if (queue === 'Net-PS') {
        try {
          const [netpsMembers] = await pool.query(
            'SELECT u.email, u.full_name FROM netps_members nm JOIN users u ON nm.user_id=u.id'
          );
          netpsMembers.forEach(member => {
            mailer.sendMail({
              from: process.env.EMAIL_USER,
              to: member.email,
              subject: `🛡️ Net-PS — New Ticket Assigned: ${ticket_no}`,
              html: `<h2>Hi ${member.full_name},</h2>
                     <p>A new ticket has been submitted to the <b>Net-PS team</b> and may be assigned to you:</p>
                     <p><b>Ticket:</b> ${ticket_no}</p>
                     <p><b>Title:</b> ${title}</p>
                     <p><a href="https://kca-cloudnet.com/netps.html" style="background:#0e8a78;color:#fff;padding:.5rem 1rem;border-radius:6px;text-decoration:none">Open Net-PS Dashboard →</a></p>
                     <br><p>Best regards,<br><b>KCA Team</b><br>kca-cloudnet.com</p>`
            }).catch(e => console.error('Net-PS member email error:', e.message));
          });
          // Confirm to student
          const [[studentInfo]] = await pool.query('SELECT full_name, email FROM users WHERE id=?', [req.user.id]);
          if (studentInfo) {
            mailer.sendMail({
              from: process.env.EMAIL_USER,
              to: studentInfo.email,
              subject: `KCA — Your Net-PS Ticket ${ticket_no} Has Been Received`,
              html: `<h2>Hi ${studentInfo.full_name},</h2>
                     <p>Your ticket has been submitted to the <b>Net-PS (Problem Solver) team</b>:</p>
                     <p><b>Ticket #:</b> ${ticket_no}</p>
                     <p><b>Title:</b> ${title}</p>
                     <p>A Net-PS agent will review your issue and respond shortly.</p>
                     <p><a href="https://kca-cloudnet.com/ticket-view.html?id=${result.insertId}" style="background:#0e8a78;color:#fff;padding:.5rem 1rem;border-radius:6px;text-decoration:none">Track Your Ticket →</a></p>
                     <br><p>Best regards,<br><b>KCA Team</b><br>kca-cloudnet.com</p>`
            }).catch(e => console.error('Student ticket confirm email error:', e.message));
          }
        } catch(emailErr) { console.error('Net-PS email fetch error:', emailErr.message); }
      }
      res.status(201).json({ message: 'Ticket created!', id: result.insertId, ticket_no });
    } catch(e) { console.error(e); res.status(500).json({ error: 'Failed to create ticket' }); }
  });
});

// Get all Net-PS members
app.get('/api/netps/team', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT u.id, u.full_name, u.email, nm.added_at,
       (SELECT COUNT(*) FROM tickets WHERE assigned_to=u.id) as total_tickets,
       (SELECT COUNT(*) FROM tickets WHERE assigned_to=u.id AND status='resolved') as resolved_tickets
       FROM netps_members nm JOIN users u ON nm.user_id=u.id ORDER BY nm.added_at DESC`
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch Net-PS team' }); }
});

// Get eligible students (approved, not already Net-PS)
app.get('/api/netps/eligible', auth, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT u.id, u.full_name, u.email,
       (SELECT 1 FROM netps_members WHERE user_id=u.id) as is_netps,
       (SELECT GROUP_CONCAT(c.title ORDER BY c.title SEPARATOR ', ')
        FROM enrollments e JOIN courses c ON e.course_id=c.id
        WHERE e.user_id=u.id AND e.status='approved') as enrolled_courses
       FROM users u WHERE u.role='student' AND u.status='approved'
       ORDER BY u.full_name`
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch eligible students' }); }
});

// Add to Net-PS team
app.post('/api/netps/team/:userId', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('INSERT IGNORE INTO netps_members (user_id, added_by) VALUES (?,?)', [req.params.userId, req.user.id]);
    res.json({ message: 'Added to Net-PS team' });
  } catch(e) { res.status(500).json({ error: 'Failed to add member' }); }
});

// Remove from Net-PS team
app.delete('/api/netps/team/:userId', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM netps_members WHERE user_id=?', [req.params.userId]);
    res.json({ message: 'Removed from Net-PS team' });
  } catch(e) { res.status(500).json({ error: 'Failed to remove member' }); }
});

// Get Net-PS tickets (for a logged-in Net-PS member)
app.get('/api/netps/tickets', auth, async (req, res) => {
  try {
    const [member] = await pool.query('SELECT id FROM netps_members WHERE user_id=?', [req.user.id]);
    if (!member.length && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Net-PS access required' });
    const params = [];
    let where = "WHERE t.queue='Net-PS'";
    if (req.user.role !== 'admin') { where += ' AND t.assigned_to=?'; params.push(req.user.id); }
    const [rows] = await pool.query(
      `SELECT t.*, u.full_name as creator_name,
       (SELECT COUNT(*) FROM ticket_comments WHERE ticket_id=t.id) as comment_count
       FROM tickets t LEFT JOIN users u ON t.created_by=u.id ${where}
       ORDER BY FIELD(t.status,'assigned','work_in_progress','resolved'), t.created_at DESC`, params);
    rows.forEach(r => r.username = getUsername(r.creator_name));
    res.json(rows);
  } catch(e) { res.status(500).json({ error: 'Failed to fetch tickets' }); }
});

// Assign ticket to a Net-PS member
app.put('/api/tickets/:id/assign', auth, adminOnly, async (req, res) => {
  const { assigned_to } = req.body;
  if (!assigned_to) return res.status(400).json({ error: 'assigned_to is required' });
  try {
    await pool.query("UPDATE tickets SET assigned_to=?, status='work_in_progress' WHERE id=?", [assigned_to, req.params.id]);
    res.json({ message: 'Ticket assigned' });
  } catch(e) { res.status(500).json({ error: 'Assign failed' }); }
});

// Net-PS member submits solution + resolves ticket
app.put('/api/tickets/:id/netps-response', auth, async (req, res) => {
  const { netps_response } = req.body;
  if (!netps_response) return res.status(400).json({ error: 'Response is required' });
  try {
    const [member] = await pool.query('SELECT id FROM netps_members WHERE user_id=?', [req.user.id]);
    if (!member.length && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Net-PS access required' });
    await pool.query("UPDATE tickets SET netps_response=?, status='resolved' WHERE id=?", [netps_response, req.params.id]);
    await pool.query('INSERT INTO ticket_comments (ticket_id, user_id, comment) VALUES (?,?,?)',
      [req.params.id, req.user.id, `✅ Net-PS Solution:\n${netps_response}`]);
    res.json({ message: 'Solution submitted and ticket resolved' });
  } catch(e) { res.status(500).json({ error: 'Failed to submit response' }); }
});

// ─── END NET-PS ───────────────────────────────────────────────

app.use((req, res) => {
  if (!req.path.startsWith('/api')) res.sendFile(path.join(__dirname, 'public', 'index.html'));
  else res.status(404).json({ error: 'Not found' });
});

const PORT = process.env.PORT || 3000;


// ── CLASS SESSIONS ──────────────────────────────────────────
app.get('/api/admin/sessions', auth, adminOnly, async (req, res) => {
  try {
    const [sessions] = await pool.query(`
      SELECT s.*,
        (SELECT COUNT(*) FROM enrollments e
         WHERE e.status='approved'
           AND DATE(e.enrolled_at) BETWEEN s.start_date AND s.end_date) AS student_count
      FROM class_sessions s ORDER BY FIELD(s.status,'open','closed'), s.start_date DESC
    `);
    res.json(sessions);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/sessions/:id', auth, adminOnly, async (req, res) => {
  try {
    const [[session]] = await pool.query('SELECT * FROM class_sessions WHERE id=?', [req.params.id]);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    const [students] = await pool.query(`
      SELECT e.id, e.enrolled_at, u.full_name, u.email, u.phone, c.title AS course, c.category
      FROM enrollments e
      JOIN users u ON e.user_id=u.id
      JOIN courses c ON e.course_id=c.id
      WHERE e.status='approved' AND DATE(e.enrolled_at) BETWEEN ? AND ?
      ORDER BY e.enrolled_at DESC
    `, [session.start_date, session.end_date]);
    res.json({ session, students });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/sessions', auth, adminOnly, async (req, res) => {
  try {
    const now   = new Date();
    const month = now.toLocaleString('en-US', { month: 'long' });
    const year  = now.getFullYear();
    const name  = `${month}-${year}`;
    const start = now.toISOString().split('T')[0];
    const end   = new Date(year, now.getMonth()+1, 0).toISOString().split('T')[0];
    const [[exists]] = await pool.query('SELECT id FROM class_sessions WHERE name=?', [name]);
    if (exists) return res.status(409).json({ error: `Session "${name}" already exists` });
    // Auto-close all open sessions
    await pool.query("UPDATE class_sessions SET status='closed' WHERE status='open'");
    const [result] = await pool.query(
      'INSERT INTO class_sessions (name,start_date,end_date,status) VALUES (?,?,?,\'open\')', [name,start,end]
    );
    res.json({ id: result.insertId, name, start_date: start, end_date: end, student_count: 0 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, '0.0.0.0', () => console.log(`KCA running on port ${PORT}`));
