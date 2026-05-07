# Kuwaha Cloud Academy (KCA) Platform
> Empowering Digital Professionals — kca-cloudnet.com

## Tech Stack
| Layer | Technology |
|---|---|
| Backend | Node.js / Express |
| Database | MySQL (kca_db) |
| Process Manager | PM2 |
| Web Server | Nginx (reverse proxy → port 3000) |
| Hosting | AWS EC2 (Ubuntu 24) |
| Domain | kca-cloudnet.com (Hostinger DNS, Let's Encrypt SSL) |
| File Uploads | Multer |
| Auth | JWT tokens (localStorage: kca_token, kca_user) |

## User Roles
| Role | Access |
|---|---|
| `admin` | Full platform access |
| `instructor` | Instructor portal only (assignments) |
| `student` | Dashboard, assignments, ticketing (if enrolled) |

## Key Pages
| URL | Description | Access |
|---|---|---|
| `/` | Homepage with course cards | Public |
| `/register` | Student registration | Public |
| `/login` | Student login | Public |
| `/dashboard` | Student dashboard | Students |
| `/admin` | Admin panel | Admin only |
| `/instructor` | Instructor portal | Admin + Instructor |
| `/assignments` | Student assignments | Enrolled students |
| `/tickets` | KCA ticketing system | Enrolled students + Admin |
| `/ticket-view?id=X` | Individual ticket | Owner + Admin |

## Database Tables
- `users` — id, full_name, email, password_hash, phone, country, role, created_at
- `courses` — id, title
- `enrollments` — id, user_id, course_id, status, progress, enrolled_at
- `tickets` — id, ticket_no, title, description, queue, status, created_by, image_path, created_at
- `assignments` — id, title, description (LONGTEXT), file_path, file_type, course_id, created_by, created_at
- `assignment_submissions` — id, assignment_id, student_id, reply_text, file_path, instructor_reply, replied_at, submitted_at

## File Structure



## Common Commands
```bash
# Restart app
pm2 restart kca-website --update-env

# View logs
pm2 logs kca-website --lines 30 --nostream

# Reload Nginx
sudo systemctl reload nginx

# MySQL access
mysql -u root -p kca_db
```

## Features
- ✅ Student registration/login (JWT auth)
- ✅ Admin panel (students, enrollments, tickets, CSV export)
- ✅ Role management (promote students to instructor)
- ✅ KCA Ticketing system (queues, filters, delete selected/all)
- ✅ Instructor portal (assignments with PKT/image/PDF upload)
- ✅ Paste images directly into assignment instructions
- ✅ Student assignment submission with file attach
- ✅ Instructor feedback replies on submissions
- ✅ 20 CCNA lesson modules with CLI simulators
- ✅ Clean URLs (no .html extensions)
- ✅ OG meta tags (logo thumbnail on link share)

## Courses
| ID | Title |
|---|---|
| 1 | Cisco CCNA (200-301) |
| 2 | AWS Cloud Practitioner |
| 3 | AWS Advanced Networking |
| 4 | Linux Fundamentals |

## Brand
- Navy: `#0A1A3B` / `#0D3B6E`
- Teal: `#0E8A78`
- Gold: `#F5A623`
- Tagline: *Empowering Digital Professionals*
