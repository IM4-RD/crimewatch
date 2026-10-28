# CrimeWatch Role-Based Access Control (RBAC)

## Default Users

The system automatically creates three default users on first run:

| Email | Password | Role | Description |
|-------|----------|------|-------------|
| `public@crimewatch.ke` | `public123` | `public` | Citizen who reports crimes |
| `officer@crimewatch.ke` | `officer123` | `officer` | Police officer who investigates |
| `admin@crimewatch.ke` | `admin123` | `admin` | System administrator |

> **⚠️ WARNING**: Change these passwords in production!

---

## Permissions by Role

### 🟢 Public Role
**Capabilities:**
- View only their own submitted reports
- Submit anonymous crime reports
- Upload media files to their reports
- View report history

**Restricted from:**
- Viewing others' reports
- Changing report status
- Decrypting report payload
- Accessing admin/officer features

**API Access:**
```
✓ POST   /api/auth/register         (self-service signup)
✓ POST   /api/auth/login            
✓ POST   /api/reports               (create own report)
✓ GET    /api/reports               (only their own)
✓ GET    /api/reports/{id}          (only their own)
✓ POST   /api/reports/{id}/media    (upload media)
✗ PATCH  /api/reports/{id}/status   (DENIED)
✗ GET    /api/stats                 (DENIED - use own report view instead)
✗ GET    /api/users                 (DENIED)
```

---

### 🟡 Officer Role
**Capabilities:**
- View all reports (no filter)
- Decrypt report payload (read actual crime details)
- Update report status (received → reviewing → investigating → resolved → closed)
- Assign reports to themselves or other officers
- Add investigation notes
- View statistics (total, by status, by severity)

**Restricted from:**
- Changing user roles
- Creating new officer/admin accounts

**API Access:**
```
✓ GET    /api/reports               (all reports)
✓ GET    /api/reports/{id}          (all reports)
✓ GET    /api/reports/{id}?decrypt=true  (decrypt payload)
✓ PATCH  /api/reports/{id}/status   (update status + assign)
✓ POST   /api/reports/{id}/media    (attach evidence)
✓ GET    /api/reports/{id}/history  (see audit trail)
✓ GET    /api/stats                 (dashboard stats)
✗ GET    /api/users                 (DENIED)
✗ PATCH  /api/users/{id}/role       (DENIED)
```

---

### 🔴 Admin Role
**Capabilities:**
- All officer capabilities PLUS:
- List all system users
- Change user roles (promote officer → admin, demote admin → officer, etc.)
- Manage system-wide settings (future)

**API Access:**
```
✓ All officer endpoints
✓ GET    /api/users                 (list all users)
✓ PATCH  /api/users/{id}/role       (change role: public → officer → admin)
```

---

## How to Change User Permissions

### Change a User's Role (Admin only)

```bash
# Login as admin
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@crimewatch.ke","password":"admin123"}'

# Copy the access_token from response

# Promote an officer to admin
curl -X PATCH http://localhost:8000/api/users/{user_id}/role \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'
```

### Create a New Admin User

```sql
-- SQLite
INSERT INTO users (id, email, name, role, password_hash, is_active) VALUES 
  (lower(hex(randomblob(16))), 'newadmin@crimewatch.ke', 'New Admin', 'admin', 
   'hash_here', 1);
```

**To generate the password hash:**
```bash
python3 << 'EOF'
from auth import hash_password
pwd = hash_password("newadmin123")
print(pwd)
EOF
```

Then use that hash in the INSERT.

---

## Report Status Workflow (Officers)

```
received → reviewing → investigating → resolved → closed
  ↓          ↓            ↓               ↓         ↓
 (new)   (assigned)   (in progress)    (solved)  (archived)
```

Only **officer** and **admin** roles can transition reports through statuses.

---

## Security Notes

1. **Password Storage**: All passwords are bcrypt-hashed (cost: 12 rounds)
2. **Session**: Access tokens expire after 24 hours (configurable via `JWT_EXPIRE_HOURS`)
3. **Audit Trail**: All sensitive actions are logged (decrypt, status change, role change)
4. **Encryption**: Report payloads are AES-256-GCM encrypted; officers need private key to decrypt
5. **Anonymity**: Public users can submit truly anonymous reports (no user link if desired)

---

## Initial Database Setup

When you run the app, it automatically:
1. Creates SQLite tables from models
2. Seeds the three default users (public, officer, admin)
3. Generates RSA key pair for encryption
4. Creates media storage directory

No manual `init_db.py` needed—it all happens on startup!
