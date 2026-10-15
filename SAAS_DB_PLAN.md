# SaaS Database & Architecture Implementation Plan

This execution plan guides agents in incrementally expanding Patchwork OS from a single-tenant demo into a full multi-tenant B2B SaaS platform.

---

## 1. Executive Summary & Goals
- **Objective:** Upgrade [`db.js`](file:///c:/Users/omu/projects/patchworkos-site/db.js) and [`server.js`](file:///c:/Users/omu/projects/patchworkos-site/server.js) to support multi-tenant organizations, subscription tiers, role-based access control (RBAC), usage metering, and developer integrations.
- **Database Engine:** SQLite (`better-sqlite3` with WAL mode enabled).
- **Target Audience:** B2B Enterprise / Financial Operations.

---

## 2. Phased Roadmap

### Phase 1: Multi-Tenancy & Workspace Isolation (Core Foundations)
- [x] **1.1 Workspace/Organization Models** *(Completed)*
  - Create table `organizations` (`id`, `name`, `slug`, `status`, `created_at`, `updated_at`). *(Operational in `db.js`)*
  - Create table `organization_members` (`id`, `org_id`, `user_id`, `role`, `joined_at`). *(Operational in `db.js`)*
  - Create table `invitations` (`id`, `org_id`, `email`, `role`, `token`, `status`, `expires_at`). *(Operational in `db.js`)*
- [x] **1.2 User Decoupling** *(Completed)*
  - Update `users` table to support foreign key membership rather than single workspace string. *(Operational via `organization_members`)*
  - Establish `sessions` / `refresh_tokens` table for secure session management. *(Operational via `auth_refresh_tokens` in `db.js` and `/api/auth/refresh` in `server.js`)*
- [x] **1.3 Tenant Context Middleware** *(Completed)*
  - Add Express middleware in `server.js` to parse tenant ID from headers/JWT (`X-Workspace-ID` or subdomains) and enforce tenant isolation on queries. *(Operational via `authenticate`, `requireAuth`, `requireBillingAdmin`)*

### Phase 2: Billing, Plans & Subscriptions
- [x] **2.1 Pricing & Tier Definitions** *(Completed)*
  - Create table `plans` (`id`, `name`, `billing_interval`, `price_cents`, `currency`, `stripe_price_id`). *(Operational in `db.js`)*
  - Seed default tiers: `developer` (Free/Starter), `growth` ($499/mo), `enterprise` (Custom). *(Seeded in `db.js`)*
- [x] **2.2 Subscription State & Webhooks** *(Completed)*
  - Create table `subscriptions` (`id`, `org_id`, `plan_id`, `stripe_customer_id`, `stripe_subscription_id`, `status`, `current_period_start`, `current_period_end`, `cancel_at_period_end`). *(Operational in `db.js`)*
  - Implement `/api/billing/webhook` handler to sync status changes from Stripe/payment gateway. *(Operational for Paystack webhooks & Pesapal IPN in `server.js`)*
- [x] **2.3 Invoicing & History** *(Completed)*
  - Create table `invoices` (`id`, `org_id`, `stripe_invoice_id`, `amount_paid`, `status`, `invoice_pdf_url`, `created_at`). *(Operational in `db.js` with instant printable HTML/PDF receipt generator at `/api/billing/invoices/:id/receipt`)*

### Phase 3: Entitlements, Feature Flags & Metering
- [x] **3.1 Feature Entitlement Engine** *(Completed)*
  - Create table `features` (`id`, `name`, `description`). *(Operational & seeded in `db.js`)*
  - Create table `plan_features` (`plan_id`, `feature_id`, `is_enabled`, `limit_value`). *(Operational & seeded in `db.js`)*
  - Support organizational quota overrides & overage configurations (`overage_enabled`, `overage_budget_cap_cents`). *(Operational in `db.js` & `server.js`)*
- [x] **3.2 Usage Metering & Quotas** *(Completed)*
  - Create table `usage_records` (`id`, `org_id`, `metric_name`, `quantity`, `recorded_at`). *(Operational in `db.js`)*
  - Implement quota enforcement middleware (e.g., check if monthly reconciliations/API calls exceed plan limit). *(Operational in `getQuotaUsage` and `/api/recon/batch`)*

### Phase 4: Developer Platform & Connectors
- [x] **4.1 Scoped API Keys** *(Completed)*
  - Create table `api_keys` (`id`, `org_id`, `user_id`, `name`, `key_prefix`, `key_hash`, `scopes`, `last_used_at`, `expires_at`). *(Operational in `db.js`)*
  - Add middleware to authenticate requests via `Authorization: Bearer pw_live_...` with hash check. *(Operational in `server.js`)*
- [x] **4.2 Integrations & Credentials** *(Completed)*
  - Create table `integrations` (`id`, `org_id`, `provider`, `credentials_encrypted`, `status`, `last_synced_at`). *(Operational in `db.js` & `server.js` with encrypted credentials store and sync APIs)*
- [x] **4.3 Webhook Dispatcher** *(Completed)*
  - Create table `webhook_endpoints` (`id`, `org_id`, `url`, `secret`, `events`, `status`). *(Operational in `db.js` & `server.js` with HMAC-SHA256 signature dispatch)*
  - Create table `webhook_deliveries` (`id`, `endpoint_id`, `event_type`, `payload`, `response_status`, `attempts`, `delivered_at`). *(Operational in `db.js` & `server.js`)*

### Phase 5: Security, Audit Logging & Compliance
- [x] **5.1 Enterprise Audit Trail** *(Completed)*
  - Create table `audit_logs` (`id`, `org_id`, `user_id`, `action`, `ip_address`, `user_agent`, `metadata`, `created_at`). *(Operational in `db.js`)*
  - Log sensitive actions (role modification, API key generation, exports, SSO logins). *(Operational via `audit()` throughout `server.js`)*
- [x] **5.2 Backup & Retention Policy** *(Completed)*
  - Configure scheduled automated backup snapshots for `patchwork.db`. *(Operational with WAL checkpointing, lock-free VACUUM INTO snapshots, SHA-256 verification, catalog and restore API endpoints in `server.js`)*

---

## 3. Data Dictionary & Schemas (Reference)

```sql
-- 1. Organizations & Members
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  owner_id INTEGER NOT NULL,
  status TEXT DEFAULT 'active', -- active, suspended, trial
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS organization_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member', -- owner, admin, member, viewer
  joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(org_id, user_id)
);

CREATE TABLE IF NOT EXISTS invitations (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  token TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'pending', -- pending, accepted, expired
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. Billing & Subscriptions
CREATE TABLE IF NOT EXISTS plans (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  billing_interval TEXT NOT NULL, -- monthly, yearly
  price_cents INTEGER NOT NULL,
  currency TEXT DEFAULT 'USD',
  stripe_price_id TEXT
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  org_id TEXT UNIQUE NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  plan_id TEXT NOT NULL REFERENCES plans(id),
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  status TEXT NOT NULL, -- active, trialing, past_due, canceled
  current_period_start DATETIME,
  current_period_end DATETIME,
  cancel_at_period_end INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 3. Entitlements & Features
CREATE TABLE IF NOT EXISTS features (
  id TEXT PRIMARY KEY, -- e.g. erp_sync, custom_rules, audit_export
  name TEXT NOT NULL,
  description TEXT
);

CREATE TABLE IF NOT EXISTS plan_features (
  plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
  feature_id TEXT NOT NULL REFERENCES features(id) ON DELETE CASCADE,
  is_enabled INTEGER DEFAULT 1,
  limit_value INTEGER DEFAULT -1, -- -1 = unlimited, otherwise numerical cap
  PRIMARY KEY (plan_id, feature_id)
);

-- 4. Usage Records
CREATE TABLE IF NOT EXISTS usage_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  metric_name TEXT NOT NULL, -- api_calls, rows_reconciled
  quantity INTEGER DEFAULT 1,
  recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 5. API Keys & Webhooks
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  scopes TEXT DEFAULT '*', -- comma-separated or JSON array
  last_used_at DATETIME,
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS webhook_endpoints (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  events TEXT NOT NULL, -- JSON array of events
  status TEXT DEFAULT 'active',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 6. Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  metadata TEXT, -- JSON payload
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 4. Agent Execution Guidelines
1. **Never drop existing tables without safe migration:** Maintain compatibility for existing `users`, `tickets`, and `contact_inquiries`.
2. **Hash API Keys:** Never store API keys in plaintext. Return the secret key only once upon generation and store SHA-256 / bcrypt hash.
3. **Tenant Scoping:** Always verify that every database write and read is explicitly filtered by `org_id` to prevent cross-tenant data leaks.
4. **Validation & Verification:** After applying changes, verify with `node server.js` and test endpoints with mock curl requests.
