const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const dbPath = path.resolve(process.env.DATABASE_PATH || path.join(__dirname, 'patchwork.db'));
console.log(`[DB] Opening SQLite database at: ${dbPath}`);
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);

// Enable WAL mode for better concurrency and performance
try {
  db.pragma('journal_mode = WAL');
  console.log('[DB] WAL journal mode enabled.');
} catch (walErr) {
  console.warn('[DB] Could not set WAL journal mode, falling back:', walErr.message);
}


// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    workspace TEXT NOT NULL,
    role TEXT NOT NULL,
    tier TEXT DEFAULT 'developer',
    api_key TEXT UNIQUE NOT NULL,
    auth_provider TEXT DEFAULT 'local',
    is_superadmin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    company TEXT NOT NULL,
    category TEXT NOT NULL,
    priority TEXT NOT NULL,
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    has_attachment INTEGER DEFAULT 0,
    attachment_name TEXT,
    is_urgent_close INTEGER DEFAULT 0,
    status TEXT DEFAULT 'INVESTIGATING',
    sla TEXT NOT NULL,
    assigned_engineer TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS contact_inquiries (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    company TEXT NOT NULL,
    role TEXT NOT NULL,
    objective TEXT NOT NULL,
    volume TEXT,
    erp TEXT,
    preferred_slot TEXT,
    message TEXT NOT NULL,
    status TEXT DEFAULT 'NEW',
    assigned_architect TEXT DEFAULT 'Marcus Vance (Principal Solutions Architect)',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS demo_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    erp TEXT,
    status TEXT DEFAULT 'PENDING_REVIEW',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS waitlist_subscribers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    source TEXT DEFAULT 'landing_footer',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Multi-Tenant & SaaS Architecture Tables
  CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    owner_id INTEGER,
    status TEXT DEFAULT 'active',
    billing_email TEXT,
    tax_id TEXT,
    billing_address TEXT,
    billing_address_line1 TEXT,
    city TEXT,
    country TEXT,
    postal_code TEXT,
    allocated_seats INTEGER DEFAULT 1,
    active_seat_count INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS organization_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS invitations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    token TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'pending',
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    billing_interval TEXT NOT NULL,
    price_cents INTEGER NOT NULL,
    base_price_cents INTEGER DEFAULT 0,
    seat_price_cents INTEGER DEFAULT 0,
    included_seats INTEGER DEFAULT 1,
    currency TEXT DEFAULT 'USD',
    stripe_price_id TEXT
  );

  CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    org_id TEXT UNIQUE NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL REFERENCES plans(id),
    extra_seats INTEGER DEFAULT 0,
    total_seats INTEGER DEFAULT 1,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    status TEXT NOT NULL,
    current_period_start DATETIME,
    current_period_end DATETIME,
    cancel_at_period_end INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS features (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT
  );

  CREATE TABLE IF NOT EXISTS plan_features (
    plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
    feature_id TEXT NOT NULL REFERENCES features(id) ON DELETE CASCADE,
    is_enabled INTEGER DEFAULT 1,
    limit_value INTEGER DEFAULT -1,
    PRIMARY KEY (plan_id, feature_id)
  );

  CREATE TABLE IF NOT EXISTS usage_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    metric_name TEXT NOT NULL,
    quantity INTEGER DEFAULT 1,
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    scopes TEXT DEFAULT '*',
    last_used_at DATETIME,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    metadata TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS payment_attempts (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL REFERENCES plans(id),
    provider TEXT NOT NULL,
    reference TEXT UNIQUE NOT NULL,
    amount_cents INTEGER NOT NULL,
    currency TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    provider_transaction_id TEXT,
    verified_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS payment_webhook_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    event_key TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    processed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider, event_key)
  );

  CREATE TABLE IF NOT EXISTS invoices (
    id TEXT PRIMARY KEY,
    invoice_number TEXT UNIQUE NOT NULL,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    subscription_id TEXT REFERENCES subscriptions(id),
    payment_attempt_id TEXT REFERENCES payment_attempts(id),
    plan_id TEXT REFERENCES plans(id),
    amount_cents INTEGER NOT NULL,
    currency TEXT NOT NULL DEFAULT 'KES',
    status TEXT NOT NULL DEFAULT 'PAID',
    billing_reason TEXT DEFAULT 'subscription_cycle',
    description TEXT,
    line_items TEXT NOT NULL,
    billing_contact_email TEXT,
    company_name TEXT,
    tax_id TEXT,
    billing_address TEXT,
    paid_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS cancellation_feedback (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    comment TEXT,
    cancelled_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Platform Administration & Audit Trail
  CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    target_org_id TEXT REFERENCES organizations(id) ON DELETE SET NULL,
    target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    metadata TEXT,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Outbound Webhook Deliveries
  CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    response_status INTEGER,
    response_body TEXT,
    duration_ms INTEGER,
    attempts INTEGER DEFAULT 1,
    status TEXT DEFAULT 'success',
    delivered_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Pre-built Connector Integrations
  CREATE TABLE IF NOT EXISTS integrations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    name TEXT NOT NULL,
    credentials_encrypted TEXT NOT NULL,
    status TEXT DEFAULT 'disconnected',
    last_tested_at DATETIME,
    last_synced_at DATETIME,
    records_synced_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS integration_sync_logs (
    id TEXT PRIMARY KEY,
    integration_id TEXT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    records_ingested INTEGER DEFAULT 0,
    duration_ms INTEGER,
    status TEXT NOT NULL,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Scheduled Automated Reconciliation Jobs
  CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    schedule TEXT NOT NULL,
    cron_expr TEXT,
    source_integration_id TEXT REFERENCES integrations(id) ON DELETE SET NULL,
    target_integration_id TEXT REFERENCES integrations(id) ON DELETE SET NULL,
    rule_preset TEXT DEFAULT 'strict_exact',
    discrepancy_threshold_cents INTEGER DEFAULT 0,
    discrepancy_threshold_count INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    last_run_at DATETIME,
    next_run_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS scheduled_job_runs (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES scheduled_jobs(id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    rows_processed INTEGER DEFAULT 0,
    matched_count INTEGER DEFAULT 0,
    discrepancy_count INTEGER DEFAULT 0,
    discrepancy_amount_cents INTEGER DEFAULT 0,
    duration_ms INTEGER,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Disaster Recovery & Backup Snapshots Catalog
  CREATE TABLE IF NOT EXISTS backup_snapshots (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- High-Performance Enterprise Indexes
  CREATE INDEX IF NOT EXISTS idx_audit_logs_org_created ON audit_logs(org_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_org_created ON webhook_deliveries(org_id, delivered_at DESC);
  CREATE INDEX IF NOT EXISTS idx_integrations_org ON integrations(org_id);
  CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_next_run ON scheduled_jobs(is_active, next_run_at);
  CREATE INDEX IF NOT EXISTS idx_scheduled_job_runs_job ON scheduled_job_runs(job_id, created_at DESC);
`);

// SQLite migrations for databases created before Paystack billing was introduced.
function addColumnIfMissing(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all().map((entry) => entry.name);
  if (!columns.includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

addColumnIfMissing('plans', 'paystack_plan_code', 'TEXT');
addColumnIfMissing('plans', 'paystack_subaccount_code', "TEXT DEFAULT 'ACCT_c0ajy946qg0z5w1'");
addColumnIfMissing('plans', 'payment_provider', "TEXT NOT NULL DEFAULT 'paystack'");
addColumnIfMissing('subscriptions', 'provider', "TEXT NOT NULL DEFAULT 'paystack'");
addColumnIfMissing('subscriptions', 'provider_customer_code', 'TEXT');
addColumnIfMissing('subscriptions', 'provider_subscription_code', 'TEXT');
addColumnIfMissing('subscriptions', 'provider_authorization_code', 'TEXT');
addColumnIfMissing('subscriptions', 'last_verified_reference', 'TEXT');
addColumnIfMissing('subscriptions', 'updated_at', 'DATETIME');
addColumnIfMissing('subscriptions', 'pesapal_correlation_id', 'TEXT');
addColumnIfMissing('subscriptions', 'cancel_at_period_end', 'INTEGER DEFAULT 0');
addColumnIfMissing('payment_attempts', 'provider_order_tracking_id', 'TEXT');
addColumnIfMissing('payment_attempts', 'subaccount_code', "TEXT DEFAULT 'ACCT_c0ajy946qg0z5w1'");

// Enterprise billing profile additions
addColumnIfMissing('organizations', 'billing_email', 'TEXT');
addColumnIfMissing('organizations', 'tax_id', 'TEXT');
addColumnIfMissing('organizations', 'billing_address', 'TEXT');
addColumnIfMissing('organizations', 'billing_address_line1', 'TEXT');
addColumnIfMissing('organizations', 'city', 'TEXT');
addColumnIfMissing('organizations', 'country', 'TEXT');
addColumnIfMissing('organizations', 'postal_code', 'TEXT');

// Per-seat licensing and organization seat pool additions
addColumnIfMissing('plans', 'base_price_cents', 'INTEGER DEFAULT 0');
addColumnIfMissing('plans', 'seat_price_cents', 'INTEGER DEFAULT 0');
addColumnIfMissing('plans', 'included_seats', 'INTEGER DEFAULT 1');

addColumnIfMissing('organizations', 'allocated_seats', 'INTEGER DEFAULT 1');
addColumnIfMissing('organizations', 'active_seat_count', 'INTEGER DEFAULT 1');

// Subscriptions seat tracking
addColumnIfMissing('subscriptions', 'extra_seats', 'INTEGER DEFAULT 0');
addColumnIfMissing('subscriptions', 'total_seats', 'INTEGER DEFAULT 1');

// Milestone 1: Trial period lifecycle additions
addColumnIfMissing('subscriptions', 'trial_start', 'DATETIME');
addColumnIfMissing('subscriptions', 'trial_end', 'DATETIME');
addColumnIfMissing('subscriptions', 'trial_type', "TEXT DEFAULT 'standard'");
addColumnIfMissing('subscriptions', 'trial_converted', 'INTEGER DEFAULT 0');

// Milestone 3: Tier upgrade proration and scheduled downgrade additions
addColumnIfMissing('subscriptions', 'scheduled_plan_id', 'TEXT');
addColumnIfMissing('subscriptions', 'proration_balance_cents', 'INTEGER DEFAULT 0');

// Milestone 4: Overage settings additions
addColumnIfMissing('organizations', 'overage_enabled', 'INTEGER DEFAULT 0');
addColumnIfMissing('organizations', 'overage_budget_cap_cents', 'INTEGER DEFAULT 5000');

// Phase 1: Platform governance and enterprise expansions
addColumnIfMissing('users', 'is_superadmin', 'INTEGER DEFAULT 0');

// Sync existing plans with per-seat defaults if not already populated
db.prepare(`
  UPDATE plans 
  SET base_price_cents = CASE 
        WHEN id = 'developer' THEN 0 
        WHEN id = 'growth' THEN 50000 
        WHEN id = 'enterprise' THEN 100000 
        ELSE price_cents 
      END,
      seat_price_cents = CASE 
        WHEN id = 'developer' THEN 0 
        WHEN id = 'growth' THEN 5000 
        WHEN id = 'enterprise' THEN 10000 
        ELSE 5000 
      END,
      included_seats = CASE 
        WHEN id = 'developer' THEN 2 
        WHEN id = 'growth' THEN 5 
        WHEN id = 'enterprise' THEN 15 
        ELSE 1 
      END
  WHERE (base_price_cents = 0 AND seat_price_cents = 0 AND included_seats = 1) OR base_price_cents IS NULL
`).run();

// Backfill organization seat counts from active members and plan limits
const allOrgs = db.prepare('SELECT id FROM organizations').all();
for (const org of allOrgs) {
  const memberCount = db.prepare('SELECT COUNT(*) as cnt FROM organization_members WHERE org_id = ?').get(org.id).cnt || 1;
  const sub = db.prepare('SELECT s.*, p.included_seats FROM subscriptions s LEFT JOIN plans p ON p.id = s.plan_id WHERE s.org_id = ?').get(org.id);
  const included = sub?.included_seats || 5;
  const extraSeats = sub?.extra_seats || 0;
  const allocated = Math.max(memberCount, included + extraSeats);
  db.prepare(`
    UPDATE organizations 
    SET allocated_seats = ?,
        active_seat_count = ?
    WHERE id = ?
  `).run(allocated, memberCount, org.id);
}

// Backfill invoices from existing payment_attempts if not yet present
const existingInvoiceCount = db.prepare('SELECT COUNT(*) as count FROM invoices').get().count;
if (existingInvoiceCount === 0) {
  const attempts = db.prepare(`
    SELECT a.*, o.name as org_name, o.billing_email, o.tax_id, o.billing_address, p.name as plan_name
    FROM payment_attempts a
    JOIN organizations o ON o.id = a.org_id
    LEFT JOIN plans p ON p.id = a.plan_id
    ORDER BY a.created_at ASC
  `).all();

  const insertInvoice = db.prepare(`
    INSERT INTO invoices (
      id, invoice_number, org_id, payment_attempt_id, plan_id,
      amount_cents, currency, status, billing_reason, description,
      line_items, billing_contact_email, company_name, tax_id, billing_address,
      paid_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  let seq = 1000;
  for (const att of attempts) {
    seq++;
    const invNum = `INV-2026-${seq}`;
    const invId = `inv_${att.id.replace(/^pay_/, '')}`;
    const status = att.status === 'success' ? 'PAID' : (att.status === 'failed' ? 'REFUNDED' : 'PENDING');
    const lineItems = JSON.stringify([{
      description: `${att.plan_name || (att.plan_id ? att.plan_id.toUpperCase() : 'Platform Subscription')} - Monthly Recurring`,
      quantity: 1,
      unit_cents: att.amount_cents,
      total_cents: att.amount_cents
    }]);

    insertInvoice.run(
      invId,
      invNum,
      att.org_id,
      att.id,
      att.plan_id,
      att.amount_cents,
      att.currency || 'KES',
      status,
      'subscription_cycle',
      `${att.plan_name || 'Patchwork OS Subscription'} Tier`,
      lineItems,
      att.billing_email || null,
      att.org_name,
      att.tax_id || null,
      att.billing_address || null,
      att.verified_at || (status === 'PAID' ? att.created_at : null),
      att.created_at
    );
  }
}

// Migrate the original USD demonstration prices to the configured Kenyan Paystack plans.
db.prepare("UPDATE plans SET price_cents = 50000, currency = 'KES' WHERE id = 'growth' AND price_cents = 49900 AND currency = 'USD'").run();
db.prepare("UPDATE plans SET price_cents = 100000, currency = 'KES' WHERE id = 'enterprise' AND price_cents = 199900 AND currency = 'USD'").run();
// The public Basic package is the paid entry plan at USD $5/month.
db.prepare("UPDATE plans SET name = 'Basic', billing_interval = 'monthly', price_cents = 500, base_price_cents = 500, currency = 'USD' WHERE id = 'developer'").run();

const defaultSubaccountCode = (process.env.PAYSTACK_SUBACCOUNT_CODE || 'ACCT_c0ajy946qg0z5w1').trim();
db.prepare("UPDATE plans SET paystack_subaccount_code = ? WHERE paystack_subaccount_code IS NULL OR TRIM(paystack_subaccount_code) = '' OR paystack_subaccount_code = 'ACCT_p2rg9g4slvgqxpz'").run(defaultSubaccountCode);

// Seed default plans if empty
const planCount = db.prepare('SELECT COUNT(*) as count FROM plans').get().count;
if (planCount === 0) {
  const insertPlan = db.prepare(`
    INSERT INTO plans (id, name, billing_interval, price_cents, base_price_cents, seat_price_cents, included_seats, currency, paystack_subaccount_code)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertPlan.run('developer', 'Basic', 'monthly', 500, 500, 0, 2, 'USD', defaultSubaccountCode);
  insertPlan.run('growth', 'Growth Tier', 'monthly', 50000, 50000, 5000, 5, 'KES', defaultSubaccountCode);
  insertPlan.run('enterprise', 'Enterprise Custom', 'monthly', 100000, 100000, 10000, 15, 'KES', defaultSubaccountCode);
}

// Seed platform features if empty
const featureCount = db.prepare('SELECT COUNT(*) as count FROM features').get().count;
if (featureCount === 0) {
  const insertFeature = db.prepare('INSERT OR IGNORE INTO features (id, name, description) VALUES (?, ?, ?)');
  insertFeature.run('reconciliation_rows', 'Monthly Reconciliation Rows', 'Reconciled ledger transactions per calendar month');
  insertFeature.run('api_keys', 'Developer API Keys', 'Active scoped developer API keys');
  insertFeature.run('connectors', 'ERP & Treasury Connectors', 'Active integrations to NetSuite, SAP, BAI2');
}

// Seed plan quotas (plan_features) if empty
const planFeatureCount = db.prepare('SELECT COUNT(*) as count FROM plan_features').get().count;
if (planFeatureCount === 0) {
  const insertPlanFeature = db.prepare('INSERT OR IGNORE INTO plan_features (plan_id, feature_id, is_enabled, limit_value) VALUES (?, ?, ?, ?)');
  // Developer: 10,000 rows, 2 API keys, 0 ERP connectors
  insertPlanFeature.run('developer', 'reconciliation_rows', 1, 10000);
  insertPlanFeature.run('developer', 'api_keys', 1, 2);
  insertPlanFeature.run('developer', 'connectors', 0, 0);

  // Growth: 1,000,000 rows, 10 API keys, 2 ERP connectors
  insertPlanFeature.run('growth', 'reconciliation_rows', 1, 1000000);
  insertPlanFeature.run('growth', 'api_keys', 1, 10);
  insertPlanFeature.run('growth', 'connectors', 1, 2);

  // Enterprise: Unlimited (-1) across all metrics
  insertPlanFeature.run('enterprise', 'reconciliation_rows', 1, -1);
  insertPlanFeature.run('enterprise', 'api_keys', 1, -1);
  insertPlanFeature.run('enterprise', 'connectors', 1, -1);
}

// Seed default demo tickets if empty
const ticketCount = db.prepare('SELECT COUNT(*) as count FROM tickets').get().count;
if (ticketCount === 0) {
  const insertTicket = db.prepare(`
    INSERT INTO tickets (id, name, email, company, category, priority, subject, description, status, sla, assigned_engineer, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertTicket.run(
    'PW-TKT-10492',
    'Alex Morgan',
    'alex@acme.com',
    'Acme Corp',
    'Bank Feed & Ingestion (BAI2 / MT940 / OFX)',
    'p1',
    'BAI2 Payout Settlement Code 475 Variance',
    'Investigating J.P. Morgan treasury BAI2 parser discrepancy on rolling reserves.',
    'IN PROGRESS',
    '< 1 Hour',
    'David Ross (Tier-3 ERP Lead)',
    new Date(Date.now() - 3600000 * 2).toISOString()
  );

  insertTicket.run(
    'PW-TKT-09823',
    'Sarah Chen',
    'sarah@fincloud.dev',
    'FinCloud',
    'ERP Connector & GL Sync',
    'p3',
    'NetSuite Token-Based Auth Re-Keying',
    'Annual rotation of NetSuite SuiteTalk integration certificates.',
    'RESOLVED',
    '< 12 Hours',
    'Marcus Vance (Solutions Architect)',
    new Date(Date.now() - 86400000).toISOString()
  );
}

// ==========================================
// Phase 1: Superadmin & Enterprise HQ Seeding
// ==========================================

// Ensure the canonical platform superadmin (admin@patchworkos.com) is provisioned and elevated
let canonicalSuperadmin = db.prepare("SELECT * FROM users WHERE LOWER(email) = 'admin@patchworkos.com'").get();
if (!canonicalSuperadmin) {
  const superadminPasswordHash = bcrypt.hashSync('Admin123!', 10);
  const superadminApiKey = `pw_live_${crypto.randomBytes(18).toString('hex')}`;
  const insertSuperadmin = db.prepare(`
    INSERT INTO users (name, email, password_hash, workspace, role, tier, api_key, auth_provider, is_superadmin)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'local', 1)
  `);
  const res = insertSuperadmin.run(
    'Platform Superadmin',
    'admin@patchworkos.com',
    superadminPasswordHash,
    'Patchwork Global HQ',
    'owner',
    'enterprise',
    superadminApiKey
  );
  canonicalSuperadmin = db.prepare("SELECT * FROM users WHERE id = ?").get(res.lastInsertRowid);
} else if (!canonicalSuperadmin.is_superadmin) {
  db.prepare("UPDATE users SET is_superadmin = 1 WHERE id = ?").run(canonicalSuperadmin.id);
  canonicalSuperadmin.is_superadmin = 1;
}


// Ensure default organization 'org_patchwork_hq' exists
const hqOrgId = 'org_patchwork_hq';
let hqOrg = db.prepare("SELECT * FROM organizations WHERE id = ?").get(hqOrgId);
if (!hqOrg) {
  const existingHqSlug = db.prepare("SELECT id FROM organizations WHERE slug = 'patchwork-global-hq'").get();
  const hqSlug = existingHqSlug && existingHqSlug.id !== hqOrgId
    ? `patchwork-global-hq-${crypto.randomBytes(2).toString('hex')}`
    : 'patchwork-global-hq';

  db.prepare(`
    INSERT INTO organizations (
      id, name, slug, owner_id, status, billing_email,
      allocated_seats, active_seat_count
    ) VALUES (?, ?, ?, ?, 'active', ?, 25, 1)
  `).run(
    hqOrgId,
    'Patchwork Global HQ',
    hqSlug,
    canonicalSuperadmin.id,
    canonicalSuperadmin.email
  );
  hqOrg = db.prepare("SELECT * FROM organizations WHERE id = ?").get(hqOrgId);
} else if (!hqOrg.owner_id) {
  db.prepare("UPDATE organizations SET owner_id = ? WHERE id = ?").run(canonicalSuperadmin.id, hqOrgId);
}

// Ensure organization membership in org_patchwork_hq
const hqMembership = db.prepare("SELECT * FROM organization_members WHERE org_id = ? AND user_id = ?").get(hqOrgId, canonicalSuperadmin.id);
if (!hqMembership) {
  db.prepare(`
    INSERT OR IGNORE INTO organization_members (org_id, user_id, role)
    VALUES (?, ?, 'owner')
  `).run(hqOrgId, canonicalSuperadmin.id);
}

// Ensure active enterprise subscription for org_patchwork_hq
const hqSub = db.prepare("SELECT * FROM subscriptions WHERE org_id = ?").get(hqOrgId);
if (!hqSub) {
  db.prepare(`
    INSERT INTO subscriptions (
      id, org_id, plan_id, extra_seats, total_seats, status,
      current_period_start, current_period_end
    ) VALUES (?, ?, 'enterprise', 10, 25, 'active', CURRENT_TIMESTAMP, datetime(CURRENT_TIMESTAMP, '+1 year'))
  `).run(`sub_hq_${Date.now()}`, hqOrgId);
}

// Export database instance with attached convenience utilities
db.addColumnIfMissing = addColumnIfMissing;

db.logAdminAudit = function({ adminUserId, targetOrgId, targetUserId, action, metadata, ipAddress }) {
  return db.prepare(`
    INSERT INTO admin_audit_logs (admin_user_id, target_org_id, target_user_id, action, metadata, ip_address)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    adminUserId || null,
    targetOrgId || null,
    targetUserId || null,
    action,
    typeof metadata === 'object' ? JSON.stringify(metadata) : (metadata || null),
    ipAddress || null
  );
};

db.isSuperadmin = function(userId) {
  if (!userId) return false;
  const user = db.prepare('SELECT is_superadmin FROM users WHERE id = ?').get(userId);
  return Boolean(user && user.is_superadmin === 1);
};

db.getSuperadminUsers = function() {
  return db.prepare('SELECT id, name, email, workspace, role, tier, is_superadmin, created_at FROM users WHERE is_superadmin = 1').all();
};

console.log('[DB] Database schema and initial seeds initialized successfully.');
module.exports = db;
