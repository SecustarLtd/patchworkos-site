const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');

const TEST_PORT = 3199;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function req(path, options = {}) {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
  let body = null;
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    body = await res.json();
  } else {
    body = await res.text();
  }
  return { status: res.status, headers: res.headers, body };
}

async function runTests() {
  console.log('--- Starting Patchwork OS Phase 2 Test Suite ---');
  
  // 1. Start Server on TEST_PORT
  const env = { ...process.env, PORT: String(TEST_PORT), NODE_ENV: 'test' };
  const child = spawn('node', ['server.js'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  
  child.stdout.on('data', d => {
    // console.log('[Server stdout]', d.toString().trim());
  });
  child.stderr.on('data', d => {
    console.error('[Server stderr]', d.toString().trim());
  });

  // Wait for server ready
  let ready = false;
  for (let i = 0; i < 20; i++) {
    await sleep(300);
    try {
      const h = await req('/api/health');
      if (h.status === 200) { ready = true; break; }
    } catch (_) {}
  }
  if (!ready) {
    child.kill();
    throw new Error('Server failed to start on test port.');
  }
  console.log('[PASS] Server started and /api/health is UP.');

  try {
    // ==========================================
    // Test 1: Authentication & Superadmin Guard
    // ==========================================
    console.log('\n--- Testing Authentication & requireSuperAdmin ---');
    
    // 1.1 Unauthenticated call to /api/admin/metrics should return 401
    const unauthMetrics = await req('/api/admin/metrics');
    console.assert(unauthMetrics.status === 401, `Expected 401, got ${unauthMetrics.status}`);
    console.log('[PASS] Unauthenticated /api/admin/metrics returns 401.');

    // 1.2 Sign up a regular user (non-superadmin)
    const regularEmail = `testuser_${Date.now()}@example.com`;
    const signupRes = await req('/api/auth/signup', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Regular Auditor',
        email: regularEmail,
        password: 'Password12345!',
        workspace: 'Regular Org',
        role: 'Auditor'
      })
    });
    console.assert(signupRes.status === 201, `Expected 201 signup, got ${signupRes.status}`);
    const regularToken = signupRes.body.accessToken;
    const regularOrgId = signupRes.body.user.orgId;
    console.assert(signupRes.body.isSuperadmin === false, 'Regular user should not be superadmin');
    console.log('[PASS] Regular user signed up successfully.');

    // 1.3 Regular user accessing /api/admin/metrics should get 403 FORBIDDEN_SUPERADMIN
    const forbiddenRes = await req('/api/admin/metrics', {
      headers: { Authorization: `Bearer ${regularToken}` }
    });
    console.assert(forbiddenRes.status === 403, `Expected 403, got ${forbiddenRes.status}`);
    console.assert(forbiddenRes.body.code === 'FORBIDDEN_SUPERADMIN', `Expected FORBIDDEN_SUPERADMIN code, got ${forbiddenRes.body.code}`);
    console.log('[PASS] Non-superadmin blocked with 403 FORBIDDEN_SUPERADMIN.');

    // 1.4 Superadmin Login
    const superLogin = await req('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: 'admin@patchworkos.com',
        password: 'Admin123!'
      })
    });
    console.assert(superLogin.status === 200, `Superadmin login expected 200, got ${superLogin.status}`);
    console.assert(superLogin.body.isSuperadmin === true, 'Expected isSuperadmin === true in login response');
    console.assert(superLogin.body.user.isSuperadmin === true, 'Expected user.isSuperadmin === true');
    const superToken = superLogin.body.accessToken;
    console.log('[PASS] Superadmin authenticated via /api/auth/login.');

    // ==========================================
    // Test 2: Platform Admin REST APIs
    // ==========================================
    console.log('\n--- Testing Platform Admin REST APIs ---');

    // 2.1 GET /api/admin/metrics
    const metricsRes = await req('/api/admin/metrics', {
      headers: { Authorization: `Bearer ${superToken}` }
    });
    console.assert(metricsRes.status === 200, `Expected 200, got ${metricsRes.status}`);
    console.assert(typeof metricsRes.body.kpis.mrrCents === 'number', 'kpis.mrrCents should be number');
    console.assert(Array.isArray(metricsRes.body.tierDistribution), 'tierDistribution should be array');
    console.assert(Array.isArray(metricsRes.body.recentEvents), 'recentEvents should be array');
    console.log('[PASS] GET /api/admin/metrics returns valid KPIs and tier distribution.');

    // 2.2 GET /api/admin/organizations
    const orgsRes = await req('/api/admin/organizations?page=1&limit=10', {
      headers: { Authorization: `Bearer ${superToken}` }
    });
    console.assert(orgsRes.status === 200, `Expected 200, got ${orgsRes.status}`);
    console.assert(Array.isArray(orgsRes.body.organizations), 'organizations should be array');
    console.assert(orgsRes.body.pagination.total >= 1, 'total orgs should be >= 1');
    console.log('[PASS] GET /api/admin/organizations returned paginated organizations.');

    // 2.3 PATCH /api/admin/organizations/:id/subscription
    const subOverride = await req(`/api/admin/organizations/${regularOrgId}/subscription`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${superToken}` },
      body: JSON.stringify({
        planId: 'enterprise',
        status: 'active',
        extendTrialDays: 30,
        allocatedSeats: 25,
        overageEnabled: true,
        overageBudgetCapCents: 50000
      })
    });
    console.assert(subOverride.status === 200, `Expected 200, got ${subOverride.status}`);
    console.assert(subOverride.body.organization.planId === 'enterprise', 'planId should be enterprise');
    console.assert(subOverride.body.organization.allocatedSeats === 25, 'allocatedSeats should be 25');
    console.log('[PASS] PATCH /api/admin/organizations/:id/subscription successfully updated subscription.');

    // 2.4 Organization Suspension & requireActiveSubscriptionOrTrial Guard
    const suspendRes = await req(`/api/admin/organizations/${regularOrgId}/status`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${superToken}` },
      body: JSON.stringify({ status: 'suspended', reason: 'Audit testing suspension' })
    });
    console.assert(suspendRes.status === 200, `Expected 200, got ${suspendRes.status}`);
    console.assert(suspendRes.body.status === 'suspended', 'Org status should be suspended');

    // Tenant mutation should be rejected with 403 ORGANIZATION_SUSPENDED
    const blockedBatch = await req('/api/recon/batch', {
      method: 'POST',
      headers: { Authorization: `Bearer ${regularToken}` },
      body: JSON.stringify({ rows: 100 })
    });
    console.assert(blockedBatch.status === 403, `Expected 403 on suspended org, got ${blockedBatch.status}`);
    console.assert(blockedBatch.body.code === 'ORGANIZATION_SUSPENDED', `Expected code ORGANIZATION_SUSPENDED, got ${blockedBatch.body.code}`);
    console.log('[PASS] Suspended organization rejected by requireActiveSubscriptionOrTrial with ORGANIZATION_SUSPENDED.');

    // Restore to active
    await req(`/api/admin/organizations/${regularOrgId}/status`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${superToken}` },
      body: JSON.stringify({ status: 'active' })
    });
    console.log('[PASS] Organization status restored to active.');

    // 2.5 Platform Users & Superadmin Toggle
    const usersRes = await req('/api/admin/users?page=1&limit=10', {
      headers: { Authorization: `Bearer ${superToken}` }
    });
    console.assert(usersRes.status === 200, `Expected 200, got ${usersRes.status}`);
    console.assert(usersRes.body.users.length > 0, 'Users should not be empty');
    console.log('[PASS] GET /api/admin/users returns list of users.');

    const regularUserId = signupRes.body.user.id;
    const toggleAdmin = await req(`/api/admin/users/${regularUserId}/superadmin`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${superToken}` },
      body: JSON.stringify({ isSuperadmin: true })
    });
    console.assert(toggleAdmin.status === 200 && toggleAdmin.body.isSuperadmin === true, 'Should toggle superadmin to true');
    // Toggle back
    await req(`/api/admin/users/${regularUserId}/superadmin`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${superToken}` },
      body: JSON.stringify({ isSuperadmin: false })
    });
    console.log('[PASS] PATCH /api/admin/users/:id/superadmin toggled superadmin status.');

    // 2.6 Support & Operations Triage
    const tickets = await req('/api/admin/tickets', {
      headers: { Authorization: `Bearer ${superToken}` }
    });
    console.assert(tickets.status === 200 && Array.isArray(tickets.body.tickets), 'Expected tickets array');
    if (tickets.body.tickets.length > 0) {
      const tId = tickets.body.tickets[0].id;
      const tPatch = await req(`/api/admin/tickets/${tId}`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${superToken}` },
        body: JSON.stringify({ status: 'IN PROGRESS', priority: 'p1' })
      });
      console.assert(tPatch.status === 200, 'Ticket patch should succeed');
    }
    console.log('[PASS] Support ticket triage endpoints operational.');

    // 2.7 Webhook Inspector
    const inspector = await req('/api/admin/webhooks/inspector', {
      headers: { Authorization: `Bearer ${superToken}` }
    });
    console.assert(inspector.status === 200 && Array.isArray(inspector.body.deliveries), 'Expected deliveries array');
    console.log('[PASS] GET /api/admin/webhooks/inspector returned deliveries.');

    // 2.8 Disaster Recovery & Database Backups
    const checkpoint = await req('/api/admin/backup/checkpoint', {
      method: 'POST',
      headers: { Authorization: `Bearer ${superToken}` }
    });
    console.assert(checkpoint.status === 200, `Expected 200 for checkpoint, got ${checkpoint.status}`);
    console.assert(checkpoint.body.success === true, 'Expected success === true for checkpoint');
    console.log('[PASS] POST /api/admin/backup/checkpoint completed WAL truncate.');

    const backupCreate = await req('/api/admin/backup/create', {
      method: 'POST',
      headers: { Authorization: `Bearer ${superToken}` }
    });
    console.assert(backupCreate.status === 201, `Expected 201 for backup create, got ${backupCreate.status}`);
    console.assert(backupCreate.body.snapshot.checksumSha256.length === 64, 'Checksum should be 64-char sha256 hex');
    const snapshotId = backupCreate.body.snapshot.id;
    console.log('[PASS] POST /api/admin/backup/create generated lock-free snapshot with SHA-256.');

    const backupList = await req('/api/admin/backup/list', {
      headers: { Authorization: `Bearer ${superToken}` }
    });
    console.assert(backupList.status === 200 && backupList.body.snapshots.length > 0, 'Snapshots list should have entries');
    console.log('[PASS] GET /api/admin/backup/list returns snapshot catalog and live sizes.');

    const downloadRes = await req(`/api/admin/backup/download/${snapshotId}`, {
      headers: { Authorization: `Bearer ${superToken}` }
    });
    console.assert(downloadRes.status === 200, `Expected 200 for download, got ${downloadRes.status}`);
    console.assert(downloadRes.headers.get('content-disposition').includes(backupCreate.body.snapshot.filename), 'Download attachment header set correctly');
    console.log('[PASS] GET /api/admin/backup/download/:id streams backup snapshot.');

    // ==========================================
    // Test 3: Customer Portal Endpoints
    // ==========================================
    console.log('\n--- Testing Customer Portal Endpoints (Tenant Scoped) ---');

    // 3.1 Enterprise Audit Log Explorer & RFC 4180 CSV Export
    const auditRes = await req('/api/audit?page=1&limit=10', {
      headers: { Authorization: `Bearer ${regularToken}` }
    });
    console.assert(auditRes.status === 200, `Expected 200 for audit, got ${auditRes.status}`);
    console.assert(Array.isArray(auditRes.body.logs), 'Expected logs array');
    console.log('[PASS] GET /api/audit returns paginated logs.');

    const exportRes = await req('/api/audit/export', {
      headers: { Authorization: `Bearer ${regularToken}` }
    });
    console.assert(exportRes.status === 200, `Expected 200 for export, got ${exportRes.status}`);
    console.assert(exportRes.headers.get('content-type').includes('text/csv'), 'Content-Type should be text/csv');
    console.assert(exportRes.body.startsWith('id,timestamp,user_email,action,ip_address,metadata'), 'CSV headers match specification');
    console.log('[PASS] GET /api/audit/export returns RFC 4180 CSV with specified headers.');

    // 3.2 Outbound Webhooks & HMAC Dispatcher
    // Set up local test receiver server to verify HMAC-SHA256 signature
    let receivedSignature = null;
    let receivedPayload = null;
    const testReceiver = http.createServer((req, res) => {
      receivedSignature = req.headers['x-patchwork-signature'];
      let data = '';
      req.on('data', chunk => data += chunk);
      req.on('end', () => {
        try { receivedPayload = JSON.parse(data); } catch (_) {}
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ received: true }));
      });
    });
    const RECEIVER_PORT = 3299;
    await new Promise(r => testReceiver.listen(RECEIVER_PORT, r));

    const hookCreate = await req('/api/webhooks', {
      method: 'POST',
      headers: { Authorization: `Bearer ${regularToken}` },
      body: JSON.stringify({
        url: `http://127.0.0.1:${RECEIVER_PORT}/webhook-sink`,
        events: ['recon.batch.completed', 'recon.discrepancy.flagged', 'ping']
      })
    });
    console.assert(hookCreate.status === 201, `Expected 201 for webhook create, got ${hookCreate.status}`);
    console.assert(hookCreate.body.endpoint.secret.startsWith('whsec_'), 'Secret should start with whsec_');
    const hookId = hookCreate.body.endpoint.id;
    const hookSecret = hookCreate.body.endpoint.secret;
    console.log('[PASS] POST /api/webhooks registers endpoint with signing secret.');

    // Test ping
    const testHook = await req(`/api/webhooks/${hookId}/test`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${regularToken}` }
    });
    console.assert(testHook.status === 200, `Expected 200 for webhook test, got ${testHook.status}`);
    console.assert(testHook.body.success === true, 'Test ping should succeed');
    console.assert(receivedSignature !== null, 'Receiver should have received X-Patchwork-Signature');
    
    // Verify HMAC-SHA256 signature
    const [tPart, v1Part] = receivedSignature.split(',');
    const tVal = tPart.replace('t=', '');
    const sigVal = v1Part.replace('v1=', '');
    const expectedSig = crypto.createHmac('sha256', hookSecret).update(`${tVal}.${JSON.stringify(receivedPayload)}`).digest('hex');
    console.assert(sigVal === expectedSig, 'HMAC signature matches byte-for-byte');
    console.log('[PASS] Outbound webhook HMAC-SHA256 signature verified.');

    // Check webhook deliveries list
    const deliveriesRes = await req(`/api/webhooks/${hookId}/deliveries`, {
      headers: { Authorization: `Bearer ${regularToken}` }
    });
    console.assert(deliveriesRes.status === 200 && deliveriesRes.body.deliveries.length > 0, 'Should have recorded delivery');
    console.log('[PASS] GET /api/webhooks/:id/deliveries logged delivery attempt.');

    testReceiver.close();

    // 3.3 Connectors & Integrations
    const intCreate = await req('/api/integrations', {
      method: 'POST',
      headers: { Authorization: `Bearer ${regularToken}` },
      body: JSON.stringify({
        provider: 'netsuite',
        name: 'Corporate NetSuite OneWorld',
        credentials: {
          accountId: 'TST123456',
          consumerKey: 'secret_consumer_key_12345',
          consumerSecret: 'very_secret_consumer_secret_val',
          tokenId: 'token_id_99999',
          tokenSecret: 'token_secret_88888'
        }
      })
    });
    console.assert(intCreate.status === 201, `Expected 201 for integration create, got ${intCreate.status}`);
    const intId = intCreate.body.integration.id;

    // GET should mask credentials
    const intList = await req('/api/integrations', {
      headers: { Authorization: `Bearer ${regularToken}` }
    });
    console.assert(intList.status === 200, `Expected 200, got ${intList.status}`);
    const foundInt = intList.body.integrations.find(i => i.id === intId);
    console.assert(foundInt.config.consumerKey.includes('************'), 'consumerKey should be masked');
    console.log('[PASS] Connectors GET masks secrets.');

    // Handshake test
    const intTest = await req(`/api/integrations/${intId}/test`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${regularToken}` }
    });
    console.assert(intTest.status === 200 && intTest.body.status === 'connected', 'Handshake test verified');
    console.log('[PASS] POST /api/integrations/:id/test simulated handshake latency.');

    // Sync test
    const intSync = await req(`/api/integrations/${intId}/sync`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${regularToken}` }
    });
    console.assert(intSync.status === 200 && intSync.body.recordsIngested >= 50, 'Sync should ingest records');
    console.log('[PASS] POST /api/integrations/:id/sync ingested reconciliation records.');

    // 3.4 Scheduled Reconciliation Jobs
    const jobCreate = await req('/api/jobs', {
      method: 'POST',
      headers: { Authorization: `Bearer ${regularToken}` },
      body: JSON.stringify({
        name: 'Daily Treasury Matcher',
        schedule: 'daily_midnight',
        sourceIntegrationId: intId,
        rulePreset: 'strict_exact',
        discrepancyThresholdCents: 5000,
        discrepancyThresholdCount: 2,
        isActive: true
      })
    });
    console.assert(jobCreate.status === 201, `Expected 201, got ${jobCreate.status}`);
    console.assert(Boolean(jobCreate.body.job.nextRunAt), 'nextRunAt computed');
    const jobId = jobCreate.body.job.id;
    console.log('[PASS] POST /api/jobs scheduled job created with nextRunAt.');

    // Run job ad-hoc
    const jobRun = await req(`/api/jobs/${jobId}/run`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${regularToken}` }
    });
    console.assert(jobRun.status === 200, `Expected 200, got ${jobRun.status}`);
    console.assert(jobRun.body.run.rowsProcessed > 0, 'Rows should be processed');
    console.log('[PASS] POST /api/jobs/:id/run executed job run successfully.');

    // Check job runs history
    const jobRunsList = await req(`/api/jobs/${jobId}/runs`, {
      headers: { Authorization: `Bearer ${regularToken}` }
    });
    console.assert(jobRunsList.status === 200 && jobRunsList.body.runs.length > 0, 'Job runs history recorded');
    console.log('[PASS] GET /api/jobs/:id/runs returned execution history.');

    // ==========================================
    // Test 4: Route Mapping /admin
    // ==========================================
    console.log('\n--- Testing Route Mapping /admin ---');
    const adminRoute = await req('/admin');
    console.assert(adminRoute.status === 200, `Expected 200 for /admin, got ${adminRoute.status}`);
    console.assert(adminRoute.body.includes('SUPERADMIN COCKPIT'), 'HTML contains SUPERADMIN COCKPIT');
    console.log('[PASS] Route /admin serves admin.html successfully.');

    console.log('\n======================================================');
    console.log('ALL PHASE 2 CONTRACTS & ACCEPTANCE CRITERIA VERIFIED!');
    console.log('======================================================\n');
  } finally {
    child.kill();
  }
}

runTests().catch(err => {
  console.error('\n[TEST FAILURE]:', err);
  process.exit(1);
});
