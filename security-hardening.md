OPENCLAW SECURITY
HARDENING GUIDE
Post-Deployment Security Lockdown
With Copy-Paste Agent Prompts at Every Step
ScaleUP Media • 2026 Edition
How to Use This Guide
This guide is designed to be worked through section by section. Each section contains:
 * An explanation of WHY this security control matters.
 * The technical details of WHAT to configure.
 * A ready-to-use AGENT PROMPT you can copy and paste directly into your AI coding agent (Claude, Cursor, Windsurf, etc.) to have it implement the hardening step for you.
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> The purple boxes like this one contain your agent prompts. Copy the entire contents and paste into your AI agent. Each prompt is self-contained and tells the agent exactly what to do, what to check, and what to output.
> 
Work through them in order. After completing all sections, use the master checklist in Section 11 to verify everything is locked down.
✅ PRO TIP: For the training video: walk through each section, explain the concept, then show yourself pasting the agent prompt and reviewing the output.
1. Pre-Hardening Assessment
Before you touch a single setting, you need to understand your current attack surface. Do NOT skip this.
1.1 Document Your Current Configuration
Pull up your OpenClaw dashboard and document every single integration, API connection, and webhook.
Configuration Audit Checklist
 * List all active API keys and their permission scopes.
 * Document every webhook URL currently registered.
 * Identify all third-party integrations (CRMs, payment processors, email providers).
 * Map all user accounts and their access levels.
 * Record which models are accessible and their routing configurations.
 * Note any custom endpoints or proxy configurations.
 * Screenshot your current environment variable setup (redact sensitive values).
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Audit my OpenClaw deployment for security vulnerabilities. Do the following:
>  * SCAN THE ENTIRE CODEBASE for hardcoded API keys, secrets, passwords, or tokens. Check all files including .env.example, docker-compose.yml, CI/CD configs, and README files. Report every instance found.
>  * LIST every environment variable that contains a secret or API key. For each one, tell me: Variable name, What service it authenticates to, Whether it has an expiration date, The file(s) where it is referenced.
>  * FIND all API endpoints in the application. For each endpoint, report: Route path and HTTP method, Whether authentication is required, What authorization checks exist, Whether rate limiting is applied.
>  * CHECK for common security misconfigurations: CORS set to wildcard (*), Debug mode enabled in production, Stack traces exposed in error responses, Swagger/API docs publicly accessible, Default credentials still active.
>  * OUTPUT a security audit report as a markdown file with: Critical findings (fix immediately), High priority findings (fix within 24 hours), Medium priority findings (fix within 1 week), Low priority findings (fix in next maintenance cycle).
> Do NOT modify any code yet. This is audit only.
> 
🛑 CRITICAL: If your agent finds API keys hardcoded anywhere in your frontend code, STOP. That is your number one priority to fix.
1.2 Threat Model for OpenClaw Deployments
| Threat Category | Risk Level | Description | Impact |
|---|---|---|---|
| API Key Theft | CRITICAL | Exposed keys allow unlimited model access | Runaway costs, data exfiltration |
| Prompt Injection | HIGH | Malicious inputs manipulate model behavior | Data leaks, unauthorized actions |
| Model Abuse | HIGH | Unauthorized users consuming expensive models | Cost explosion ($1K+/day possible) |
| Webhook Hijacking | MEDIUM | Intercepted webhooks expose data flows | Data breach, workflow manipulation |
| Rate Limit Bypass | MEDIUM | Attackers overwhelm your instance | Service disruption, inflated costs |
| Session Hijacking | MEDIUM | Stolen session tokens grant full access | Account takeover |
| Data Exfiltration | HIGH | Context/memory data extracted via prompts | Customer data breach |
1.3 Security Baseline Score
Score your current deployment (0-100). Re-score after completing the process.
| Security Control | Status | Points |
|---|---|---|
| API keys stored in environment variables (not code) | Yes / No | 10 |
| HTTPS enforced on all endpoints | Yes / No | 10 |
| Rate limiting configured | Yes / No | 8 |
| Authentication required for all API routes | Yes / No | 10 |
| Model access restricted by user role | Yes / No | 8 |
| Webhook signatures validated | Yes / No | 7 |
| Logging and monitoring active | Yes / No | 7 |
| Input validation on all user-facing endpoints | Yes / No | 8 |
| CORS properly configured (not wildcard) | Yes / No | 7 |
| Secrets rotated in last 90 days | Yes / No | 5 |
| Backup and recovery plan documented | Yes / No | 5 |
| Error messages sanitized (no stack traces exposed) | Yes / No | 5 |
✅ PRO TIP: Score < 50 means critical gaps. < 30 is an emergency.
2. API Key & Secrets Management
Your API keys are the keys to the kingdom.
2.1 Key Rotation Protocol
 * Generate a new API key in provider’s dashboard.
 * Add as a secondary key in OpenClaw.
 * Update deployment to use the new key.
 * Verify model calls are succeeding.
 * Revoke the old key.
 * Update documentation.
 * Set a 90-day reminder.
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Harden API key and secrets management in my OpenClaw deployment:
>  * FIND every location where API keys or secrets are stored or referenced. Search for patterns: "sk-ant-", "sk-", "api_key", "secret", "token", "password", "ANTHROPIC", "OPENAI" across the entire codebase.
>  * MOVE all hardcoded secrets to environment variables: Create/update .env, replace in source with process.env.VARIABLE_NAME, add .env to .gitignore, create .env.example.
>  * IMPLEMENT a secrets validation module that checks on startup: Presence of variables, no placeholder values, pattern matching, and refuse to start if checks fail.
>  * ADD a .gitignore entry for: .env, .env.local, .env.production, *.pem, *.key.
>  * CREATE a key rotation script that: Accepts new values, updates config, triggers graceful restart, verifies new key works, and logs the event.
>  * VERIFY no secrets exist in git history using git log --all -p.
> Output all changes as a clear diff.
> 
⚠️ WARNING: If using Railway, Vercel, or Render, use their built-in secrets management.
2.2 Key Scope Restriction
| Key Type | Scope | Access Level | Rotation |
|---|---|---|---|
| Admin Key | Full system config | Owner only | 60 days |
| API Key (Prod) | Model routing | App server | 90 days |
| API Key (Dev) | Testing/Sandbox | Dev team | 30 days |
| Webhook Secret | Signature validation | Integration endpoints | 90 days |
| Read-Only Key | Dashboard/Logs | Support team | 120 days |
2.3 Secrets Scanning
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Set up automated secrets scanning for my OpenClaw repository:
>  * CREATE a pre-commit hook script that scans for API key patterns, secret variable names, and private keys. Block the commit if found.
>  * CREATE a .secrets-patterns file with regex for Anthropic, OpenAI, AWS, GitHub tokens, and generic "password/secret" assignments.
>  * ADD a CI/CD step (GitHub Actions) that runs the same scan on every pull request.
>  * SCAN the entire git history for leaked secrets and provide instructions for cleaning history if found.
> Ensure scanning does NOT flag .env.example files.
> 
3. Authentication & Access Control
3.1 Authentication Layer Setup
 * JWT_EXPIRY: 15m (Short-lived)
 * JWT_ALGORITHM: RS256 (Asymmetric signing)
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Implement authentication hardening on my OpenClaw deployment:
>  * AUDIT all API routes and list unprotected ones.
>  * CREATE an authentication middleware: Validate JWT, check expiration, validate issuer/audience, extract role, return 401 for invalid tokens, log failures.
>  * IMPLEMENT token generation: RS256 (generate RSA keys), 15m access expiry, 7d refresh expiry.
>  * ADD a refresh token endpoint: Rotate refresh token on use, invalidate old ones.
>  * APPLY middleware to ALL routes except health, login, and refresh.
>  * GENERATE 2048-bit RSA keys for signing.
> 
3.2 Role-Based Access Control (RBAC)
| Role | Model Access | Admin Panel | API Keys |
|---|---|---|---|
| Owner | All models | Full access | Create/Rotate/Delete |
| Admin | All models | Read + Config | View/Rotate |
| Developer | Sonnet/Haiku | Read only | View own keys |
| Consumer | Per key | No access | Use assigned key |
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Implement Role-Based Access Control (RBAC) for my OpenClaw deployment:
>  * Create a roles system (owner, admin, developer, api_consumer, viewer).
>  * Create authorization middleware to check permissions and return 403 Forbidden.
>  * Implement model-tier access: Block requests to unauthorized models before they reach the API.
>  * Add per-role rate limits (e.g., Owner: 100 req/min, Consumer: 20 req/min).
>  * Create admin endpoints for role management (Owner only).
> 
3.3 Session Management
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Harden session management:
>  * Configure cookie-based storage: httpOnly, secure, sameSite: 'strict'.
>  * Implement controls: Max 3 concurrent sessions, 24h absolute timeout, 15m sliding window.
>  * Add session tracking (IP, User Agent) and alert on dramatic IP changes.
>  * Create endpoints to list and revoke sessions.
>  * Remove tokens from localStorage; migrate to httpOnly cookies.
> 
4. Network Security & Transport
4.1 TLS/HTTPS Enforcement
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Harden TLS/HTTPS:
>  * Enforce TLS 1.2 minimum (TLS 1.3 preferred).
>  * Configure NGINX/Node.js with strong ciphers (ECDHE + AES-GCM).
>  * Enable HSTS header (1 year, includeSubDomains, preload).
>  * Redirect all HTTP to HTTPS via 301.
>  * Set up automatic certificate renewal.
> 
4.2 CORS Configuration
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Lock down CORS:
>  * Replace wildcard (*) with a strict whitelist from environment variables.
>  * Configure allowed methods (GET, POST, OPTIONS) and headers.
>  * Implement dynamic origin validation.
>  * Test by making a fetch request from an unauthorized origin.
> 
4.3 Firewall & IP Restrictions
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Implement IP restrictions and security headers:
>  * Create middleware to whitelist IPs for /admin/* routes.
>  * Disable Swagger/API docs and debug endpoints in production.
>  * Implement webhook HMAC-SHA256 signature validation.
>  * Sanitize /health endpoint (minimal info only).
>  * Add security headers: X-Content-Type-Options, X-Frame-Options: DENY, CSP: default-src 'self'.
> 
5. Rate Limiting & Abuse Prevention
5.1 Multi-Layer Rate Limiting
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Implement comprehensive rate limiting:
>  * Layer 1 (IP): 100 req/min (sliding window).
>  * Layer 2 (API Key): 60 req/min (token bucket).
>  * Layer 3 (Model): Haiku (60), Sonnet (30), Opus (10) req/min.
>  * Use Redis for state. Implement progressive blocking (10+ hits = 5min block).
> 
5.2 Cost Circuit Breakers
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Implement cost circuit breakers:
>  * Track cost per request based on tokens and model rates.
>  * WARNING ($100/day): Notify admin.
>  * SOFT LIMIT ($250/day): Auto-downgrade Opus -> Sonnet.
>  * HARD LIMIT ($500/day): Block all non-Haiku.
>  * EMERGENCY ($1000/day): Total shutoff, manual reset required.
> 
5.3 Prompt Injection Defense
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Implement prompt injection defenses:
>  * Input Validation: Max 4000 chars, block patterns like "ignore previous instructions" or "jailbreak mode".
>  * Output Filtering: Check for leaked API keys or system prompts in responses.
>  * Canary Tokens: Embed a random string in system prompt; block if it appears in output.
>  * Quarantine: Temporarily block keys after 3 injection attempts.
> 
6. Logging, Monitoring & Incident Response
6.1 What to Log
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Implement security logging:
>  * Structured JSON logs (timestamp, level, category, IP, user_id).
>  * Log failed logins, rate limit hits, circuit breaker events, and admin actions.
>  * ALERTS: Critical (10+ failed logins), High (cost spikes), Medium (daily digests).
>  * Log rotation policy: Compress older than 1 day, retain security logs for 1 year.
> 
6.2 Incident Response Playbook
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Create automated incident response:
>  * Detect key compromise, brute force, and cost anomalies.
>  * AUTO ACTIONS: Disable compromised keys, block attacking IPs, activate circuit breakers.
>  * Create /admin/incidents endpoint and a master Kill Switch endpoint (Owner only).
> 
7. Data Protection & Privacy
7.1 Data Encryption
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Implement data protection:
>  * Field-level encryption: Hash API keys (bcrypt), encrypt user tokens (AES-256-GCM).
>  * Connections: Force SSL for Postgres and Redis.
>  * Retention: Auto-purge prompt logs > 7 days, anonymize analytics > 90 days.
>  * PII Detection: Scan and redact SSN, credit cards, and emails from logs.
> 
8. Deployment & Infrastructure Hardening
8.1 Container Security (Docker)
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Harden Docker configuration:
>  * Use specific image tags (no 'latest'), non-root user, multi-stage builds.
>  * Compose settings: no-new-privileges:true, read_only: true, resource limits (512M RAM).
>  * Add .dockerignore for secrets. Scan image for CVEs (Trivy/Scout).
> 
8.2 & 8.3 Dependency Management
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Harden dependencies:
>  * Run full audit (npm audit). Fix vulnerabilities.
>  * Create CI workflow to fail builds on High/Critical vulnerabilities.
>  * Pin GitHub Actions to commit SHAs. Add security:audit scripts to package.json.
> 
9. Backup & Disaster Recovery
9.1 Backup Strategy
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Set up automated backups:
>  * Daily compressed and encrypted database dumps to S3/GCS.
>  * Automated recovery script to restore and verify integrity.
>  * Daily verification cron job (restore to test DB and check health).
>  * Document a step-by-step recovery runbook.
> 
10. Ongoing Security Maintenance
10.1 Security Maintenance Calendar
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Create automated maintenance:
>  * Weekly security report script (failed auths, costs, vulnerabilities).
>  * Monthly checklist (key age > 80 days, inactive users).
>  * Key rotation reminder system.
>  * /admin/security-status endpoint for real-time overview.
> 
11. Master Security Hardening Checklist
 * [ ] Complete pre-hardening security audit
 * [ ] Rotate all API keys and move to env vars
 * [ ] Set up automated secrets scanning
 * [ ] Configure JWT authentication on all endpoints
 * [ ] Implement RBAC with model tier restrictions
 * [ ] Enforce TLS 1.2+ and HSTS
 * [ ] Lock down CORS (no wildcards)
 * [ ] Apply IP restrictions to admin panel
 * [ ] Implement multi-layer rate limiting
 * [ ] Configure cost circuit breakers
 * [ ] Deploy prompt injection defenses
 * [ ] Set up comprehensive security logging
 * [ ] Create incident response automation
 * [ ] Implement data encryption (rest + transit)
 * [ ] Harden Docker/container configuration
 * [ ] Audit and pin all dependencies
 * [ ] Set up automated encrypted backups
 * [ ] Complete first recovery test
> 🤖 AGENT PROMPT — Copy & paste this to your AI agent:
> Run a final security verification:
>  * VERIFY: Authentication on all endpoints, CORS blocking, Rate limiting (simulate rapid requests), security headers, and non-root Docker user.
>  * SIMULATED ATTACK: Attempt known injection patterns, access admin from unauthorized IP, and use expired tokens.
>  * REPORT: Generate final security score, summary of changes, and date for next review.
> 
Built for the SPRINT Community by ScaleUP Media
Would you like me to generate a specific .env template for this setup?
