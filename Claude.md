# WHITE — Claude Code Project Instructions

## 1. Project Mission

WHITE is a website security assessment tool with two interfaces:

1. **GUI:** A minimal, user-friendly web application designed primarily for non-technical website owners and business decision-makers.
2. **CLI:** An independent command-line tool that developers can clone from GitHub and run locally.

Users enter a website URL and receive a security assessment containing evidence-backed findings, risk explanations, and practical remediation advice.

The GUI explains findings in plain English. The CLI provides detailed technical output.

Both interfaces MUST use the same Python scanning engine, check definitions, and finding schema.

WHITE must never claim to detect every possible vulnerability or guarantee that a website is secure.

## 2. Core Engineering Principles

- Build functional software, not frontend mockups.
- Never fabricate scan results, progress, or successful operations.
- Never mark a scan successful if the scanner or required operations failed.
- Never report a vulnerability without sufficient supporting evidence.
- Clearly distinguish confirmed findings, potential findings, passed checks, skipped checks, and errors.
- Implement features completely before presenting them as functional.
- Every visible button, link, form, and navigation item must work.
- Handle loading states, empty states, invalid inputs, timeouts, and failures.
- Prefer simple, maintainable implementations over unnecessary complexity.
- Never introduce paid infrastructure without explaining the cost and receiving my approval.
- Never claim a test, build, migration, deployment, or integration succeeded without verifying it.
- Preserve existing working code and inspect the repository before modifying files.
- Explain important decisions in clear, direct language.

## 3. Required Technology Stack

### Frontend
- Next.js with App Router
- TypeScript with strict mode
- React
- Tailwind CSS
- Accessible, reusable UI components
- Lucide icons where useful

### Backend and scanner
- Python
- FastAPI
- httpx
- Beautiful Soup
- Pydantic
- Typer for the CLI
- pytest and pytest-asyncio for testing

Use compatible, supported dependency versions. Pin dependencies where appropriate.

### Database
- Supabase PostgreSQL
- SQLAlchemy 2.x where appropriate
- Alembic for version-controlled database migrations
- Supabase Auth only where needed for hosted multi-user functionality
- Row Level Security for user-owned data

### Development
- Git
- GitHub-compatible repository structure
- Local environment variables
- Reproducible setup instructions
- Automated testing and linting

Do not add Redis, paid queues, external AI APIs, or additional infrastructure unless technically necessary and approved.

## 4. Architecture

Keep the following concerns separate:

- Frontend and presentation
- API and request validation
- Python scanning engine
- Individual security checks
- Database access
- Report generation
- CLI
- Automated tests

The Python scanner must operate independently of the GUI and hosted API.

The CLI must run the scanner locally without requiring a hosted backend, Supabase account, or paid service.

The GUI must communicate with a real backend and display real scan results.

Use a shared, versioned finding schema across the scanner, API, CLI, and reports.

Do not duplicate scanning logic in TypeScript.

Keep the code modular so a background worker can be introduced later without rewriting the scanner.

## 5. Local-First Development and Hosting

Build and verify WHITE locally before deploying it.

The initial development setup should support:

- A locally running Next.js frontend
- A locally running FastAPI backend
- A Python scanner running locally
- A Supabase development database
- An independently usable CLI

Avoid requiring a continuously running hosted worker for the initial prototype.

Do not assume Vercel is suitable for running the security scanner. Before deploying any scanning functionality, check the current hosting provider's terms, execution limits, acceptable-use policy, and applicable plan restrictions.

Vercel may host an eligible frontend, but scanning workloads must run only in an environment that permits them.

Do not introduce Render, Railway, or another paid service without explaining the available alternatives and obtaining approval.

## 6. Security and Authorization

WHITE must only scan websites the user owns or has explicit permission to assess.

For the hosted application, implement domain ownership verification before enabling scans. Use a documented verification mechanism, such as a DNS TXT record or verification file.

Implement:

- Strict URL parsing and validation
- HTTP and HTTPS scheme restrictions
- Rejection of embedded URL credentials
- DNS resolution validation
- Blocking of loopback, private, link-local, reserved, and cloud metadata addresses
- Redirect validation at every hop
- Protection against DNS rebinding and time-of-check/time-of-use problems
- Connection-level enforcement of validated destinations
- Request timeouts
- Response-size limits
- Page-count and scan-duration limits
- Concurrency and per-host rate limits
- Authentication and authorization for hosted operations
- Ownership checks for scan history and reports
- Safe logging with sensitive information redacted

Do not implement arbitrary URL fetching, proxy functionality, credential guessing, brute force, destructive payloads, denial-of-service testing, or unauthorized exploitation.

Do not execute downloaded website content.

Do not automatically submit forms that could modify data.

Do not collect, expose, or store credentials, session tokens, or unnecessary sensitive response data.

If authorization cannot be established or a destination cannot be validated safely, refuse the operation and explain why.

Treat all remote website content as untrusted input.

## 7. Scanning Engine

Implement a registry of individual, independently testable checks.

Initial checks may include:

1. HTTPS availability and HTTP redirect behaviour
2. TLS certificate information
3. Common security headers
4. Cookie security attributes
5. Mixed-content indicators
6. Public information exposure through responses
7. Directory listing indicators
8. Limited, non-destructive reflected-XSS indicators
9. Conservative SQL injection indicators
10. A small, documented set of public-file exposure checks

Use OWASP Top 10:2025 as a risk taxonomy, not a promise that every category can be detected through URL-only scanning.

Do not automatically classify every unusual response as a vulnerability.

Keep XSS and SQL injection checks conservative, bounded, and restricted to authorized targets. If reliable evidence cannot be collected safely, mark the check as NOT_TESTED.

Use the following check statuses:

- PASS
- FINDING
- POTENTIAL
- NOT_TESTED
- ERROR

Use severity levels INFO, LOW, MEDIUM, HIGH, and CRITICAL.

Keep severity separate from confidence. Document the rules used to assign each.

Each finding must contain:

- Stable check ID and check version
- Title
- Status
- Severity where applicable
- Confidence
- Plain-language description
- Technical explanation
- Business impact
- Evidence
- Recommended remediation
- Timestamp
- Affected URL where appropriate and safe
- Relevant execution errors

Redact sensitive information from findings and reports.

A PASS means only that the individual check completed without detecting the specified issue. It does not mean the website is secure.

## 8. GUI Design

Use a minimal, professional, responsive interface.

Visual guidelines:

- White or very light background
- Charcoal text
- Restrained green accent
- Subtle borders
- Consistent spacing
- Simple typography
- Accessible contrast
- Keyboard-accessible controls
- Useful empty, loading, success, and error states

Avoid excessive gradients, animations, decorative charts, unnecessary cards, and visual clutter.

Implement the following pages:

### Home / New Scan
- Website URL input
- Authorization confirmation
- Working scan button
- Brief explanation of scanner capabilities
- Validation and API error messages

### Scan Progress
- Actual job status
- Current stage
- Actual completed-check counts
- Elapsed time
- Cancellation if supported

Never use fabricated progress values.

### Executive Report
- Target hostname
- Scan timestamp and completion status
- Plain-English summary
- Findings grouped by severity
- Business impact
- Recommended next steps
- Checks passed, skipped, or failed
- Assessment limitations
- Working report download

### Finding Details
- What was detected
- Supporting evidence
- Why it matters
- Severity and confidence
- Recommended remediation
- Expandable technical details

### Scan History
- Previous scans belonging to the authorized user
- Scan dates and statuses
- Finding counts
- Links to previous reports

Do not display controls for features that have not been implemented.

## 9. CLI

Create a CLI named `white`.

Support commands equivalent to:

- `white scan https://authorized-example.com`
- `white scan https://authorized-example.com --format json --output report.json`
- `white scan https://authorized-example.com --format html --output report.html`
- `white checks`
- `white version`

Adapt syntax as appropriate for Typer.

The CLI must:

- Run without the GUI or hosted backend
- Use the shared Python scanning engine
- Validate targets and explain authorization requirements
- Display real scan