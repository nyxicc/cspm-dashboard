# CSPM Dashboard

A full-stack **Cloud Security Posture Management** tool that scans AWS environments for misconfigurations, maps findings to compliance frameworks, and uses AI to explain risks and model realistic attack paths.

---

## Features

- **40+ security checks** across 10 AWS services — S3, IAM, EC2, RDS, CloudTrail, KMS, Lambda, GuardDuty, Security Hub, and AWS Config
- **Compliance mapping** — every finding is tagged to CIS Benchmarks, SOC 2, PCI-DSS, NIST, and HIPAA controls
- **AI-powered risk explanations** — click any finding to get a contextual breakdown: what it is, why it's dangerous, a realistic attack scenario, and an immediate fix
- **AI attack path modeling** — generates 1–3 directed attack graphs showing how an adversary could chain findings together, with MITRE ATT&CK tactic mappings
- **Per-request credentials** — AWS credentials are used only for the duration of a scan and never stored
- **Concurrent scanning** — all 10 service scanners run in parallel via goroutines with a 5-minute timeout
- **CSV export** — download all findings as a formatted CSV report
- **Terraform test lab** — provision intentionally misconfigured AWS resources across all 10 services to validate the scanner end-to-end

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Go 1.24, stdlib `net/http`, AWS SDK v2 |
| Frontend | React 19, Vite, custom CSS Modules |
| AI | Anthropic Claude Sonnet (Messages API) |
| Infrastructure | Terraform, AWS |

---

## Getting Started

### Prerequisites

- [Go 1.21+](https://go.dev/dl/)
- [Node.js 18+](https://nodejs.org/)
- An AWS account with credentials (Access Key ID + Secret Access Key)
- An [Anthropic API key](https://console.anthropic.com/) for AI features

### Installation

```bash
git clone https://github.com/nyxicc/cspm-dashboard.git
cd cspm-dashboard
```

Install frontend dependencies:

```bash
cd frontend
npm install
cd ..
```

Create a `.env` file in the project root:

```env
ANTHROPIC_API_KEY=your_api_key_here
```

### Running

**Windows (one-click):**

```bat
start.bat
```

This loads your `.env`, starts the Go backend on `:8080`, waits for it to be ready, then launches the frontend dev server and opens `http://localhost:5173`.

**Manual:**

```bash
# Terminal 1 — backend
cd backend
go run .

# Terminal 2 — frontend
cd frontend
npm run dev
```

Then open [http://localhost:5173](http://localhost:5173).

---

## Usage

1. Enter your AWS **Access Key ID**, **Secret Access Key**, and **Region**. For MFA or assumed-role sessions, also provide a Session Token.
2. Click **Scan** — the dashboard will show results as they come in.
3. Use the **severity and service filters** to drill into specific findings.
4. Click any finding row to open a detail panel with an AI-generated explanation.
5. Switch to the **Attack Paths (AI)** tab to see how findings can be chained into multi-step attacks.
6. Use **Export CSV** to download a full report.

> Credentials are validated against STS and used only for the current scan. Nothing is stored on the server.

---

## AWS Permissions

The IAM user or role used for scanning needs read-only access to the services being checked. At minimum:

```
AmazonS3ReadOnlyAccess
IAMReadOnlyAccess
AmazonEC2ReadOnlyAccess
AmazonRDSReadOnlyAccess
AWSCloudTrailReadOnlyAccess
AWSKeyManagementServicePowerUser (read actions)
AWSLambda_ReadOnlyAccess
AmazonGuardDutyReadOnlyAccess
AWSSecurityHubReadOnlyAccess
AWSConfigUserAccess
```

Or attach the AWS managed `SecurityAudit` policy for broad read-only coverage.

---

## Security Checks

| Service | Checks |
|---------|--------|
| **S3** | Public access block, encryption at rest, access logging, versioning, HTTPS-only policy, public ACLs |
| **IAM** | Root access keys, root MFA, password policy strength, per-user MFA, admin policies on users, access key age (>90 days), inactive users, console + key combos, single active key, group-based permissions |
| **EC2** | Unrestricted ingress on SSH/RDP/DB ports, default security group traffic, EBS encryption, VPC flow logs |
| **RDS** | Public accessibility, storage encryption, backup retention (<7 days), deletion protection |
| **CloudTrail** | Trail logging enabled, log file validation, multi-region coverage, KMS encryption |
| **KMS** | Annual key rotation, wildcard principal in key policy |
| **Lambda** | VPC configuration, secrets in environment variables, admin execution role |
| **GuardDuty** | Detector existence and enabled status |
| **Security Hub** | Enrollment status, stale critical findings (unresolved >30 days) |
| **AWS Config** | Recorder existence, recording status, AllSupported flag, delivery channel |

---

## Terraform Test Lab

The `terraform/aws/` directory provisions intentionally misconfigured AWS resources to generate real scanner findings for testing and demos.

> **Warning:** These resources are deliberately insecure. Never deploy in a production account.

```bash
cd terraform/aws
terraform init
terraform apply -var="enabled=true"
```

Use the `scanner_instructions` output to get the generated IAM access key and paste it into the UI. Expected output: ~32 findings across all 10 services.

RDS is gated separately to avoid unnecessary cost:

```bash
terraform apply -var="enabled=true" -var="create_rds=true"
```

Tear down when done:

```bash
terraform destroy -var="enabled=true"
```

---

## Project Structure

```
cspm-dashboard/
├── backend/
│   ├── main.go               # HTTP server entry point (:8080)
│   ├── api/
│   │   ├── routes.go         # All HTTP handlers + Claude integration
│   │   └── attack_paths.go   # AI attack path generation
│   ├── models/
│   │   └── finding.go        # Finding struct, severity/status types
│   └── scanners/             # One file per AWS service
├── frontend/
│   └── src/
│       ├── components/       # SeveritySummaryBar, ComplianceCards, FindingsTable, AttackPaths
│       ├── hooks/            # useScan, useSummary
│       ├── api/              # fetch wrappers
│       └── utils/            # Compliance grouping, CSV export, severity helpers
├── terraform/aws/            # Intentionally misconfigured test infrastructure
├── .env                      # ANTHROPIC_API_KEY (gitignored)
└── start.bat                 # Windows one-click launcher
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Liveness check |
| `POST` | `/api/scan` | Run a full scan, returns all findings |
| `POST` | `/api/findings/summary` | Findings count by severity and service |
| `POST` | `/api/explain` | AI explanation for a single finding |
| `POST` | `/api/attack-paths` | AI-generated attack path graph for all findings |

All scan endpoints accept:
```json
{
  "access_key_id": "...",
  "secret_access_key": "...",
  "session_token": "...",
  "region": "us-east-1"
}
```

---

## License

MIT
