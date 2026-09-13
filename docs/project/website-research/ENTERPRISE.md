# Enterprise Website / Data Architecture Research

## Principle

Enterprise mode may require richer organizational/security data, but "the contract allows it" is not a reason to collect everything.

> Collect enterprise data only when a contracted SecretLoop capability demonstrably requires it.

Raw credentials should remain local and source code should remain local wherever technically possible.

## Separate data categories

### Customer security data

Used to provide SecretLoop exposure-intelligence functionality, for example organization/repository identity, finding metadata, credential identity, verification state, exposure observations and remediation state where configured.

### Operational/audit data

Required to securely operate the enterprise service, authenticate/authorize users, investigate incidents and satisfy contractual audit requirements.

### Product telemetry

Used to understand SecretLoop feature adoption. This must not silently absorb customer security data.

Enterprise purchase does not imply permission to use security data for GPY product analytics, research or marketing.

## Preferred processing model

```text
CUSTOMER ENVIRONMENT

source code
credential plaintext
raw files
      ↓
SecretLoop scanner
      ↓
structured exposure metadata
      ↓
Enterprise control plane
```

The control plane should not require raw source or plaintext credentials merely to provide centralized exposure intelligence.

## Configurable data-boundary policy

Future enterprise policy may control fields such as:

```text
Repository identity       configurable
File paths                configurable
Finding metadata          configurable
Verification status       configurable
Exposure observations     configurable
Developer identity        configurable/off by default
Source snippets           off by default
Source code               prefer never
Credential plaintext      locked off by default
```

Different organizations can choose different boundaries. Government/air-gapped deployments may keep all data inside the customer's environment.

## Enterprise privacy/security documentation

Before a real enterprise production onboarding, prepare and review as applicable:

- data inventory;
- privacy policy;
- DPA;
- enterprise agreement/MSA;
- security architecture;
- encryption model;
- tenant isolation;
- authentication, SSO and RBAC design;
- audit logging;
- retention/deletion controls;
- backup policy;
- subprocessors;
- incident response;
- vulnerability disclosure;
- employee/admin access controls;
- data export/deletion;
- deployment/data-residency options.

Legal documents and compliance claims require appropriate professional/legal review for the jurisdictions and customers involved.

## Data inventory concept

Document explicitly for every retained field:

```text
DATA | PURPOSE | STORAGE LOCATION | RETENTION | CUSTOMER CONTROL | REQUIRED/OPTIONAL
```

Retention periods should not be invented before actual product/legal requirements are known.

## Product-visible privacy controls

Enterprise administrators should be able to see what SecretLoop stores and configure supported boundaries/retention rather than relying only on contractual text.

Potential future controls:

- data-sharing policy;
- retention configuration;
- export organization data;
- deletion workflow;
- product analytics on/off;
- audit visibility.

## Deployment models

### Community / Local

Everything local; optional aggregate product counters only.

### Enterprise Cloud

Local scanners send only configured structured exposure metadata to the GPY-hosted organization control plane.

### Enterprise Sovereign / On-prem

Scanner, control plane, database and dashboard run inside the customer-controlled environment; designed for regulated/air-gapped use cases when/if customer evidence justifies the work.

## Enterprise engagement discipline

When a prospective enterprise requests a feature/integration/data field, classify it before implementation:

- required for pilot;
- required for production;
- customer-specific;
- strategic reusable product capability.

Do not agree automatically to every integration or security/compliance claim.
