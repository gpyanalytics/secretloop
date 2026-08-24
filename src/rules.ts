export type Severity = "critical" | "high" | "medium" | "low";

export interface SecretRule {
  id: string;
  description: string;
  regex: RegExp;
  /** If true, the match itself is the secret. If false, use the first capture group. */
  fullMatch: boolean;
  /**
   * Cheap literal prescreen. If none of these substrings appear in the file
   * (case-insensitive), the regex is skipped entirely. This is what keeps a
   * 100+ rule set as fast as a 12-rule one on large files.
   */
  keywords?: string[];
  /** Minimum Shannon entropy the captured value must have. Filters structured lookalikes. */
  entropy?: number;
  /** Rule-scoped false-positive patterns. A value matching any of these is dropped. */
  allowlist?: RegExp[];
  /**
   * How this rule's findings are identified in a baseline. Omitted means
   * "value" — hash the captured secret, which is safe for a provider-generated
   * token. "context" is for captures that can be a human-chosen password, where
   * a truncated hash in a committed file is a wordlist away from the plaintext.
   * "keyword" defers the choice to the matched keyword, for a rule whose single
   * alternation covers both.
   */
  fingerprintStrategy?: "value" | "context" | "keyword";
  /**
   * Matches by shape rather than by provider — `<keyword> = "<value>"` — so it
   * overlaps other rules by construction. When it does, the named rule wins:
   * that one identifies the provider, which is what unlocks verification,
   * rotation and the provider-named consent prompt. A generic match knows only
   * that something key-shaped was assigned.
   *
   * A flag rather than a per-rule specificity score: across the whole detection
   * corpus every overlap involves this one rule and named rules never collide
   * with each other, so scoring 103 rules would invent 102 numbers nobody could
   * check to settle a conflict that only ever has one side.
   */
  generic?: boolean;
  severity: Severity;
}

// Matches documentation/sample values that share a real credential's shape.
const DOC_SAMPLE = [
  /EXAMPLE/i,
  /^(?:x{6,}|X{6,}|0{6,}|1{6,}|a{6,}|A{6,})$/,
  /YOUR[_-]?(?:API|SECRET|ACCESS|PRIVATE)?[_-]?(?:KEY|TOKEN|SECRET)/i,
  /\b(?:sample|dummy|placeholder|redacted|changeme|notreal|fakekey)\b/i,
  // Stripe's published sample key. Unlike AWS's, its value carries no marker a
  // pattern could catch, so it has to be listed literally. Shared rather than
  // scoped to stripe-secret-key: the generic assignment rule matches the same
  // span, so exempting one rule only changes which rule reports the sample.
  /^(?:sk|rk)_(?:live|test)_4eC39HqLyjWDarjtT1zdp7dc$/,
];

/**
 * True for a value that is a published documentation sample rather than a
 * credential. Exposed because the entropy pass needs it too: a sample dropped by
 * every named rule still has the randomness of a real key, so without this it is
 * simply reported one tier down instead of not at all.
 */
export function isDocumentationSample(value: string): boolean {
  return DOC_SAMPLE.some((r) => r.test(value));
}

export const rules: SecretRule[] = [
  // ---------------------------------------------------------------- AWS
  {
    id: "aws-access-key",
    description: "AWS Access Key ID",
    regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    fullMatch: true,
    keywords: ["AKIA", "ASIA", "ABIA", "ACCA"],
    allowlist: [/^AKIAIOSFODNN7EXAMPLE$/, ...DOC_SAMPLE],
    severity: "critical",
  },
  {
    id: "aws-secret-key",
    description: "AWS Secret Access Key",
    regex:
      /(?:aws[_.-]?secret[_.-]?(?:access[_.-]?)?key|aws[_.-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    fullMatch: false,
    keywords: ["aws_secret", "aws-secret", "awssecret", "aws.secret"],
    entropy: 3.5,
    allowlist: DOC_SAMPLE,
    severity: "critical",
  },
  {
    id: "aws-session-token",
    description: "AWS Session Token",
    regex: /(?:aws[_.-]?session[_.-]?token)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{100,})["']?/gi,
    fullMatch: false,
    keywords: ["aws_session_token", "aws-session-token"],
    severity: "high",
  },

  // ------------------------------------------------------------- GCP / Google
  {
    id: "google-api-key",
    description: "Google API Key",
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    fullMatch: true,
    keywords: ["AIza"],
    allowlist: DOC_SAMPLE,
    severity: "high",
  },
  {
    id: "gcp-service-account-key",
    description: "GCP Service Account private key ID",
    regex: /"private_key_id"\s*:\s*"([a-f0-9]{40})"/g,
    fullMatch: false,
    keywords: ["private_key_id"],
    severity: "critical",
  },
  {
    id: "gcp-oauth-client-secret",
    description: "GCP OAuth Client Secret",
    regex: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/g,
    fullMatch: true,
    keywords: ["GOCSPX"],
    severity: "high",
  },
  {
    id: "firebase-cloud-messaging-key",
    description: "Firebase Cloud Messaging server key",
    regex: /\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{130,}\b/g,
    fullMatch: true,
    keywords: ["APA91b"],
    severity: "high",
  },

  // ----------------------------------------------------------------- Azure
  {
    id: "azure-storage-account-key",
    description: "Azure Storage account key (connection string)",
    regex: /AccountKey\s*=\s*([A-Za-z0-9+/=]{86,88})/g,
    fullMatch: false,
    keywords: ["AccountKey"],
    severity: "critical",
  },
  {
    id: "azure-ad-client-secret",
    description: "Azure AD application client secret",
    regex: /\b[A-Za-z0-9~._-]{3}(?:8Q~|7Q~|9Q~)[A-Za-z0-9~._-]{31,34}\b/g,
    fullMatch: true,
    keywords: ["8Q~", "7Q~", "9Q~"],
    entropy: 3.6,
    severity: "critical",
  },
  {
    id: "azure-sas-token",
    description: "Azure Shared Access Signature token",
    regex: /\bsig=([A-Za-z0-9%2F%2B/+=]{43,})(?:&|$|["'\s])/g,
    fullMatch: false,
    keywords: ["sig="],
    severity: "high",
  },

  // ------------------------------------------------------------------ GitHub
  {
    id: "github-token",
    description: "GitHub Personal Access Token",
    regex: /\bghp_[A-Za-z0-9]{36}\b/g,
    fullMatch: true,
    keywords: ["ghp_"],
    allowlist: DOC_SAMPLE,
    severity: "critical",
  },
  {
    id: "github-oauth-token",
    description: "GitHub OAuth Access Token",
    regex: /\bgho_[A-Za-z0-9]{36}\b/g,
    fullMatch: true,
    keywords: ["gho_"],
    severity: "critical",
  },
  {
    id: "github-app-token",
    description: "GitHub App / Installation Token",
    regex: /\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b/g,
    fullMatch: true,
    keywords: ["ghu_", "ghs_"],
    severity: "critical",
  },
  {
    id: "github-refresh-token",
    description: "GitHub Refresh Token",
    regex: /\bghr_[A-Za-z0-9]{36,255}\b/g,
    fullMatch: true,
    keywords: ["ghr_"],
    severity: "high",
  },
  {
    id: "github-fine-grained-pat",
    description: "GitHub Fine-Grained PAT",
    regex: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g,
    fullMatch: true,
    keywords: ["github_pat_"],
    severity: "critical",
  },

  // ------------------------------------------------------------------ GitLab
  {
    id: "gitlab-pat",
    description: "GitLab Personal Access Token",
    regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    fullMatch: true,
    keywords: ["glpat-"],
    severity: "critical",
  },
  {
    id: "gitlab-runner-token",
    description: "GitLab Runner Registration/Auth Token",
    regex: /\b(?:glrt|glagent|glcbt)-[A-Za-z0-9_-]{20,}\b/g,
    fullMatch: true,
    keywords: ["glrt-", "glagent-", "glcbt-"],
    severity: "high",
  },
  {
    id: "gitlab-pipeline-trigger",
    description: "GitLab Pipeline Trigger Token",
    regex: /\bglptt-[A-Za-z0-9_-]{20,}\b/g,
    fullMatch: true,
    keywords: ["glptt-"],
    severity: "high",
  },
  {
    id: "gitlab-deploy-token",
    description: "GitLab Deploy Token",
    regex: /\bgldt-[A-Za-z0-9_-]{20,}\b/g,
    fullMatch: true,
    keywords: ["gldt-"],
    severity: "high",
  },

  // -------------------------------------------------------- Atlassian / Bitbucket
  {
    id: "atlassian-api-token",
    description: "Atlassian / Jira API Token",
    regex: /\bATATT3x[A-Za-z0-9_\-=.]{100,}\b/g,
    fullMatch: true,
    keywords: ["ATATT3x"],
    severity: "critical",
  },
  {
    id: "bitbucket-app-password",
    description: "Bitbucket App Password / API Token",
    regex: /\bATBB[A-Za-z0-9]{32,}\b/g,
    fullMatch: true,
    keywords: ["ATBB"],
    severity: "critical",
  },

  // ----------------------------------------------------------------- Payments
  {
    id: "stripe-secret-key",
    description: "Stripe / Clerk secret key",
    regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b/g,
    fullMatch: true,
    keywords: ["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
    allowlist: DOC_SAMPLE,
    severity: "critical",
  },
  {
    id: "stripe-webhook-secret",
    description: "Stripe Webhook Signing Secret",
    regex: /\bwhsec_[A-Za-z0-9]{32,}\b/g,
    fullMatch: true,
    keywords: ["whsec_"],
    severity: "high",
  },
  {
    id: "shopify-token",
    description: "Shopify Access Token",
    regex: /\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b/g,
    fullMatch: true,
    keywords: ["shpat_", "shpss_", "shpca_", "shppa_"],
    severity: "critical",
  },
  {
    id: "square-access-token",
    description: "Square Access Token",
    regex: /\b(?:sq0atp-[A-Za-z0-9_-]{22}|EAAA[A-Za-z0-9_-]{59,})\b/g,
    fullMatch: true,
    keywords: ["sq0atp-", "EAAA"],
    severity: "critical",
  },
  {
    id: "square-oauth-secret",
    description: "Square OAuth Secret",
    regex: /\bsq0csp-[A-Za-z0-9_-]{43}\b/g,
    fullMatch: true,
    keywords: ["sq0csp-"],
    severity: "critical",
  },
  {
    id: "razorpay-key",
    description: "Razorpay API Key",
    regex: /\brzp_(?:live|test)_[A-Za-z0-9]{14}\b/g,
    fullMatch: true,
    keywords: ["rzp_live_", "rzp_test_"],
    severity: "high",
  },
  {
    id: "paypal-braintree-token",
    description: "PayPal / Braintree Access Token",
    regex: /\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}\b/g,
    fullMatch: true,
    keywords: ["access_token$"],
    severity: "critical",
  },
  {
    id: "plaid-secret",
    description: "Plaid API Secret",
    regex: /(?:plaid[_.-]?secret)["']?\s*[:=]\s*["']?([a-f0-9]{30})["']?/gi,
    fullMatch: false,
    keywords: ["plaid"],
    severity: "high",
  },

  // --------------------------------------------------------------- AI providers
  {
    id: "openai-api-key",
    description: "OpenAI API Key",
    regex: /\bsk-(?:proj|svcacct|admin)?-?[A-Za-z0-9_-]{32,}\b/g,
    fullMatch: true,
    keywords: ["sk-"],
    entropy: 3.5,
    allowlist: [/^sk-ant-/, ...DOC_SAMPLE],
    severity: "critical",
  },
  {
    id: "anthropic-api-key",
    description: "Anthropic API Key",
    regex: /\bsk-ant-(?:api\d{2}|admin\d{2})-[A-Za-z0-9_-]{80,}\b/g,
    fullMatch: true,
    keywords: ["sk-ant-"],
    severity: "critical",
  },
  {
    id: "huggingface-token",
    description: "Hugging Face Access Token",
    regex: /\bhf_[A-Za-z0-9]{34,}\b/g,
    fullMatch: true,
    keywords: ["hf_"],
    severity: "high",
  },
  {
    id: "replicate-token",
    description: "Replicate API Token",
    regex: /\br8_[A-Za-z0-9]{37,}\b/g,
    fullMatch: true,
    keywords: ["r8_"],
    severity: "high",
  },
  {
    id: "groq-api-key",
    description: "Groq API Key",
    regex: /\bgsk_[A-Za-z0-9]{50,}\b/g,
    fullMatch: true,
    keywords: ["gsk_"],
    severity: "high",
  },
  {
    id: "perplexity-api-key",
    description: "Perplexity API Key",
    regex: /\bpplx-[A-Za-z0-9]{32,}\b/g,
    fullMatch: true,
    keywords: ["pplx-"],
    severity: "high",
  },
  {
    id: "langsmith-api-key",
    description: "LangSmith API Key",
    regex: /\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b/g,
    fullMatch: true,
    keywords: ["lsv2_"],
    severity: "high",
  },

  // ---------------------------------------------------------------- Messaging
  {
    id: "slack-token",
    description: "Slack Token",
    regex: /\bxox[baprse]-[A-Za-z0-9-]{10,}\b/g,
    fullMatch: true,
    keywords: ["xox"],
    allowlist: DOC_SAMPLE,
    severity: "critical",
  },
  {
    id: "slack-app-config-token",
    description: "Slack App Configuration Token",
    regex: /\bxapp-\d-[A-Za-z0-9_-]{20,}\b/g,
    fullMatch: true,
    keywords: ["xapp-"],
    severity: "high",
  },
  {
    id: "slack-webhook",
    description: "Slack Webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9+/]{40,}/g,
    fullMatch: true,
    keywords: ["hooks.slack.com"],
    severity: "high",
  },
  {
    id: "discord-bot-token",
    description: "Discord Bot Token",
    regex: /\b[MNO][A-Za-z0-9_-]{23,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b/g,
    fullMatch: true,
    keywords: ["discord"],
    severity: "critical",
  },
  {
    id: "discord-webhook",
    description: "Discord Webhook URL",
    regex: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,}\/[A-Za-z0-9_-]{60,}/g,
    fullMatch: true,
    keywords: ["discord.com/api/webhooks", "discordapp.com/api/webhooks"],
    severity: "high",
  },
  {
    id: "telegram-bot-token",
    description: "Telegram Bot Token",
    regex: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g,
    fullMatch: true,
    keywords: [":AA"],
    severity: "high",
  },
  {
    id: "twilio-api-key",
    description: "Twilio API Key SID",
    regex: /\bSK[a-f0-9]{32}\b/g,
    fullMatch: true,
    keywords: ["twilio", "SK"],
    severity: "high",
  },
  {
    id: "twilio-auth-token",
    description: "Twilio Auth Token",
    regex: /(?:twilio[_.-]?(?:auth[_.-]?)?token)["']?\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
    fullMatch: false,
    keywords: ["twilio"],
    severity: "critical",
  },
  {
    id: "sendgrid-api-key",
    description: "SendGrid API Key",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    fullMatch: true,
    keywords: ["SG."],
    severity: "critical",
  },
  {
    id: "mailgun-api-key",
    description: "Mailgun API Key",
    regex: /\bkey-[a-f0-9]{32}\b/g,
    fullMatch: true,
    keywords: ["key-"],
    severity: "high",
  },
  {
    id: "mailchimp-api-key",
    description: "Mailchimp API Key",
    regex: /\b[a-f0-9]{32}-us\d{1,2}\b/g,
    fullMatch: true,
    keywords: ["-us"],
    severity: "high",
  },
  {
    id: "postmark-server-token",
    description: "Postmark Server Token",
    regex: /(?:postmark[_.-]?(?:server[_.-]?)?token)["']?\s*[:=]\s*["']?([a-f0-9-]{36})["']?/gi,
    fullMatch: false,
    keywords: ["postmark"],
    severity: "high",
  },

  // ------------------------------------------------------------ Package registries
  {
    id: "npm-token",
    description: "npm Access Token",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    fullMatch: true,
    keywords: ["npm_"],
    severity: "critical",
  },
  {
    id: "pypi-token",
    description: "PyPI Upload Token",
    regex: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g,
    fullMatch: true,
    keywords: ["pypi-AgEIcHlwaS5vcmc"],
    severity: "critical",
  },
  {
    id: "rubygems-token",
    description: "RubyGems API Key",
    regex: /\brubygems_[a-f0-9]{48}\b/g,
    fullMatch: true,
    keywords: ["rubygems_"],
    severity: "critical",
  },
  {
    id: "dockerhub-pat",
    description: "Docker Hub Personal Access Token",
    regex: /\bdckr_pat_[A-Za-z0-9_-]{27,}\b/g,
    fullMatch: true,
    keywords: ["dckr_pat_"],
    severity: "critical",
  },
  {
    id: "jfrog-token",
    description: "JFrog Artifactory Token",
    regex: /\b(?:AKCp[A-Za-z0-9]{60,}|cmVmdGtuOjAx[A-Za-z0-9_/+=-]{60,})\b/g,
    fullMatch: true,
    keywords: ["AKCp", "cmVmdGtuOjAx"],
    severity: "critical",
  },
  {
    id: "nuget-api-key",
    description: "NuGet API Key",
    regex: /\boy2[a-z0-9]{43}\b/g,
    fullMatch: true,
    keywords: ["oy2"],
    severity: "high",
  },

  // -------------------------------------------------------------- Infra / hosting
  {
    id: "digitalocean-token",
    description: "DigitalOcean Access Token",
    regex: /\bdo[oprt]_v1_[a-f0-9]{64}\b/g,
    fullMatch: true,
    keywords: ["dop_v1_", "doo_v1_", "dor_v1_", "dot_v1_"],
    severity: "critical",
  },
  {
    id: "heroku-api-key",
    description: "Heroku API Key",
    regex: /(?:heroku[_.-]?(?:api[_.-]?)?key)["']?\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?/gi,
    fullMatch: false,
    keywords: ["heroku"],
    severity: "critical",
  },
  {
    id: "cloudflare-api-token",
    description: "Cloudflare API Token",
    regex: /(?:cloudflare|cf)[_.-]?api[_.-]?(?:token|key)["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{37,40})["']?/gi,
    fullMatch: false,
    keywords: ["cloudflare", "cf_api"],
    entropy: 3.5,
    severity: "critical",
  },
  {
    id: "cloudflare-origin-ca-key",
    description: "Cloudflare Origin CA Key",
    regex: /\bv1\.0-[A-Za-z0-9]{24}-[A-Za-z0-9]{146}\b/g,
    fullMatch: true,
    keywords: ["v1.0-"],
    severity: "critical",
  },
  {
    id: "flyio-token",
    description: "Fly.io API Token",
    regex: /\bfm[12][ar]?_[A-Za-z0-9+/=_-]{40,}\b/g,
    fullMatch: true,
    keywords: ["fm1a_", "fm1r_", "fm2_"],
    severity: "critical",
  },
  {
    id: "vercel-token",
    description: "Vercel API Token",
    regex: /(?:vercel[_.-]?(?:api[_.-]?)?token)["']?\s*[:=]\s*["']?([A-Za-z0-9]{24})["']?/gi,
    fullMatch: false,
    keywords: ["vercel"],
    entropy: 3.4,
    severity: "high",
  },
  {
    id: "netlify-token",
    description: "Netlify Access Token",
    regex: /(?:netlify[_.-]?(?:auth[_.-]?|access[_.-]?)?token)["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{40,64})["']?/gi,
    fullMatch: false,
    keywords: ["netlify"],
    entropy: 3.5,
    severity: "high",
  },
  {
    id: "ngrok-authtoken",
    description: "ngrok Auth Token",
    regex: /\b[0-9][A-Za-z0-9]{19}_[A-Za-z0-9]{20,27}\b/g,
    fullMatch: true,
    keywords: ["ngrok"],
    severity: "medium",
  },
  {
    id: "terraform-cloud-token",
    description: "Terraform Cloud API Token",
    regex: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}\b/g,
    fullMatch: true,
    keywords: ["atlasv1."],
    severity: "critical",
  },
  {
    id: "hashicorp-vault-token",
    description: "HashiCorp Vault Token",
    regex: /\bhv[sb]\.[A-Za-z0-9_-]{50,}\b/g,
    fullMatch: true,
    keywords: ["hvs.", "hvb."],
    severity: "critical",
  },
  {
    id: "doppler-token",
    description: "Doppler Service/Personal Token",
    regex: /\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9_-]{40,}\b/g,
    fullMatch: true,
    keywords: ["dp.pt.", "dp.st.", "dp.sa.", "dp.ct."],
    severity: "critical",
  },
  {
    id: "onepassword-service-account",
    description: "1Password Service Account Token",
    regex: /\bops_[A-Za-z0-9+/=_-]{40,}\b/g,
    fullMatch: true,
    keywords: ["ops_"],
    severity: "critical",
  },

  // ------------------------------------------------------------ Databases / data
  {
    id: "db-connection-string",
    fingerprintStrategy: "context",
    description: "Database connection string with embedded credentials",
    regex:
      /(?:postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|clickhouse|cassandra):\/\/[^:\s"'/]+:([^@\s"']{3,})@[^\s"']+/gi,
    fullMatch: false,
    keywords: ["://"],
    allowlist: [/^(?:password|pass|pwd|secret|changeme|example|test|root|admin)$/i, ...DOC_SAMPLE],
    severity: "critical",
  },
  {
    id: "http-basic-auth-url",
    fingerprintStrategy: "context",
    description: "URL with embedded HTTP basic-auth credentials",
    regex: /https?:\/\/[^:\s"'/]+:([^@\s"'/]{6,})@[^\s"']+/gi,
    fullMatch: false,
    keywords: ["://"],
    entropy: 3.0,
    allowlist: [/^(?:password|pass|pwd|secret|changeme|example|test|token)$/i, ...DOC_SAMPLE],
    severity: "critical",
  },
  {
    id: "snowflake-credentials",
    fingerprintStrategy: "context",
    description: "Snowflake account password",
    regex: /(?:snowflake[_.-]?password)["']?\s*[:=]\s*["']([^"'\s]{8,})["']/gi,
    fullMatch: false,
    keywords: ["snowflake"],
    severity: "critical",
  },
  {
    id: "databricks-token",
    description: "Databricks Personal Access Token",
    regex: /\bdapi[a-f0-9]{32}(?:-\d)?\b/g,
    fullMatch: true,
    keywords: ["dapi"],
    severity: "critical",
  },
  {
    id: "supabase-service-key",
    description: "Supabase Personal Access Token",
    regex: /\bsbp_[a-f0-9]{40}\b/g,
    fullMatch: true,
    keywords: ["sbp_"],
    severity: "critical",
  },
  {
    id: "planetscale-token",
    description: "PlanetScale Token",
    regex: /\bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.-]{32,}\b/g,
    fullMatch: true,
    keywords: ["pscale_"],
    severity: "critical",
  },

  // ---------------------------------------------------------- Observability / CI
  {
    id: "datadog-api-key",
    description: "Datadog API Key",
    regex: /(?:datadog|dd)[_.-]?(?:api[_.-]?)?key["']?\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
    fullMatch: false,
    keywords: ["datadog", "dd_api", "dd-api"],
    severity: "high",
  },
  {
    id: "newrelic-key",
    description: "New Relic API Key",
    regex: /\bNR(?:AK|JS|II|RA|IQ)-[A-Za-z0-9]{27}\b/g,
    fullMatch: true,
    keywords: ["NRAK-", "NRJS-", "NRII-"],
    severity: "high",
  },
  {
    id: "sentry-auth-token",
    description: "Sentry Auth Token",
    regex: /\bsntry[su]_[A-Za-z0-9_.-]{40,}\b/g,
    fullMatch: true,
    keywords: ["sntrys_", "sntryu_"],
    severity: "high",
  },
  {
    id: "grafana-token",
    description: "Grafana Service Account / Cloud Token",
    regex: /\b(?:glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}|glc_[A-Za-z0-9+/=]{32,})\b/g,
    fullMatch: true,
    keywords: ["glsa_", "glc_"],
    severity: "high",
  },
  {
    id: "sonarqube-token",
    description: "SonarQube Token",
    regex: /\bsq[apu]_[a-f0-9]{40}\b/g,
    fullMatch: true,
    keywords: ["squ_", "sqp_", "sqa_"],
    severity: "high",
  },
  {
    id: "codecov-token",
    description: "Codecov Upload Token",
    regex: /(?:codecov[_.-]?token)["']?\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?/gi,
    fullMatch: false,
    keywords: ["codecov"],
    severity: "medium",
  },
  {
    id: "buildkite-token",
    description: "Buildkite Agent Token",
    regex: /(?:buildkite[_.-]?(?:agent[_.-]?)?token)["']?\s*[:=]\s*["']?([A-Za-z0-9]{40,})["']?/gi,
    fullMatch: false,
    keywords: ["buildkite"],
    severity: "high",
  },
  {
    id: "circleci-token",
    description: "CircleCI Personal Token",
    regex: /(?:circle[_.-]?ci[_.-]?token|CIRCLE_TOKEN)["']?\s*[:=]\s*["']?([a-f0-9]{40})["']?/gi,
    fullMatch: false,
    keywords: ["circle"],
    severity: "high",
  },
  {
    id: "launchdarkly-key",
    description: "LaunchDarkly Access Token",
    regex: /\bapi-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g,
    fullMatch: true,
    keywords: ["api-"],
    severity: "medium",
  },

  // ----------------------------------------------------------- SaaS / productivity
  {
    id: "notion-token",
    description: "Notion Integration Token",
    regex: /\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b/g,
    fullMatch: true,
    keywords: ["secret_", "ntn_"],
    severity: "high",
  },
  {
    id: "linear-api-key",
    description: "Linear API Key",
    regex: /\blin_api_[A-Za-z0-9]{40}\b/g,
    fullMatch: true,
    keywords: ["lin_api_"],
    severity: "high",
  },
  {
    id: "figma-token",
    description: "Figma Personal Access Token",
    regex: /\bfigd_[A-Za-z0-9_-]{40,}\b/g,
    fullMatch: true,
    keywords: ["figd_"],
    severity: "high",
  },
  {
    id: "airtable-token",
    description: "Airtable Personal Access Token",
    regex: /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b/g,
    fullMatch: true,
    keywords: ["pat"],
    severity: "high",
  },
  {
    id: "asana-token",
    description: "Asana Personal Access Token",
    regex: /\b\d{1,}\/\d{16}:[A-Za-z0-9]{32}\b/g,
    fullMatch: true,
    keywords: ["asana"],
    severity: "high",
  },
  {
    id: "dropbox-token",
    description: "Dropbox Access Token",
    regex: /\bsl\.[A-Za-z0-9_-]{130,}\b/g,
    fullMatch: true,
    keywords: ["sl."],
    severity: "high",
  },
  {
    id: "algolia-admin-key",
    description: "Algolia Admin API Key",
    regex: /(?:algolia[_.-]?(?:admin[_.-]?)?(?:api[_.-]?)?key)["']?\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
    fullMatch: false,
    keywords: ["algolia"],
    severity: "high",
  },
  {
    id: "intercom-token",
    description: "Intercom Access Token",
    regex: /\bdG9r[A-Za-z0-9+/=]{50,}\b/g,
    fullMatch: true,
    keywords: ["dG9r"],
    severity: "high",
  },
  {
    id: "contentful-token",
    description: "Contentful Delivery/Management Token",
    regex: /\bCFPAT-[A-Za-z0-9_-]{43}\b/g,
    fullMatch: true,
    keywords: ["CFPAT-"],
    severity: "high",
  },
  {
    id: "okta-api-token",
    description: "Okta API Token",
    regex: /(?:okta[_.-]?(?:api[_.-]?)?token)["']?\s*[:=]\s*["']?(00[A-Za-z0-9_-]{40})["']?/gi,
    fullMatch: false,
    keywords: ["okta"],
    severity: "critical",
  },
  {
    id: "auth0-client-secret",
    description: "Auth0 Client Secret",
    regex: /(?:auth0[_.-]?client[_.-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{40,})["']?/gi,
    fullMatch: false,
    keywords: ["auth0"],
    severity: "critical",
  },
  {
    id: "pusher-secret",
    description: "Pusher App Secret",
    regex: /(?:pusher[_.-]?(?:app[_.-]?)?secret)["']?\s*[:=]\s*["']?([a-f0-9]{20})["']?/gi,
    fullMatch: false,
    keywords: ["pusher"],
    severity: "high",
  },
  {
    id: "segment-write-key",
    description: "Segment Write Key",
    regex: /(?:segment[_.-]?write[_.-]?key)["']?\s*[:=]\s*["']?([A-Za-z0-9]{32})["']?/gi,
    fullMatch: false,
    keywords: ["segment"],
    severity: "medium",
  },

  // --------------------------------------------------------------- Social / media
  {
    id: "facebook-access-token",
    description: "Facebook / Meta Access Token",
    regex: /\bEAA[A-Za-z0-9]{90,}\b/g,
    fullMatch: true,
    keywords: ["EAA"],
    allowlist: [/^EAAA/],
    severity: "high",
  },
  {
    id: "twitter-bearer-token",
    description: "Twitter/X Bearer Token",
    regex: /\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{50,}\b/g,
    fullMatch: true,
    keywords: ["AAAAAAAAAAAAAAAAAAAAA"],
    severity: "high",
  },
  {
    id: "twitch-client-secret",
    description: "Twitch Client Secret",
    regex: /(?:twitch[_.-]?client[_.-]?secret)["']?\s*[:=]\s*["']?([a-z0-9]{30})["']?/gi,
    fullMatch: false,
    keywords: ["twitch"],
    severity: "high",
  },
  {
    id: "spotify-client-secret",
    description: "Spotify Client Secret",
    regex: /(?:spotify[_.-]?client[_.-]?secret)["']?\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
    fullMatch: false,
    keywords: ["spotify"],
    severity: "medium",
  },

  // ------------------------------------------------------------ Keys / crypto / generic
  {
    id: "private-key-block",
    description: "Private Key Block (PEM)",
    regex:
      /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{50,}?-----END \1?PRIVATE KEY(?: BLOCK)?-----/g,
    fullMatch: true,
    keywords: ["PRIVATE KEY"],
    severity: "critical",
  },
  {
    id: "putty-private-key",
    description: "PuTTY Private Key",
    regex: /PuTTY-User-Key-File-\d[\s\S]{50,}?Private-MAC:/g,
    fullMatch: true,
    keywords: ["PuTTY-User-Key-File"],
    severity: "critical",
  },
  {
    id: "jwt",
    description: "JSON Web Token",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    fullMatch: true,
    keywords: ["eyJ"],
    severity: "high",
  },
  {
    id: "bcrypt-hash",
    description: "bcrypt password hash",
    regex: /\$2[aby]?\$\d{2}\$[A-Za-z0-9./]{53}/g,
    fullMatch: true,
    keywords: ["$2a$", "$2b$", "$2y$"],
    severity: "medium",
  },
  {
    id: "generic-api-key-assignment",
    generic: true,
    fingerprintStrategy: "keyword",
    description: "Generic API key / secret assignment",
    regex:
      /(?:api[_.-]?key|apikey|secret[_.-]?key|access[_.-]?token|auth[_.-]?token|client[_.-]?secret|private[_.-]?key|passwd|password)["']?\s*[:=]\s*["']([A-Za-z0-9_\-/+=.]{16,})["']/gi,
    fullMatch: false,
    keywords: ["key", "secret", "token", "password", "passwd"],
    entropy: 3.5,
    allowlist: [
      /^(?:process\.env|os\.environ|ENV|System\.getenv)/,
      // No /^\$\{?[A-Za-z_]/ here: that guard was generalised into
      // isPlaceholder, which runs for every rule before any allowlist. It is not
      // missing — it covers this rule and the three whose captures accept
      // arbitrary text, which is where the same false positive was still
      // getting through.
      /^(?:true|false|null|undefined|none)$/i,
      ...DOC_SAMPLE,
    ],
    severity: "high",
  },
];

/** Case-insensitive placeholder values that should never be flagged, whatever the rule. */
export const placeholderDenylist = new Set([
  "your_api_key_here",
  "changeme",
  "example",
  "xxxxxxxxxxxxxxxx",
  "insert_key_here",
  "<api_key>",
  "test",
  "placeholder",
  "your-api-key",
  "my-secret-key",
  "dummy",
  "redacted",
  "none",
  "null",
  "undefined",
]);

/** Paths never worth scanning: generated, vendored, or lock-step files. */
export const defaultExcludePaths = [
  "**/node_modules/**",
  "**/vendor/**",
  "**/dist/**",
  "**/build/**",
  "**/out/**",
  "**/.git/**",
  "**/*.min.js",
  "**/*.min.css",
  "**/*.map",
  "**/package-lock.json",
  "**/yarn.lock",
  "**/pnpm-lock.yaml",
  "**/poetry.lock",
  "**/Gemfile.lock",
  "**/Cargo.lock",
  "**/go.sum",
  "**/composer.lock",
];

export const rulesById = new Map(rules.map((r) => [r.id, r]));

/** Rule ids that match by shape and therefore yield to a named rule on overlap. */
export const genericRuleIds = new Set(rules.filter((r) => r.generic).map((r) => r.id));
