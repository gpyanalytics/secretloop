/**
 * Synthetic, non-functional credentials shaped like the real thing. These are
 * randomly generated at module load from a fixed seed so no real secret ever
 * lands in this repo, and so the corpus can't accidentally be a live key.
 */
let seed = 1337;
function rand(): number {
  // xorshift32 — deterministic, no dependency.
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return Math.abs(seed) / 2 ** 31;
}
const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const HEX = "0123456789abcdef";
const UPPER_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const LOWER_NUM = "abcdefghijklmnopqrstuvwxyz0123456789";

function gen(n: number, alphabet = ALNUM): string {
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[Math.floor(rand() * alphabet.length)];
  return out;
}
const hex = (n: number) => gen(n, HEX);
const uuid = () => `${hex(8)}-${hex(4)}-${hex(4)}-${hex(4)}-${hex(12)}`;

/** ruleId -> a snippet that rule must flag. */
export const positiveSamples: Record<string, string> = {
  // A visibly-fake sentinel rather than a gen()-produced value, which is the
  // one place in this corpus where generating would be wrong. An AWS key ID is
  // AKIA plus 16 uppercase alphanumerics with no separator, so a generated one
  // is indistinguishable from a planted credential to anyone reading the file
  // or grepping the repository -- and a secret scanner whose own fixtures read
  // like live AWS keys invites exactly the report it exists to prevent.
  //
  // The run of X's is load-bearing in both directions: it has to still match
  // aws-access-key, and it must NOT be on DOC_SAMPLE or any rule allowlist, or
  // the fixture would prove the rule declines a value rather than finds one --
  // which is what happened to AKIAIOSFODNN7EXAMPLE and why the note below
  // exists. AKIAEXAMPLE... cannot be used for the same reason: DOC_SAMPLE
  // matches /EXAMPLE/i. tests/rules.test.ts pins both halves.
  "aws-access-key": "AKIAXXXXXXXXXXXXXXXX",
  // Generated, not AWS's published example. The doc sample used to sit here and
  // stopped working as a positive fixture the moment DOC_SAMPLE learned to
  // recognise it -- a rule that correctly declines a value cannot also be
  // proven by it. The negative case has its own test.
  "aws-secret-key": `aws_secret_access_key = "${gen(40, ALNUM + "+/")}"`,
  "aws-session-token": `aws_session_token="${gen(140)}"`,
  "google-api-key": "AIzaSyD" + gen(32),
  "gcp-service-account-key": `"private_key_id": "${hex(40)}"`,
  "gcp-oauth-client-secret": "GOCSPX-" + gen(28),
  "firebase-cloud-messaging-key": "AAAA" + gen(7) + ":APA91b" + gen(140),
  "azure-storage-account-key": "AccountKey=" + gen(86) + "==",
  "azure-ad-client-secret": "aB78Q~" + gen(33),
  "azure-sas-token": "sig=" + gen(45) + "&se=2026",
  "github-token": "ghp_" + gen(36),
  "github-oauth-token": "gho_" + gen(36),
  "github-app-token": "ghs_" + gen(36),
  "github-refresh-token": "ghr_" + gen(40),
  "github-fine-grained-pat": "github_pat_" + gen(22) + "_" + gen(50),
  "gitlab-pat": "glpat-" + gen(20),
  "gitlab-runner-token": "glrt-" + gen(20),
  "gitlab-pipeline-trigger": "glptt-" + gen(20),
  "gitlab-deploy-token": "gldt-" + gen(20),
  "atlassian-api-token": "ATATT3x" + gen(110),
  "bitbucket-app-password": "ATBB" + gen(34),
  "stripe-secret-key": "sk_live_" + gen(30),
  "stripe-webhook-secret": "whsec_" + gen(34),
  "shopify-token": "shpat_" + hex(32),
  "square-access-token": "sq0atp-" + gen(22),
  "square-oauth-secret": "sq0csp-" + gen(43),
  "razorpay-key": "rzp_live_" + gen(14),
  "paypal-braintree-token": "access_token$production$" + gen(16, LOWER_NUM) + "$" + hex(32),
  "plaid-secret": `plaid_secret = "${hex(30)}"`,
  "openai-api-key": "sk-proj-" + gen(64),
  // sk-or- is the documented OpenRouter prefix; the hex tail matches the shape
  // its own docs show. Also the anti-regression fixture for the OpenAI
  // carve-out -- if /^sk-or-/ ever leaves openai-api-key's allowlist, the
  // corpus overlap guard fails on this value.
  "openrouter-api-key": "sk-or-v1-" + hex(64),
  "anthropic-api-key": "sk-ant-api03-" + gen(95),
  "huggingface-token": "hf_" + gen(36),
  "replicate-token": "r8_" + gen(38),
  "groq-api-key": "gsk_" + gen(52),
  "perplexity-api-key": "pplx-" + gen(36),
  "langsmith-api-key": "lsv2_pt_" + hex(32) + "_" + hex(10),
  "slack-token": "xoxb-" + gen(12, "0123456789") + "-" + gen(24),
  "slack-app-config-token": "xapp-1-" + gen(30),
  "slack-webhook": "https://hooks.slack.com/services/" + gen(45),
  // The rule carries a `discord` keyword prescreen, so the fixture must
  // contain it — same convention as the twilio/ngrok/asana fixtures.
  "discord-bot-token": `const discordToken = "M${gen(24)}.${gen(6)}.${gen(30)}";`,
  "discord-webhook": "https://discord.com/api/webhooks/" + gen(18, "0123456789") + "/" + gen(70),
  "telegram-bot-token": gen(9, "123456789") + ":AA" + gen(33),
  "twilio-api-key": "twilio SK" + hex(32),
  "twilio-auth-token": `twilio_auth_token="${hex(32)}"`,
  "sendgrid-api-key": "SG." + gen(22) + "." + gen(43),
  "mailgun-api-key": "key-" + hex(32),
  "mailchimp-api-key": hex(32) + "-us14",
  "postmark-server-token": `postmark_server_token="${uuid()}"`,
  "npm-token": "npm_" + gen(36),
  "pypi-token": "pypi-AgEIcHlwaS5vcmc" + gen(60),
  "rubygems-token": "rubygems_" + hex(48),
  "dockerhub-pat": "dckr_pat_" + gen(30),
  "jfrog-token": "AKCp" + gen(65),
  "nuget-api-key": "oy2" + gen(43, LOWER_NUM),
  "digitalocean-token": "dop_v1_" + hex(64),
  "heroku-api-key": `heroku_api_key="${uuid()}"`,
  "cloudflare-api-token": `cloudflare_api_token = "${gen(40)}"`,
  "cloudflare-origin-ca-key": "v1.0-" + gen(24) + "-" + gen(146),
  "flyio-token": "fm2_" + gen(50),
  "vercel-token": `vercel_token="${gen(24)}"`,
  "netlify-token": `netlify_auth_token="${gen(44)}"`,
  "ngrok-authtoken": "ngrok authtoken 2" + gen(19) + "_" + gen(24),
  "terraform-cloud-token": gen(14) + ".atlasv1." + gen(65),
  "hashicorp-vault-token": "hvs." + gen(60),
  "doppler-token": "dp.st." + gen(45),
  "onepassword-service-account": "ops_" + gen(50),
  "db-connection-string": "postgres://appuser:" + gen(18) + "@db.internal:5432/prod",
  "http-basic-auth-url": "https://svc:" + gen(20) + "@api.internal/v1",
  "snowflake-credentials": `snowflake_password = "${gen(20)}"`,
  "databricks-token": "dapi" + hex(32),
  "supabase-service-key": "sbp_" + hex(40),
  "planetscale-token": "pscale_tkn_" + gen(40),
  "datadog-api-key": `datadog_api_key="${hex(32)}"`,
  "newrelic-key": "NRAK-" + gen(27, UPPER_NUM),
  "sentry-auth-token": "sntrys_" + gen(50),
  "grafana-token": "glsa_" + gen(32) + "_" + hex(8),
  "sonarqube-token": "squ_" + hex(40),
  "codecov-token": `codecov_token="${uuid()}"`,
  "buildkite-token": `buildkite_agent_token="${gen(45)}"`,
  "circleci-token": `CIRCLE_TOKEN="${hex(40)}"`,
  "launchdarkly-key": "api-" + uuid(),
  "notion-token": "secret_" + gen(43),
  "linear-api-key": "lin_api_" + gen(40),
  "figma-token": "figd_" + gen(45),
  "airtable-token": "pat" + gen(14) + "." + hex(64),
  "asana-token": "asana 1/" + gen(16, "0123456789") + ":" + gen(32),
  "dropbox-token": "sl." + gen(140),
  "algolia-admin-key": `algolia_admin_api_key="${hex(32)}"`,
  "intercom-token": "dG9r" + gen(60),
  "contentful-token": "CFPAT-" + gen(43),
  "okta-api-token": `okta_api_token="00${gen(40)}"`,
  "auth0-client-secret": `auth0_client_secret="${gen(48)}"`,
  "pusher-secret": `pusher_app_secret="${hex(20)}"`,
  "segment-write-key": `segment_write_key="${gen(32)}"`,
  "facebook-access-token": "EAA" + gen(95),
  "twitter-bearer-token": "AAAAAAAAAAAAAAAAAAAAA" + gen(60),
  "twitch-client-secret": `twitch_client_secret="${gen(30, LOWER_NUM)}"`,
  "spotify-client-secret": `spotify_client_secret="${hex(32)}"`,
  "private-key-block":
    "-----BEGIN RSA PRIVATE KEY-----\n" + gen(120) + "\n-----END RSA PRIVATE KEY-----",
  "putty-private-key": "PuTTY-User-Key-File-2: ssh-rsa\n" + gen(80) + "\nPrivate-MAC:",
  "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + gen(30),
  "bcrypt-hash": "$2b$12$" + gen(53, ALNUM + "./"),
  "generic-api-key-assignment": `api_key = "${gen(28)}"`,
};

/** Snippets that must produce zero findings. Each is a real-world FP class. */
export const negativeSamples: { label: string; text: string }[] = [
  { label: "env var reference", text: "const apiKey = process.env.API_KEY;" },
  { label: "placeholder password", text: 'password = "changeme"' },
  { label: "AWS docs sample key", text: "AKIAIOSFODNN7EXAMPLE" },
  { label: "template placeholder", text: 'api_key = "your_api_key_here"' },
  { label: "lockfile integrity hash", text: `"integrity": "sha512-${gen(60)}"` },
  { label: "git commit sha", text: `commit = "${hex(40)}"` },
  { label: "uuid identifier", text: `id = "${uuid()}"` },
  { label: "filesystem path", text: 'const p = "/usr/local/share/some/long/file/name.txt"' },
  { label: "version string", text: 'version = "1.24.3018.20194"' },
  { label: "shell interpolation", text: 'token = "${GITHUB_TOKEN}"' },
  { label: "repeated char", text: 'secret_key = "aaaaaaaaaaaaaaaaaaaaaaaa"' },
  { label: "sha256 digest", text: `checksum = "${hex(64)}"` },
  { label: "data uri", text: 'src = "data:image/png;base64,' + gen(80) + '"' },
];
