# Mediated Vault Access

This context defines how a cooperative AI agent discovers Bitwarden items and performs one-shot credentialed commands while a local broker withholds master passwords, vault session keys, and vault material from model context.

## Language

**Vault Broker**:
An on-demand local process shared by Pi sessions that owns Keychain access, Bitwarden CLI state, vault sessions, metadata derivation, and credentialed process execution.
_Avoid_: OS sandbox, privileged broker

**Secure Prompt**:
A hidden Pi TUI input owned by the extension whose value is sent only to the Vault Broker and is neither returned to the model nor stored in the conversation.
_Avoid_: Agent prompt, broker prompt

**Stored Unlock Credential**:
The Bitwarden master password retained in the macOS login Keychain for unattended retrieval while that Keychain is unlocked.
_Avoid_: Vault Session, cached password

**Vault Authentication**:
An email and master-password flow that signs the Bitwarden CLI into an account using the Stored Unlock Credential.
_Avoid_: Vault Unlock, CLI setup

**Vault Unlock**:
An operation that decrypts an authenticated Bitwarden vault using the Stored Unlock Credential.
_Avoid_: Vault Authentication, secret access

**Vault Session**:
The in-memory Bitwarden session key held privately by the Vault Broker for up to 15 minutes of approved activity.
_Avoid_: Login session, environment session

**Safe Metadata**:
An allowlisted item description containing item and material handles, item type, favorite flag, title, folder name, normalized web origins, field labels and types, attachment filename, MIME type and byte size, delivery support, and presence or count flags.
_Avoid_: Redacted item, item data

**Vault Material**:
Any non-metadata vault content, including scalar fields, TOTP data, notes, SSH keys, and attachment bytes.
_Avoid_: Item data, value

**Vault Material Run**:
A one-shot structured process invocation that receives selected Vault Material only through temporary environment variables and stdin.
_Avoid_: Password retrieval, secret access, Secret-Bearing Run

**Sanitized Output**:
Captured text-process output from which injected Vault Material and its common JSON, URL, base64, base64url, and hexadecimal encodings have been removed before it reaches the model.
_Avoid_: Safe output, raw output

**Raw Secret**:
A master password, Vault Session, or Vault Material.
_Avoid_: Value, sensitive data

## Relationships

- Multiple Pi sessions may share one **Vault Broker**
- A **Vault Broker** starts on demand and exits after 30 minutes without requesting clients
- One or more concurrent **Secure Prompts** may open; the first valid authentication response wins and later responses are discarded
- A **Secure Prompt** captures the master password when no valid **Stored Unlock Credential** exists and sends it only to the **Vault Broker**
- The **Stored Unlock Credential** is retrieved unattended by the **Vault Broker** while the login Keychain is unlocked
- **Vault Authentication** and **Vault Unlock** use the **Stored Unlock Credential** without entering model context
- Successful **Vault Authentication** or **Vault Unlock** creates a **Vault Session**
- Approved activity renews the **Vault Session** for up to 15 minutes of inactivity
- Each **Vault Session** assigns temporary opaque handles invalidated on lock or logout
- A **Vault Session** may return 100-item pages of **Safe Metadata** for all vault items; material descriptors are inspected on demand
- A **Vault Material Run** may inject any number of scalar text values through distinct environment variables and at most one arbitrary payload through stdin
- A **Vault Material Run** never writes decrypted Vault Material to a file
- A text-only **Vault Material Run** returns only **Sanitized Output**
- A **Vault Material Run** with bulk or binary stdin suppresses stdout and stderr and returns only execution metadata
- Neither the extension nor **Vault Broker** adds the **Vault Session** or **Vault Material** to Pi's process environment, tool arguments, tool results, transcript, logs, argv, or temporary files

## Example dialogue

> **Dev:** "Can the agent retrieve the GitHub password or SSH key?"
> **Domain expert:** "No. It can select either using **Safe Metadata** and request a **Vault Material Run**; the child process receives the selected **Vault Material**, while the agent receives only **Sanitized Output** or execution metadata."

## Flagged ambiguities

- "login" could mean Bitwarden CLI authentication, vault decryption, or using a stored login — resolved: **Vault Authentication** handles an unauthenticated CLI and **Vault Unlock** handles a locked CLI.
- "access the items" could mean reading raw fields or using stored content — resolved: the agent may enumerate **Safe Metadata** and inject any selected item content through a **Vault Material Run**, but may not retrieve raw item content.
- "stored for a long time" means the master password, not item passwords or `BW_SESSION` — resolved: it is an unattended **Stored Unlock Credential** in the macOS login Keychain.
- "never shown to the agent" is a cooperative-agent guarantee at the extension interface, not an OS security boundary — resolved: deliberate host-process or Keychain inspection, direct CLI authentication, UI phishing, arbitrary secret transformations, and command-driven exfiltration are out of scope.
- Human-authored metadata can contain misplaced secrets — resolved: the guarantee is structural, and titles, field labels, and attachment filenames are user-approved metadata that must not contain secrets.
- Bitwarden native search may match hidden values and therefore acts as a membership oracle — resolved: this side channel is accepted under the cooperative-agent model.
