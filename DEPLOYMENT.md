# Token Binder - Burp Suite Extension Deployment Guide

## Overview

**Token Binder** is a Burp Suite extension that automatically extracts authentication tokens from API responses and injects them into subsequent requests. It's built using the **Montoya API** (Burp Suite 2024+) and supports multiple injection methods.

### Features
- ✅ Automatic token extraction from JSON responses (JSONPath) or regex patterns
- ✅ Multiple injection methods (Headers, Query Parameters, JSON Body, Form Body)
- ✅ Flexible URL pattern matching for tab identification
- ✅ Interactive UI for configuration
- ✅ Token masking for security in logs
- ✅ Works with Burp Suite Repeater tool

---

## Prerequisites

1. **Java 21** installed and available
   - Download from: https://adoptium.net/ or use Homebrew
   - Set `JAVA_HOME` environment variable

2. **Burp Suite 2024.x or later** (Community, Professional, or Paid)
   - The Montoya API is required

3. **Gradle** (included in the project via `gradlew`)

---

## Build Instructions

### Step 1: Set Java 21 as Active

```bash
# Linux/Mac
export JAVA_HOME=/path/to/java21
export PATH=$JAVA_HOME/bin:$PATH

# Verify
java -version
```

If using Homebrew on Mac/Linux:
```bash
export JAVA_HOME=$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home
```

### Step 2: Build the Extension

Navigate to the project directory and build:

```bash
cd /home/rtvkiz/Research/ExtensionTemplateProject
./gradlew clean jar
```

**Expected Output:**
```
BUILD SUCCESSFUL in Xs
```

The compiled JAR will be in:
```
build/libs/TokenBinder.jar
```

### Step 3: Verify Build Output

```bash
ls -lh build/libs/TokenBinder.jar
```

---

## Installation in Burp Suite

### Method 1: Load Extension from Burp UI (Recommended)

1. **Open Burp Suite**
   - Launch Burp Suite (Community or Professional)

2. **Navigate to Extensions**
   - Click: `Extensions` → `Installed` → `Add`

3. **Select the JAR File**
   - Choose: `build/libs/TokenBinder.jar`

4. **Extension Loaded**
   - Burp will load the extension
   - You should see "Token Binder" tab appear in the Burp interface
   - Check the "Extension Load" console for confirmation messages

### Method 2: Command-line Installation (Alternative)

If using Burp Suite command-line mode:

```bash
burpsuite --project-file=myproject.burp \
  --load-extension=build/libs/TokenBinder.jar
```

---

## Configuration

Once the extension is loaded, follow these steps:

### 1. Open Token Binder Tab

- Find the **"Token Binder"** tab in Burp Suite's main interface
- It will display the configuration panel

### 2. Configure Settings

Fill in the configuration fields:

| Field | Description | Example |
|-------|-------------|---------|
| **Source Tab (Token Generator)** | URL pattern of the endpoint that returns the token | `api.example.com/auth` or `/login` |
| **Target Tab (Token Consumer)** | URL pattern of the endpoint that needs the token | `api.example.com/api` or `/data` |
| **Token Path** | JSONPath (starting with `$.`) or regex pattern | `$.access_token` or `"token":"([^"]+)"` |
| **Injection Location** | Where to inject the token | Header / Query Parameter / Body (JSON) / Body (Form) |
| **Injection Key** | Header name or parameter name | `Authorization` / `token` / `api_key` |
| **Token Format** | Template for formatting the token | `Bearer {token}` or `{token}` |

### 3. Example Configurations

#### Example 1: OAuth2 Bearer Token (Header)
```
Source Tab:        api.example.com/oauth/token
Target Tab:        api.example.com/api
Token Path:        $.access_token
Injection Location: Header
Injection Key:     Authorization
Token Format:      Bearer {token}
```

#### Example 2: API Key in Query Parameter
```
Source Tab:        api.example.com/v1/auth
Target Tab:        api.example.com/v1/resource
Token Path:        "token":"([^"]+)"
Injection Location: Query Parameter
Injection Key:     api_key
Token Format:      {token}
```

#### Example 3: Token in JSON Body
```
Source Tab:        /login
Target Tab:        /api/user
Token Path:        $.sessionToken
Injection Location: Body (JSON)
Injection Key:     session_id
Token Format:      {token}
```

### 4. Apply Configuration

Click **"Apply Configuration"** button to save settings.

You should see a success message in the Burp logs and the "Extension Load" console.

---

## Usage Workflow

### Step 1: Authenticate (Extract Token)

1. Open Burp Suite **Repeater** tool
2. Create a request to the **Source Tab** URL (token generation endpoint)
3. Send the request
4. The Token Binder extension will automatically extract the token from the response
5. Check the extension's UI tab or Burp logs for confirmation: `[Token Binder] Token extracted: xxxxxxxx...`

### Step 2: Use Token (Inject Token)

1. In Burp **Repeater**, create a new request to the **Target Tab** URL
2. Send the request
3. The Token Binder will automatically inject the extracted token
4. Check Burp logs for: `[Token Binder] Token injected into target request`
5. The request will use the injected token for authentication

### Step 3: Manual Token Management

- **Clear Token**: Click "Clear Token" button to manually clear the stored token
- **Refresh Status**: Click "Refresh Token Status" to see current token (masked)
- **View Logs**: Check Burp's "Extension Load" console for detailed operation logs

---

## Troubleshooting

### Issue: Extension not loading

**Symptom:** JAR file doesn't appear in Burp's Extensions list

**Solution:**
1. Verify Java version: `java -version` (should be 21 or higher)
2. Ensure JAR was built successfully: `ls build/libs/TokenBinder.jar`
3. Check Burp's "Extension Load" tab for error messages
4. Try rebuilding: `./gradlew clean jar`

### Issue: Token not extracting

**Symptom:** "No token extracted yet" message persists

**Solution:**
1. Verify the **Source Tab** URL pattern matches your token endpoint
2. Check the **Token Path** format:
   - For JSON: `$.field_name` (e.g., `$.access_token`)
   - For regex: `"field":"([^"]+)"` (capture group required)
3. Inspect response manually to confirm token location
4. Check Burp logs for extraction errors: `[Token Binder] JSON extraction error` or `Regex extraction error`

### Issue: Token not injecting

**Symptom:** Token is extracted but not injected into target requests

**Solution:**
1. Verify the **Target Tab** URL pattern is correct
2. Confirm **Injection Location** is appropriate (headers vs body vs params)
3. Check that requests are sent from the **Repeater** tool
4. Verify the target request goes through the configured target tab URL
5. Check Burp logs for injection errors

### Issue: Build fails with Java version error

**Symptom:** `java.lang.IllegalArgumentException: 25.0.1`

**Solution:**
```bash
export JAVA_HOME=/path/to/java21
java -version  # Should show Java 21
./gradlew clean jar
```

### Issue: Montoya API not found

**Symptom:** `Could not find net.portswigger.burp.extensions:montoya-api`

**Solution:**
1. Ensure you have internet access (Maven Central required)
2. Clear Gradle cache: `rm -rf ~/.gradle/caches`
3. Retry build: `./gradlew clean jar`

---

## Advanced Configuration

### Custom Regex Patterns

For complex token extraction, use regex patterns:

```
Token Path: "access_token"\s*:\s*"([^"]+)"
```

The pattern MUST contain a capture group `()` to extract the token.

### Multiple Token Formats

The **Token Format** field supports:
- `Bearer {token}` - OAuth2 style
- `Token {token}` - Token auth style
- `{token}` - Plain token
- `X-API-Key: {token}` - Custom format (for custom headers)

### Disabling Extension

To temporarily disable the extension without uninstalling:
1. Go to `Extensions` → `Installed`
2. Uncheck the **Token Binder** extension checkbox
3. Click to re-enable when needed

---

## Security Considerations

1. **Token Masking**: Tokens are masked in logs (shows only first 4 and last 4 characters)
2. **In-Memory Storage**: Tokens are stored in memory only, not persisted to disk
3. **Burp Suite Scope**: Extension only processes requests from the **Repeater** tool
4. **Clear Token**: Manually clear tokens when done with sensitive operations

---

## Support & Documentation

- **Montoya API Docs**: https://portswigger.github.io/burp-extensions-montoya-api/
- **Burp Extension Guide**: https://portswigger.net/burp/documentation/desktop/extend-burp/extensions
- **GitHub Issues**: Report bugs or feature requests

---

## Version Information

- **Extension Name**: Token Binder
- **API**: Montoya API (Burp 2024+)
- **Java**: 21 (minimum)
- **License**: PortSwigger Extension License

---

## Quick Reference: Common URL Patterns

```
OAuth2 Login:     /oauth/token, /auth/token, /api/auth
REST API Login:   /login, /api/login, /v1/auth
Token Endpoint:   /token, /authenticate, /sessions
API Endpoints:    /api, /v1/resources, /data
```

---

**Last Updated**: 2025
**Author**: Token Binder Extension Team
