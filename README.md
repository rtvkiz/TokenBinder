# Token Binder - Burp Suite Extension

> Automatically extract and inject authentication tokens in Burp Suite using the Montoya API

## 🚀 Quick Start

```bash
# 1. Set Java 21
export JAVA_HOME=/path/to/java21

# 2. Build
./gradlew clean jar

# 3. Load in Burp Suite
# Extensions → Installed → Add → build/libs/TokenBinder.jar

# 4. Configure and use!
```

## 📋 Overview

**Token Binder** is a powerful Burp Suite extension that streamlines authentication token management during API security testing. It:

- ✅ Automatically extracts tokens from API responses
- ✅ Automatically injects tokens into subsequent requests
- ✅ Supports multiple extraction methods (JSONPath & Regex)
- ✅ Supports multiple injection points (Headers, Query Params, JSON/Form Body)
- ✅ Provides interactive configuration UI
- ✅ Works seamlessly with Burp Repeater
- ✅ Logs all operations for debugging

## 🎯 Use Cases

### OAuth2 API Testing
Extract access tokens from `/oauth/token` endpoint and inject into API requests:
- **Source**: `api.example.com/oauth/token`
- **Target**: `api.example.com/api/*`
- **Token Format**: `Bearer {token}` (Header)

### REST API with Session Tokens
Test REST APIs that use session tokens:
- **Source**: `/login` endpoint
- **Target**: `/api/resources` endpoints
- **Token Format**: `session_id={token}` (JSON Body)

### API Key Authentication
Manage API keys programmatically:
- **Source**: `/authenticate`
- **Target**: `/api/v1/*`
- **Injection**: Query Parameter `api_key`

## 🔧 Installation

### Prerequisites
- **Java 21+** (required by Montoya API)
- **Burp Suite 2024.x or later**
- **Gradle** (bundled with project)

### Build Steps

1. **Verify Java 21 is active:**
   ```bash
   java -version
   # Should show: openjdk version "21.x.x"
   ```

2. **Build the extension:**
   ```bash
   cd /path/to/ExtensionTemplateProject
   ./gradlew clean jar
   ```

3. **Output:**
   ```
   build/libs/token-binder.jar  (approximately 50KB)
   ```

### Load into Burp Suite

1. Open **Burp Suite**
2. Navigate to: `Extensions → Installed`
3. Click **Add**
4. Select: `build/libs/token-binder.jar`
5. Click **Next** and confirm

**Verification:**
- "Token Binder" tab appears in main interface
- Logs show: `[Token Binder] extension loaded successfully!`

## ⚙️ Configuration

### Configuration Panel

The extension adds a "Token Binder" tab with the following fields:

| Field | Purpose | Example |
|-------|---------|---------|
| **Source Tab** | URL pattern for token-generating endpoint | `/auth`, `api.example.com/login` |
| **Target Tab** | URL pattern for endpoints using the token | `/api`, `api.example.com/v1` |
| **Token Path** | JSONPath or Regex to extract token | `$.access_token` or `"token":"([^"]+)"` |
| **Injection Location** | Where to place the token | Header / Query / Body JSON / Body Form |
| **Injection Key** | Name of header/param/field | `Authorization` / `api_key` / `token` |
| **Token Format** | Template for token value | `Bearer {token}` / `{token}` |

### Configuration Examples

#### Example 1: OAuth2 Bearer Token

```
Source Tab:          api.example.com/oauth/token
Target Tab:          api.example.com/api
Token Path:          $.access_token
Injection Location:  Header
Injection Key:       Authorization
Token Format:        Bearer {token}
```

#### Example 2: Custom Header with Regex

```
Source Tab:          /authenticate
Target Tab:          /api/user
Token Path:          "token"\s*:\s*"([^"]+)"
Injection Location:  Header
Injection Key:       X-Auth-Token
Token Format:        {token}
```

#### Example 3: Query Parameter

```
Source Tab:          api.example.com/v1/auth
Target Tab:          api.example.com/v1/resources
Token Path:          $.api_key
Injection Location:  Query Parameter
Injection Key:       key
Token Format:        {token}
```

### How to Configure

1. Click the **Token Binder** tab in Burp Suite
2. Fill in all fields with appropriate values
3. Click **Apply Configuration**
4. Confirm success message
5. Tokens will be extracted/injected automatically from now on

## 🔄 Usage Workflow

### Step 1: Extract Token

1. Open **Burp Repeater**
2. Create a request to your **Source Tab** URL (authentication endpoint)
3. Send the request
4. Extension extracts token automatically
5. Check logs: `[Token Binder] Token extracted: xxxx...`

### Step 2: Inject Token

1. Create a new request to your **Target Tab** URL
2. Send the request (from Repeater only)
3. Extension injects the token automatically
4. Check logs: `[Token Binder] Token injected`

### Step 3: Manage Tokens

**Clear Token:** Click "Clear Token" button to manually clear stored token

**Refresh Status:** Click "Refresh Token Status" to see current token (masked)

**View Logs:** Check "Extension Load" console for detailed operation logs

## 🛠️ Advanced Features

### Token Extraction Methods

**JSONPath (for structured JSON responses):**
- Path format: `$.field_name` or `$.nested.field`
- Example: `$.data.access_token` extracts from `{"data": {"access_token": "xyz"}}`

**Regex (for unstructured or complex responses):**
- Pattern must include capture group: `(...)`
- Example: `"token"\s*:\s*"([^"]+)"` extracts from `"token": "xyz"`

### Token Injection Locations

1. **Header** - Injects as HTTP header
   - Example: `Authorization: Bearer {token}`

2. **Query Parameter** - Adds URL query parameter
   - Example: `https://api.example.com/endpoint?api_key={token}`

3. **Body (JSON)** - Adds JSON field
   - Example: `{"user": "john", "token": "xyz"}`

4. **Body (Form)** - Adds form parameter
   - Example: `user=john&token=xyz`

### Logging and Debugging

The extension logs all operations to Burp's **Extension Load** console:

```
[Token Binder] extension loaded successfully!
[Token Binder] Configuration updated:
  Source Tab: api.example.com/oauth
  Target Tab: api.example.com/api
  Token Path: $.access_token
  Injection: header -> Authorization
[Token Binder] Token extracted: xxxx...
[Token Binder] Token injected into target request: HEADER -> Authorization
```

## 🐛 Troubleshooting

### Build Issues

**Error: `25.0.1` IllegalArgumentException**
```bash
# Solution: Set correct Java version
export JAVA_HOME=/path/to/java21
./gradlew clean jar
```

**Error: `Could not find montoya-api`**
```bash
# Solution: Clear Gradle cache
rm -rf ~/.gradle/caches
./gradlew clean jar
```

### Runtime Issues

**Token not extracting:**
- Verify Source Tab URL pattern matches your endpoint
- Check Token Path format (JSONPath vs Regex)
- Inspect actual response to confirm token location
- Check logs for extraction errors

**Token not injecting:**
- Verify Target Tab URL pattern is correct
- Confirm requests come from Repeater tool
- Check Injection Location matches request format
- Verify Injection Key name is correct

**Extension not loading:**
- Verify Java 21: `java -version`
- Check JAR exists: `ls build/libs/token-binder.jar`
- Review Burp's Extension Load console for errors
- Try reloading: Disable/Enable extension in Burp

## 📁 Project Structure

```
ExtensionTemplateProject/
├── src/main/java/
│   └── Extension.java           # Main extension implementation
├── build.gradle.kts             # Gradle build configuration
├── settings.gradle.kts          # Gradle settings
├── gradlew                       # Gradle wrapper (Linux/Mac)
├── gradlew.bat                  # Gradle wrapper (Windows)
├── README.md                    # This file
└── DEPLOYMENT.md                # Detailed deployment guide
```

## 🔐 Security

- **Token Masking**: Tokens are masked in logs (first 4 and last 4 chars shown)
- **In-Memory Only**: Tokens stored only in memory, not persisted
- **Repeater Only**: Extension only processes requests from Repeater tool
- **Manual Clear**: Tokens can be manually cleared via UI

## 📚 Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Comprehensive deployment guide with troubleshooting
- **[Montoya API Docs](https://portswigger.github.io/burp-extensions-montoya-api/)** - Official API documentation
- **[Burp Extension Guide](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions)** - Burp extension development

## 🔧 Technologies

- **Language**: Java 21
- **API**: Burp Montoya API (Burp Suite 2024+)
- **Build Tool**: Gradle 8.x
- **UI Framework**: Java Swing
- **Pattern Matching**: Java Regex + JSONPath

## 📝 License

This extension follows PortSwigger's extension licensing terms. See Burp Suite documentation for details.

## 🤝 Contributing

To extend or modify this extension:

1. Edit `src/main/java/Extension.java`
2. Implement new extraction/injection methods
3. Build: `./gradlew clean jar`
4. Test in Burp Suite
5. Follow Burp extension best practices

## ❓ FAQ

**Q: Can I use this with Burp Community Edition?**
A: Yes! Montoya API works with both Community and Professional editions.

**Q: Does it work with other Burp tools besides Repeater?**
A: Currently optimized for Repeater. Can be extended for Scanner, Intruder, etc.

**Q: Can I change configuration mid-session?**
A: Yes! Apply new configuration anytime. Previous token will be cleared.

**Q: Is my token secure?**
A: Tokens are in-memory only, masked in logs, and cleared on command. Use at your discretion.

---

**Version**: 1.0  
**Last Updated**: 2025  
**Requires**: Java 21+ | Burp Suite 2024+