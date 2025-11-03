import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Burp Suite Extension: Token Binder
 * 
 * Binds two repeater tabs together:
 * - Source tab: Extracts token from response
 * - Target tab: Injects token into request
 * 
 * Uses Montoya API (Burp Suite 2024+)
 * 
 * NEW FEATURE: Auto-fetch token from source when target request is detected
 */
public class Extension implements BurpExtension, HttpHandler {
    
    private MontoyaApi montoyaApi;
    
    // Configuration
    private String sourceTabPattern = "";
    private String targetTabPattern = "";  // NEW: Support comma-separated patterns
    private java.util.List<String> targetTabPatterns = new java.util.ArrayList<>();  // NEW: Multiple target patterns
    private String tokenPath = "";
    private TokenInjectionLocation injectionLocation = TokenInjectionLocation.HEADER;
    private String injectionKey = "Authorization";
    private String tokenFormat = "Bearer {token}";
    
    // NEW: Repeater tab tracking
    private int sourceRepeaterTabId = -1;      // Tab ID for source request
    private int targetRepeaterTabId = -1;      // Tab ID for target request (deprecated, for backward compatibility)
    private java.util.List<Integer> targetRepeaterTabIds = new java.util.ArrayList<>();  // NEW: Support multiple target tabs
    private boolean useRepeaterTabIds = false; // Flag to use tab IDs instead of patterns
    private Map<Integer, Long> tabRequestTimes = new HashMap<>();  // Track request times by tab
    private HttpRequest sourceRequestTemplate = null;  // NEW: Template source request for auto-fetch
    
    // Token storage
    private String currentToken = null;
    private Map<String, String> tabTokens = new HashMap<>();
    private boolean autoFetchEnabled = true;  // NEW: Auto-fetch feature flag
    private long lastTokenFetchTime = 0;      // NEW: Track when token was fetched
    private static final long TOKEN_REUSE_TIMEOUT = 5000; // 5 seconds - reuse token within this window
    private HttpRequest lastSourceRequest = null;  // NEW: Store last request to source for auto-fetch
    
    // UI Components
    private TokenBinderConfigPanel configPanel;
    
    private enum TokenInjectionLocation {
        HEADER,
        QUERY_PARAM,
        BODY_JSON,
        BODY_FORM
    }
    
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        
        montoyaApi.extension().setName("Token Binder");
        
        // Register HTTP handler
        montoyaApi.http().registerHttpHandler(this);
        
        // Create and register UI tab
        configPanel = new TokenBinderConfigPanel(this);
        montoyaApi.userInterface().registerSuiteTab("Token Binder", configPanel);
        
        montoyaApi.logging().logToOutput("Token Binder extension loaded successfully!");
        montoyaApi.logging().logToOutput("Configure source/target tabs and token path in the 'Token Binder' tab.");
        montoyaApi.logging().logToOutput("[Token Binder] Auto-fetch enabled: When you access a target request, the extension will automatically fetch a fresh token from the source!");
    }
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Only process requests from Repeater
        if (!requestToBeSent.toolSource().isFromTool(ToolType.REPEATER)) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        
        String url = requestToBeSent.url();
        long currentTime = System.currentTimeMillis();
        
        // In Tab ID mode: track which tab sent this request
        if (useRepeaterTabIds) {
            montoyaApi.logging().logToOutput("[Token Binder] Request from Repeater to: " + url);
            
            // In Tab ID mode: Always send source request first to get fresh token
            if (sourceRequestTemplate != null && autoFetchEnabled) {
                // Auto-fetch fresh token from source
                montoyaApi.logging().logToOutput("[Token Binder] [TAB ID MODE] Auto-fetching fresh token from source...");
                Thread fetchThread = new Thread(() -> autoFetchTokenFromSourceEndpoint());
                fetchThread.setDaemon(true);
                fetchThread.start();
                
                try {
                    Thread.sleep(2000);  // Wait for token to be fetched
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                
                if (currentToken != null) {
                    montoyaApi.logging().logToOutput("[Token Binder] ✓ Fresh token obtained: " + maskToken(currentToken));
                }
            } else if (sourceRequestTemplate == null) {
                montoyaApi.logging().logToOutput("[Token Binder] [TAB ID MODE] Source template not set. Send source request first to Tab " + sourceRepeaterTabId);
            }
            
            // Now inject the token if we have one
            if (currentToken != null) {
                montoyaApi.logging().logToOutput("[Token Binder] [TAB ID MODE] Injecting fresh token into request...");
                try {
                    HttpRequest modifiedRequest = injectToken(requestToBeSent);
                    if (modifiedRequest != null && modifiedRequest != requestToBeSent) {
                        montoyaApi.logging().logToOutput("[Token Binder] ✓ Token injected: " + 
                            injectionLocation + " -> " + injectionKey);
                        return RequestToBeSentAction.continueWith(modifiedRequest);
                    }
                } catch (Exception e) {
                    montoyaApi.logging().logToError("[Token Binder] Error injecting token: " + e.getMessage());
                }
            }
            
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        
        // Pattern mode logic
        boolean isSourceRequest = (sourceTabPattern != null && !sourceTabPattern.isEmpty() && matchesPattern(url, sourceTabPattern));
        boolean isTargetRequest = false;
        for (String targetPattern : targetTabPatterns) {
            if (targetPattern != null && !targetPattern.isEmpty() && matchesPattern(url, targetPattern)) {
                isTargetRequest = true;
                break;
            }
        }
        
        // In pattern mode: if this is a target request, auto-fetch fresh token first
        if (isTargetRequest && sourceRequestTemplate != null && autoFetchEnabled) {
            montoyaApi.logging().logToOutput("[Token Binder] [PATTERN MODE] Target request detected. Auto-fetching fresh token...");
            Thread fetchThread = new Thread(() -> autoFetchTokenFromSourceEndpoint());
            fetchThread.setDaemon(true);
            fetchThread.start();
            
            try {
                Thread.sleep(2000);  // Wait for token to be fetched
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            if (currentToken != null) {
                montoyaApi.logging().logToOutput("[Token Binder] ✓ Fresh token obtained: " + maskToken(currentToken));
            }
        }
        
        if (currentToken == null) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        
        // Inject token if this is a target request
        boolean shouldInject = false;
        if (useRepeaterTabIds) {
            shouldInject = true; // In Tab ID mode, always inject if we have a token
        } else {
            shouldInject = isTargetRequest;
        }
        
        if (shouldInject) {
            try {
                HttpRequest modifiedRequest = injectToken(requestToBeSent);
                if (modifiedRequest != null && modifiedRequest != requestToBeSent) {
                    montoyaApi.logging().logToOutput("[Token Binder] ✓ Token injected into target request: " + 
                        injectionLocation + " -> " + injectionKey);
                    return RequestToBeSentAction.continueWith(modifiedRequest);
                }
            } catch (Exception e) {
                montoyaApi.logging().logToError("[Token Binder] Error modifying request: " + e.getMessage());
            }
        }
        
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }
    
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Only process responses from Repeater
        if (!responseReceived.toolSource().isFromTool(ToolType.REPEATER)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        
        if (tokenPath == null || tokenPath.isEmpty()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        
        String url = responseReceived.initiatingRequest().url();
        
        // In Tab ID mode: only extract if response contains token
        // In pattern mode: extract if URL matches source pattern
        boolean shouldExtract = false;
        
        if (useRepeaterTabIds) {
            // In Tab ID mode: extract from responses that contain tokens
            montoyaApi.logging().logToOutput("[Token Binder] [TAB ID MODE] Response received from: " + url);
            shouldExtract = true;
        } else {
            // In pattern mode, check source pattern
            if (sourceTabPattern != null && !sourceTabPattern.isEmpty() && matchesPattern(url, sourceTabPattern)) {
                shouldExtract = true;
            }
        }
        
        if (shouldExtract) {
            try {
                // Try to extract token first
                String body = responseReceived.bodyToString();
                if (body != null && !body.isEmpty()) {
                    String token = null;
                    
                    if (tokenPath.startsWith("$.")) {
                        token = extractFromJson(body, tokenPath);
                    } else {
                        token = extractFromRegex(body, tokenPath);
                    }
                    
                    // Only capture as source request if we found a token
                    if (token != null && !token.isEmpty()) {
                        lastSourceRequest = responseReceived.initiatingRequest();
                        sourceRequestTemplate = responseReceived.initiatingRequest();  // NEW: Also save as template
                        montoyaApi.logging().logToOutput("[Token Binder] ✓ Source request captured for auto-fetch: " + url);
                        montoyaApi.logging().logToOutput("[Token Binder] [TAB ID MODE] Source request saved as template for auto-fetch");
                        
                        // Now extract the token properly
                        extractToken(responseReceived);
                    } else if (!useRepeaterTabIds) {
                        // In pattern mode, still extract even if no token found
                        lastSourceRequest = responseReceived.initiatingRequest();
                        montoyaApi.logging().logToOutput("[Token Binder] Source request captured (token extraction may fail): " + url);
                        extractToken(responseReceived);
                    } else {
                        montoyaApi.logging().logToOutput("[Token Binder] [TAB ID MODE] No token found in response from: " + url);
                    }
                }
            } catch (Exception e) {
                montoyaApi.logging().logToError("[Token Binder] Error extracting token: " + e.getMessage());
            }
        }
        
        return ResponseReceivedAction.continueWith(responseReceived);
    }
    
    /**
     * Extract token from response body
     */
    private void extractToken(HttpResponse response) {
        try {
            String body = response.bodyToString();
            if (body == null || body.isEmpty()) {
                montoyaApi.logging().logToOutput("[Token Binder] Response has empty body, cannot extract token");
                return;
            }
            
            String token = null;
            
            // Try JSONPath-like extraction
            if (tokenPath != null && !tokenPath.isEmpty()) {
                if (tokenPath.startsWith("$.")) {
                    token = extractFromJson(body, tokenPath);
                    montoyaApi.logging().logToOutput("[Token Binder] Attempting JSONPath extraction: " + tokenPath);
                } else {
                    // Try regex extraction
                    token = extractFromRegex(body, tokenPath);
                    montoyaApi.logging().logToOutput("[Token Binder] Attempting regex extraction: " + tokenPath);
                }
            }
            
            if (token != null && !token.isEmpty()) {
                currentToken = token;
                lastTokenFetchTime = System.currentTimeMillis();
                montoyaApi.logging().logToOutput("[Token Binder] ✓ Token extracted successfully: " + maskToken(token));
                montoyaApi.logging().logToOutput("[Token Binder] Token is ready to be injected into target endpoints matching: " + targetTabPattern);
                if (configPanel != null) {
                    SwingUtilities.invokeLater(() -> configPanel.updateTokenStatus());
                }
            } else {
                montoyaApi.logging().logToError("[Token Binder] Failed to extract token. Check token path: " + tokenPath);
                montoyaApi.logging().logToError("[Token Binder] Response body preview: " + body.substring(0, Math.min(200, body.length())));
            }
        } catch (Exception e) {
            montoyaApi.logging().logToError("[Token Binder] Error processing response: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Extract from JSON using simple path (e.g., $.token or $.data.token)
     */
    private String extractFromJson(String json, String path) {
        try {
            // Simple JSON path extraction - extract first level key
            String key = path.replace("$.", "").split("\\.")[0];
            Pattern pattern = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]+)\"");
            Matcher matcher = pattern.matcher(json);
            if (matcher.find()) {
                return matcher.group(1);
            }
            
            // Try without quotes (numeric or boolean values)
            pattern = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*([^,}\\s]+)");
            matcher = pattern.matcher(json);
            if (matcher.find()) {
                return matcher.group(1).trim();
            }
        } catch (Exception e) {
            montoyaApi.logging().logToError("[Token Binder] JSON extraction error: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Extract using regex pattern
     */
    private String extractFromRegex(String body, String pattern) {
        try {
            Pattern p = Pattern.compile(pattern);
            Matcher m = p.matcher(body);
            if (m.find()) {
                if (m.groupCount() > 0) {
                    return m.group(1);
                } else {
                    return m.group(0);
                }
            }
        } catch (Exception e) {
            montoyaApi.logging().logToError("[Token Binder] Regex extraction error: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Inject token into request
     */
    private HttpRequest injectToken(HttpRequest request) {
        try {
            HttpRequest modifiedRequest = request;
            String formattedToken = tokenFormat.replace("{token}", currentToken);
            
            switch (injectionLocation) {
                case HEADER:
                    // Remove existing header and add new one
                    modifiedRequest = request.withRemovedHeader(injectionKey)
                        .withAddedHeader(injectionKey, formattedToken);
                    break;
                    
                case QUERY_PARAM:
                    // Add or replace query parameter
                    HttpParameter param = HttpParameter.parameter(injectionKey, formattedToken, HttpParameterType.URL);
                    modifiedRequest = request.withAddedParameters(param);
                    break;
                    
                case BODY_JSON:
                    String bodyStr = request.bodyToString();
                    if (bodyStr != null && bodyStr.trim().startsWith("{")) {
                        bodyStr = bodyStr.trim();
                        if (bodyStr.endsWith("}")) {
                            bodyStr = bodyStr.substring(0, bodyStr.length() - 1).trim();
                            if (!bodyStr.endsWith("{") && !bodyStr.isEmpty()) {
                                bodyStr += ",";
                            }
                            bodyStr += "\"" + injectionKey + "\":\"" + 
                                formattedToken.replace("\"", "\\\"") + "\"}";
                            modifiedRequest = request.withBody(bodyStr);
                        }
                    }
                    break;
                    
                case BODY_FORM:
                    String formBody = request.bodyToString();
                    if (formBody == null || formBody.isEmpty()) {
                        formBody = injectionKey + "=" + java.net.URLEncoder.encode(formattedToken, StandardCharsets.UTF_8);
                    } else {
                        if (!formBody.endsWith("&")) {
                            formBody += "&";
                        }
                        formBody += injectionKey + "=" + java.net.URLEncoder.encode(formattedToken, StandardCharsets.UTF_8);
                    }
                    modifiedRequest = request.withBody(formBody);
                    break;
            }
            
            return modifiedRequest;
        } catch (Exception e) {
            montoyaApi.logging().logToError("[Token Binder] Error injecting token: " + e.getMessage());
            return request;
        }
    }
    
    /**
     * Check if URL matches pattern
     */
    private boolean matchesPattern(String url, String pattern) {
        if (pattern == null || pattern.isEmpty() || url == null) {
            return false;
        }
        
        // Support wildcard patterns like "api.example.com/v1/*"
        if (pattern.contains("*")) {
            // Convert wildcard pattern to regex
            String regexPattern = pattern
                .replace(".", "\\.")  // Escape dots
                .replace("*", ".*");   // Replace * with .*
            return url.matches(".*" + regexPattern + ".*");
        }
        
        // Simple contains match for flexibility
        return url.contains(pattern) || pattern.contains(url);
    }
    
    /**
     * NEW: Check if a tab ID is a target tab (supports multiple target tabs)
     */
    private boolean isTargetTab(int tabId) {
        return targetRepeaterTabIds.contains(tabId);
    }
    
    /**
     * Mask token for logging
     */
    private String maskToken(String token) {
        if (token == null || token.length() <= 10) {
            return token;
        }
        return token.substring(0, 4) + "..." + token.substring(token.length() - 4);
    }
    
    // Configuration methods
    public void configure(String sourceTab, String targetTab, String tokenPath,
                         String injectionLocation, String injectionKey, String tokenFormat) {
        this.sourceTabPattern = sourceTab;
        this.targetTabPattern = targetTab;
        this.tokenPath = tokenPath;
        this.injectionKey = injectionKey;
        this.tokenFormat = tokenFormat != null ? tokenFormat : "Bearer {token}";
        this.useRepeaterTabIds = false;
        
        // Parse comma-separated target patterns
        this.targetTabPatterns.clear();
        if (targetTab != null && !targetTab.trim().isEmpty()) {
            String[] patterns = targetTab.split(",");
            for (String p : patterns) {
                this.targetTabPatterns.add(p.trim());
            }
        }

        switch (injectionLocation.toLowerCase()) {
            case "header":
                this.injectionLocation = TokenInjectionLocation.HEADER;
                break;
            case "query":
            case "query_param":
                this.injectionLocation = TokenInjectionLocation.QUERY_PARAM;
                break;
            case "body_json":
            case "json":
                this.injectionLocation = TokenInjectionLocation.BODY_JSON;
                break;
            case "body_form":
            case "form":
                this.injectionLocation = TokenInjectionLocation.BODY_FORM;
                break;
            default:
                this.injectionLocation = TokenInjectionLocation.HEADER;
        }
        
        montoyaApi.logging().logToOutput("[Token Binder] Configuration updated (URL Patterns):");
        montoyaApi.logging().logToOutput("  Source Tab: " + sourceTabPattern);
        montoyaApi.logging().logToOutput("  Target Tabs: " + (targetTabPatterns.isEmpty() ? "None" : targetTabPatterns));
        montoyaApi.logging().logToOutput("  Token Path: " + tokenPath);
        montoyaApi.logging().logToOutput("  Injection: " + injectionLocation + " -> " + injectionKey);
    }
    
    /**
     * NEW: Configure using Repeater tab IDs
     * @param sourceRepeaterTabId The ID of the source Repeater tab (where to get the token from)
     * @param targetRepeaterTabIds Comma-separated target tab IDs (where to inject the token) or single ID
     * @param tokenPath JSONPath or regex to extract token
     * @param injectionLocation Where to inject (header/query/body_json/body_form)
     * @param injectionKey Header/param name
     * @param tokenFormat Token format template
     */
    public void configureWithRepeaterTabIds(int sourceRepeaterTabId, String targetRepeaterTabIdsStr, String tokenPath,
                                           String injectionLocation, String injectionKey, String tokenFormat) {
        this.sourceRepeaterTabId = sourceRepeaterTabId;
        this.tokenPath = tokenPath;
        this.injectionKey = injectionKey;
        this.tokenFormat = tokenFormat != null ? tokenFormat : "Bearer {token}";
        this.useRepeaterTabIds = true;
        this.lastSourceRequest = null; // Reset captured request
        
        // Parse comma-separated target tab IDs
        this.targetRepeaterTabIds.clear();
        if (targetRepeaterTabIdsStr != null && !targetRepeaterTabIdsStr.trim().isEmpty()) {
            String[] tabIdStrings = targetRepeaterTabIdsStr.split(",");
            for (String tabIdStr : tabIdStrings) {
                try {
                    int tabId = Integer.parseInt(tabIdStr.trim());
                    this.targetRepeaterTabIds.add(tabId);
                } catch (NumberFormatException e) {
                    montoyaApi.logging().logToError("[Token Binder] Invalid target tab ID: " + tabIdStr);
                }
            }
        }
        
        // Keep backward compatibility
        if (!this.targetRepeaterTabIds.isEmpty()) {
            this.targetRepeaterTabId = this.targetRepeaterTabIds.get(0);
        }
        
        switch (injectionLocation.toLowerCase()) {
            case "header":
                this.injectionLocation = TokenInjectionLocation.HEADER;
                break;
            case "query":
            case "query_param":
                this.injectionLocation = TokenInjectionLocation.QUERY_PARAM;
                break;
            case "body_json":
            case "json":
                this.injectionLocation = TokenInjectionLocation.BODY_JSON;
                break;
            case "body_form":
            case "form":
                this.injectionLocation = TokenInjectionLocation.BODY_FORM;
                break;
            default:
                this.injectionLocation = TokenInjectionLocation.HEADER;
        }
        
        montoyaApi.logging().logToOutput("[Token Binder] Configuration updated (Repeater Tab IDs):");
        montoyaApi.logging().logToOutput("  Source Repeater Tab ID: " + sourceRepeaterTabId);
        montoyaApi.logging().logToOutput("  Target Repeater Tab IDs: " + this.targetRepeaterTabIds);
        montoyaApi.logging().logToOutput("  Token Path: " + tokenPath);
        montoyaApi.logging().logToOutput("  Injection: " + injectionLocation + " -> " + injectionKey);
    }
    
    public String getCurrentToken() {
        return currentToken;
    }
    
    public void clearToken() {
        currentToken = null;
        lastTokenFetchTime = 0;
        tabTokens.clear();
        montoyaApi.logging().logToOutput("[Token Binder] Token cleared");
    }
    
    // NEW: Getter for auto-fetch enabled state
    public boolean isAutoFetchEnabled() {
        return autoFetchEnabled;
    }
    
    // NEW: Setter for auto-fetch enabled state
    public void setAutoFetchEnabled(boolean enabled) {
        this.autoFetchEnabled = enabled;
        montoyaApi.logging().logToOutput("[Token Binder] Auto-fetch " + (enabled ? "enabled" : "disabled"));
    }
    
    /**
     * NEW: Automatically fetch token by sending a request to the source endpoint
     * This method uses the actual request captured from Repeater to ensure exact replication
     */
    private void autoFetchTokenFromSourceEndpoint() {
        try {
            // Check if we have a captured source request or template
            HttpRequest requestToSend = lastSourceRequest != null ? lastSourceRequest : sourceRequestTemplate;
            
            if (requestToSend == null) {
                montoyaApi.logging().logToOutput("[Token Binder] No source request captured yet.");
                montoyaApi.logging().logToOutput("[Token Binder] Please send a request to your source endpoint first to establish the template.");
                return;
            }
            
            montoyaApi.logging().logToOutput("[Token Binder] Auto-fetching using " + 
                (lastSourceRequest != null ? "captured" : "template") + " source request...");
            montoyaApi.logging().logToOutput("[Token Binder] Source URL: " + requestToSend.url());
            montoyaApi.logging().logToOutput("[Token Binder] Method: " + requestToSend.method());
            
            // Send the request
            burp.api.montoya.http.message.HttpRequestResponse response = montoyaApi.http().sendRequest(requestToSend);
            
            if (response.response() != null) {
                montoyaApi.logging().logToOutput("[Token Binder] ✓ Received response from source endpoint");
                extractToken(response.response());
                montoyaApi.logging().logToOutput("[Token Binder] ✓ Auto-fetch complete!");
            } else {
                montoyaApi.logging().logToError("[Token Binder] No response received from source endpoint");
            }
            
        } catch (Exception e) {
            montoyaApi.logging().logToError("[Token Binder] Auto-fetch failed: " + e.getMessage());
        }
    }
    
    /**
     * Configuration UI Panel
     */
    private static class TokenBinderConfigPanel extends JPanel {
        private final Extension extension;
        
        private JTextField sourceTabField;
        private JTextField targetTabField;
        private JTextField tokenPathField;
        private JComboBox<String> injectionLocationCombo;
        private JTextField injectionKeyField;
        private JTextField tokenFormatField;
        private JLabel tokenStatusLabel;
        private JCheckBox autoFetchCheckBox;
        private JCheckBox useRepeaterTabIdsCheckBox;  // NEW: Tab ID mode
        private JTextField sourceRepeaterIdField;     // NEW: Source tab ID
        private JTextField targetRepeaterIdField;     // NEW: Target tab ID
        
        public TokenBinderConfigPanel(Extension extension) {
            this.extension = extension;
            initializeUI();
        }
        
        private void initializeUI() {
            setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
            setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            
            // NEW: Tab ID mode toggle
            useRepeaterTabIdsCheckBox = new JCheckBox("Use Repeater Tab IDs (instead of URL patterns)");
            useRepeaterTabIdsCheckBox.setSelected(false);
            useRepeaterTabIdsCheckBox.addActionListener(e -> updateUIMode());
            add(useRepeaterTabIdsCheckBox);
            add(Box.createVerticalStrut(10));
            
            // Source configuration - Pattern mode
            add(createLabel("Source Tab (Token Generator) - URL Pattern:"));
            sourceTabField = new JTextField(30);
            sourceTabField.setToolTipText("URL pattern for the tab that generates the token");
            add(sourceTabField);
            add(Box.createVerticalStrut(5));
            
            // Source configuration - Tab ID mode
            add(createLabel("Source Repeater Tab ID:"));
            sourceRepeaterIdField = new JTextField(30);
            sourceRepeaterIdField.setToolTipText("Repeater tab number (e.g., 1, 2, 3...)");
            sourceRepeaterIdField.setVisible(false);
            add(sourceRepeaterIdField);
            add(Box.createVerticalStrut(5));
            
            // Target configuration - Pattern mode
            add(createLabel("Target Tab (Token Consumer) - URL Pattern(s):"));
            targetTabField = new JTextField(30);
            targetTabField.setToolTipText("Comma-separated URL patterns for the tabs that use the token (e.g., api.example.com/v1/*,api.example.com/v2/*)");
            add(targetTabField);
            add(Box.createVerticalStrut(5));
            
            // Target configuration - Tab ID mode
            add(createLabel("Target Repeater Tab ID:"));
            targetRepeaterIdField = new JTextField(30);
            targetRepeaterIdField.setToolTipText("Repeater tab number (e.g., 1, 2, 3...)");
            targetRepeaterIdField.setVisible(false);
            add(targetRepeaterIdField);
            add(Box.createVerticalStrut(5));
            
            add(createLabel("Token Path (JSONPath or Regex):"));
            tokenPathField = new JTextField(30);
            tokenPathField.setToolTipText("JSONPath like '$.token' or regex pattern like '\"token\"\\\\s*:\\\\s*\"([^\"]+)\"'");
            add(tokenPathField);
            add(Box.createVerticalStrut(5));
            
            add(createLabel("Injection Location:"));
            String[] locations = {"Header", "Query Parameter", "Body (JSON)", "Body (Form)"};
            injectionLocationCombo = new JComboBox<>(locations);
            add(injectionLocationCombo);
            add(Box.createVerticalStrut(5));
            
            add(createLabel("Injection Key (Parameter Name):"));
            injectionKeyField = new JTextField(30);
            injectionKeyField.setText("Authorization");
            add(injectionKeyField);
            add(Box.createVerticalStrut(5));
            
            add(createLabel("Token Format (optional):"));
            tokenFormatField = new JTextField(30);
            tokenFormatField.setText("Bearer {token}");
            add(tokenFormatField);
            add(Box.createVerticalStrut(10));
            
            // Auto-fetch checkbox
            autoFetchCheckBox = new JCheckBox("Auto-fetch token from source when accessing target");
            autoFetchCheckBox.setSelected(true);
            autoFetchCheckBox.addActionListener(e -> {
                extension.setAutoFetchEnabled(autoFetchCheckBox.isSelected());
            });
            add(autoFetchCheckBox);
            add(Box.createVerticalStrut(10));
            
            JButton applyButton = new JButton("Apply Configuration");
            applyButton.addActionListener(e -> applyConfiguration());
            add(applyButton);
            add(Box.createVerticalStrut(10));
            
            add(createLabel("Current Token Status:"));
            tokenStatusLabel = new JLabel("No token extracted yet");
            tokenStatusLabel.setForeground(Color.GRAY);
            add(tokenStatusLabel);
            add(Box.createVerticalStrut(5));
            
            JButton clearButton = new JButton("Clear Token");
            clearButton.addActionListener(e -> {
                extension.clearToken();
                updateTokenStatus();
            });
            add(clearButton);
            
            JButton refreshButton = new JButton("Refresh Token Status");
            refreshButton.addActionListener(e -> updateTokenStatus());
            add(refreshButton);
        }
        
        // NEW: Update UI visibility based on mode
        private void updateUIMode() {
            boolean useTabIds = useRepeaterTabIdsCheckBox.isSelected();
            sourceTabField.setVisible(!useTabIds);
            targetTabField.setVisible(!useTabIds);
            sourceRepeaterIdField.setVisible(useTabIds);
            targetRepeaterIdField.setVisible(useTabIds);
            revalidate();
            repaint();
        }
        
        private JLabel createLabel(String text) {
            JLabel label = new JLabel(text);
            label.setAlignmentX(Component.LEFT_ALIGNMENT);
            return label;
        }
        
        private void applyConfiguration() {
            boolean useTabIds = useRepeaterTabIdsCheckBox.isSelected();
            
            String tokenPath = tokenPathField.getText().trim();
            String injectionLocation = (String) injectionLocationCombo.getSelectedItem();
            String injectionKey = injectionKeyField.getText().trim();
            String tokenFormat = tokenFormatField.getText().trim();
            
            if (tokenPath.isEmpty() || injectionKey.isEmpty()) {
                JOptionPane.showMessageDialog(this, 
                    "Please fill in Token Path and Injection Key",
                    "Configuration Error",
                    JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            String locationValue = getLocationValue(injectionLocation);
            
            if (useTabIds) {
                // NEW: Tab ID mode
                String sourceIdStr = sourceRepeaterIdField.getText().trim();
                String targetIdStr = targetRepeaterIdField.getText().trim();
                
                if (sourceIdStr.isEmpty() || targetIdStr.isEmpty()) {
                    JOptionPane.showMessageDialog(this, 
                        "Please fill in both Source and Target Repeater Tab IDs",
                        "Configuration Error",
                        JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                try {
                    int sourceId = Integer.parseInt(sourceIdStr);
                    int targetId = Integer.parseInt(targetIdStr);
                    extension.configureWithRepeaterTabIds(sourceId, String.valueOf(targetId), tokenPath, locationValue, injectionKey, tokenFormat);
                } catch (NumberFormatException ex) {
                    JOptionPane.showMessageDialog(this, 
                        "Repeater Tab IDs must be numbers",
                        "Configuration Error",
                        JOptionPane.ERROR_MESSAGE);
                    return;
                }
            } else {
                // Pattern mode
                String sourceTab = sourceTabField.getText().trim();
                String targetTab = targetTabField.getText().trim();
                
                if (sourceTab.isEmpty() || targetTab.isEmpty()) {
                    JOptionPane.showMessageDialog(this, 
                        "Please fill in Source and Target Tab patterns",
                        "Configuration Error",
                        JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                extension.configure(sourceTab, targetTab, tokenPath, locationValue, injectionKey, tokenFormat);
            }
            
            JOptionPane.showMessageDialog(this,
                "Configuration applied successfully!",
                "Success",
                JOptionPane.INFORMATION_MESSAGE);
            
            updateTokenStatus();
        }
        
        private String getLocationValue(String injectionLocation) {
            switch (injectionLocation) {
                case "Header":
                    return "header";
                case "Query Parameter":
                    return "query";
                case "Body (JSON)":
                    return "body_json";
                case "Body (Form)":
                    return "body_form";
                default:
                    return "header";
            }
        }
        
        public void updateTokenStatus() {
            String token = extension.getCurrentToken();
            if (token != null && !token.isEmpty()) {
                String masked = token.length() > 20 
                    ? token.substring(0, 10) + "..." + token.substring(token.length() - 10)
                    : token;
                tokenStatusLabel.setText("Token: " + masked);
                tokenStatusLabel.setForeground(Color.GREEN);
            } else {
                tokenStatusLabel.setText("No token extracted yet");
                tokenStatusLabel.setForeground(Color.GRAY);
            }
        }
    }
}