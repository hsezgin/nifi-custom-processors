package org.sezgin.processors;

import com.github.benmanes.caffeine.cache.AsyncCache;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.*;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.InputRequirement.Requirement;
import org.apache.nifi.annotation.behavior.SupportsBatching;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.PropertyValue;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.*;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.io.InputStreamCallback;
import org.apache.nifi.processor.io.OutputStreamCallback;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.stream.io.StreamUtils;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

// Add JSON parsing libraries
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

@SupportsBatching
@InputRequirement(Requirement.INPUT_ALLOWED)
@Tags({"http", "https", "ssl", "bypass", "insecure", "fast", "invoke", "pagination", "rest", "api"})
@CapabilityDescription("Custom implementation of HTTP client that allows bypassing SSL validation for improved performance with support for pagination")
public class InsecureInvokeHTTP extends AbstractProcessor {

    // Static block for SSL setup (unchanged)
    static {
        try {
            // Disable SSL validation at the JVM level
            HttpsURLConnection.setDefaultHostnameVerifier(
                    (hostname, sslSession) -> true);

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
            }, new java.security.SecureRandom());

            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            SSLContext.setDefault(sc);

            // Also disable a bunch of Java security properties
            java.security.Security.setProperty("ssl.TrustManagerFactory.algorithm", "");
            System.setProperty("com.sun.net.ssl.checkRevocation", "false");
            System.setProperty("javax.net.ssl.trustStore", "NONE");
            System.setProperty("javax.net.ssl.trustStoreType", "JKS");
            System.setProperty("javax.net.ssl.trustStorePassword", "");
            System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
            System.setProperty("jdk.tls.client.protocols", "TLSv1.2");
        } catch (Exception e) {
            // Cannot log here since logger isn't initialized yet
            System.err.println("Failed to disable SSL validation globally: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Property Descriptors (existing ones)
    public static final PropertyDescriptor URL = new PropertyDescriptor.Builder()
            .name("URL")
            .description("The URL to connect to. If not specified, the processor will try to use the http.url attribute from the FlowFile.")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.URL_VALIDATOR)
            .build();

    public static final PropertyDescriptor METHOD = new PropertyDescriptor.Builder()
            .name("HTTP Method")
            .description("The HTTP Method to use")
            .required(true)
            .allowableValues("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
            .defaultValue("GET")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    public static final PropertyDescriptor DEBUG_MODE = new PropertyDescriptor.Builder()
            .name("Debug Mode")
            .description("Enable/disable debug mode with extensive logging")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("false")
            .build();

    // Pagination properties - NOT REQUIRED and USE EXPRESSION LANGUAGE
    public static final PropertyDescriptor ENABLE_PAGINATION = new PropertyDescriptor.Builder()
            .name("Enable Pagination")
            .description("Whether to automatically handle pagination in responses. Can also be set via FlowFile attribute 'http.pagination.enabled'")
            .required(false) // Not required
            .allowableValues("true", "false")
            .defaultValue("false")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES) // Support Expression Language
            .build();

    public static final PropertyDescriptor PAGINATION_MODE = new PropertyDescriptor.Builder()
            .name("Pagination Mode")
            .description("Type of pagination to handle. Can also be set via FlowFile attribute 'http.pagination.mode'")
            .required(false) // Not required
            .allowableValues("OData (@odata.nextLink)", "Custom")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES) // Support Expression Language
            .build();

    public static final PropertyDescriptor CUSTOM_NEXT_LINK_JSONPATH = new PropertyDescriptor.Builder()
            .name("Custom Next Link JSONPath")
            .description("JSONPath expression to extract the next link URL from the response. Example: '$.nextPage' or '$.pagination.next'. Can also be set via FlowFile attribute 'http.pagination.jsonpath'")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES) // Support Expression Language
            .build();

    public static final PropertyDescriptor MAX_PAGES = new PropertyDescriptor.Builder()
            .name("Maximum Pages")
            .description("Maximum number of pages to retrieve. Use 0 for unlimited (use with caution). Can also be set via FlowFile attribute 'http.pagination.max.pages'")
            .required(false)
            .defaultValue("10")
            .addValidator(StandardValidators.NON_NEGATIVE_INTEGER_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES) // Support Expression Language
            .build();

    public static final PropertyDescriptor COMBINE_RESULTS = new PropertyDescriptor.Builder()
            .name("Combine Results")
            .description("Whether to combine results from all pages into a single response. If enabled and Pagination JSON Path specified, will combine the data arrays from each page. Can also be set via FlowFile attribute 'http.pagination.combine'")
            .required(false)
            .allowableValues("true", "false")
            .defaultValue("false")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES) // Support Expression Language
            .build();

    // Added this property with a more appropriate name
    public static final PropertyDescriptor PAGINATION_JSON_PATH = new PropertyDescriptor.Builder()
            .name("Pagination JSON Path")
            .description("When combining results, specifies the JSONPath to the array field in the response that contains the data items to be combined (e.g., 'value' for OData, 'items' for other APIs). Can also be set via FlowFile attribute 'http.pagination.data.path'")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    // Existing properties (unchanged)
    public static final PropertyDescriptor BYPASS_SSL_VALIDATION = new PropertyDescriptor.Builder()
            .name("Bypass SSL Validation")
            .description("Whether to bypass SSL certificate validation")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("true")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    public static final PropertyDescriptor CONNECTION_TIMEOUT = new PropertyDescriptor.Builder()
            .name("Connection Timeout")
            .description("Maximum time allowed for connection to remote service (in milliseconds)")
            .required(true)
            .defaultValue("5000")
            .addValidator(StandardValidators.POSITIVE_INTEGER_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    public static final PropertyDescriptor MAX_POOL_SIZE = new PropertyDescriptor.Builder()
            .name("Max Connection Pool Size")
            .description("Maximum number of connections to keep in the connection pool")
            .required(true)
            .defaultValue("100")
            .addValidator(StandardValidators.POSITIVE_INTEGER_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    public static final PropertyDescriptor PROXY_HOST = new PropertyDescriptor.Builder()
            .name("Proxy Host")
            .description("The host name of the proxy server")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor PROXY_PORT = new PropertyDescriptor.Builder()
            .name("Proxy Port")
            .description("The port of the proxy server")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.PORT_VALIDATOR)
            .build();

    public static final PropertyDescriptor CONTENT_TYPE = new PropertyDescriptor.Builder()
            .name("Content-Type")
            .description("The Content-Type to specify in the request")
            .required(false)
            .defaultValue("application/json")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor ADD_HEADERS = new PropertyDescriptor.Builder()
            .name("Add Headers to Request")
            .description("Specifies whether or not the headers should be included in the request")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("true")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    public static final PropertyDescriptor FOLLOW_REDIRECTS = new PropertyDescriptor.Builder()
            .name("Follow Redirects")
            .description("Specifies whether or not redirects should be followed")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("true")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    public static final PropertyDescriptor SUCCESS_CODES = new PropertyDescriptor.Builder()
            .name("Success Status Codes")
            .description("Comma-separated list of HTTP Status Codes that are considered successful responses. " +
                    "Any status code matching these values will be routed to success, otherwise to failure. " +
                    "Default is 2xx status codes (200-299).")
            .required(true)
            .defaultValue("200-299")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor EXTRACT_TOKEN_HEADER = new PropertyDescriptor.Builder()
            .name("Extract Token Header")
            .description("The name of the HTTP response header containing an authentication token to extract and store " +
                    "as a flowfile attribute. Common examples: Authorization, X-Auth-Token, etc.")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor TOKEN_ATTRIBUTE_NAME = new PropertyDescriptor.Builder()
            .name("Token Attribute Name")
            .description("The name of the attribute to store the extracted token value. Only used if Extract Token Header is set.")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    // Relationships
    public static final Relationship REL_SUCCESS = new Relationship.Builder()
            .name("success")
            .description("All files that are successfully processed are routed to this relationship")
            .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("failure")
            .description("All files that fail to be processed are routed to this relationship")
            .build();

    public static final Relationship REL_RETRY = new Relationship.Builder()
            .name("retry")
            .description("All files that encounter network issues will be sent to this relationship for retry")
            .build();

    private List<PropertyDescriptor> descriptors;
    private Set<Relationship> relationships;

    private final AtomicReference<CloseableHttpClient> httpClientAtomicReference = new AtomicReference<>();
    private final ObjectMapper objectMapper = new ObjectMapper();  // JSON parser for pagination

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<>();
        descriptors.add(URL);
        descriptors.add(METHOD);
        descriptors.add(DEBUG_MODE);
        // Add pagination properties
        descriptors.add(ENABLE_PAGINATION);
        descriptors.add(PAGINATION_MODE);
        descriptors.add(CUSTOM_NEXT_LINK_JSONPATH);
        descriptors.add(MAX_PAGES);
        descriptors.add(COMBINE_RESULTS);
        descriptors.add(PAGINATION_JSON_PATH); // Add the new property
        // Existing properties
        descriptors.add(BYPASS_SSL_VALIDATION);
        descriptors.add(CONNECTION_TIMEOUT);
        descriptors.add(MAX_POOL_SIZE);
        descriptors.add(PROXY_HOST);
        descriptors.add(PROXY_PORT);
        descriptors.add(CONTENT_TYPE);
        descriptors.add(ADD_HEADERS);
        descriptors.add(FOLLOW_REDIRECTS);
        descriptors.add(SUCCESS_CODES);
        descriptors.add(EXTRACT_TOKEN_HEADER);
        descriptors.add(TOKEN_ATTRIBUTE_NAME);
        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<>();
        relationships.add(REL_SUCCESS);
        relationships.add(REL_FAILURE);
        relationships.add(REL_RETRY);
        this.relationships = Collections.unmodifiableSet(relationships);
    }

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }

    /**
     * Initialize HTTP Client
     */
    private void initializeHttpClient(final ProcessContext context) {
        try {
            createHttpClient(context);
            getLogger().info("Successfully initialized HTTP client for InsecureInvokeHTTP");
        } catch (Exception e) {
            getLogger().error("Failed to initialize HTTP client: {}", new Object[]{e.getMessage()}, e);
        }
    }

    /**
     * Create a fully insecure HTTP client that will ignore all SSL validation
     */
    private CloseableHttpClient createInsecureHttpClient(int connectionTimeout, int maxPoolSize, boolean followRedirects) {
        try {
            // Create custom SSL context with no validation
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                    }
            }, new java.security.SecureRandom());

            // Register the SSL context as the default
            SSLContext.setDefault(sslContext);

            // Create SSL socket factory with no hostname verification
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                    sslContext,
                    NoopHostnameVerifier.INSTANCE);

            // Create registry with HTTP and HTTPS support
            Registry<ConnectionSocketFactory> socketFactoryRegistry =
                    RegistryBuilder.<ConnectionSocketFactory>create()
                            .register("http", PlainConnectionSocketFactory.getSocketFactory())
                            .register("https", sslsf)
                            .build();

            // Create connection manager with registry
            PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
            cm.setMaxTotal(maxPoolSize);
            cm.setDefaultMaxPerRoute(maxPoolSize);

            // Create request config
            RequestConfig requestConfig = RequestConfig.custom()
                    .setConnectTimeout(connectionTimeout)
                    .setConnectionRequestTimeout(connectionTimeout)
                    .setSocketTimeout(connectionTimeout)
                    .setRedirectsEnabled(followRedirects)
                    .build();

            // Build the HTTP client with all the settings
            return HttpClients.custom()
                    .setSSLSocketFactory(sslsf)
                    .setConnectionManager(cm)
                    .setDefaultRequestConfig(requestConfig)
                    .build();
        } catch (Exception e) {
            throw new ProcessException("Failed to create insecure HTTP client: " + e.getMessage(), e);
        }
    }

    /**
     * Create HTTP Client and store in atomic reference
     */
    private void createHttpClient(final ProcessContext context) {
        try {
            final boolean bypassSSL = context.getProperty(BYPASS_SSL_VALIDATION).asBoolean();
            final int connectionTimeout = context.getProperty(CONNECTION_TIMEOUT).asInteger();
            final int maxPoolSize = context.getProperty(MAX_POOL_SIZE).asInteger();
            final boolean followRedirects = context.getProperty(FOLLOW_REDIRECTS).asBoolean();

            // Close existing HTTP client
            closeHttpClient();

            // Create a completely insecure HTTP client regardless of the bypassSSL flag
            // This ensures all SSL validation is disabled
            CloseableHttpClient httpClient = createInsecureHttpClient(
                    connectionTimeout, maxPoolSize, followRedirects);

            // Set the created HTTP client
            httpClientAtomicReference.set(httpClient);

            getLogger().info("Created HTTP client with completely disabled SSL security");
        } catch (Exception e) {
            getLogger().error("Failed to create HTTP client: {}", new Object[]{e.getMessage()}, e);
            throw new ProcessException("Failed to create HTTP client", e);
        }
    }

    /**
     * Close HTTP Client
     */
    private void closeHttpClient() {
        final CloseableHttpClient client = httpClientAtomicReference.getAndSet(null);
        if (client != null) {
            try {
                client.close();
                getLogger().info("Successfully closed HTTP client");
            } catch (IOException e) {
                getLogger().warn("Failed to close HTTP client: {}", new Object[]{e.getMessage()}, e);
            }
        }
    }

    /**
     * Create appropriate HttpRequestBase object based on HTTP Method
     */
    private HttpRequestBase createHttpRequest(String method, String url) {
        // Add extra validation for debug mode
        if (method == null || method.trim().isEmpty()) {
            throw new IllegalArgumentException("HTTP method cannot be null or empty");
        }

        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("URL cannot be null or empty");
        }

        // Ensure URL is properly formatted
        if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://")) {
            throw new IllegalArgumentException("URL must start with http:// or https://: " + url);
        }

        // Create appropriate request object based on HTTP method
        // Using switch expressions for Java 21
        return switch (method.toUpperCase()) {
            case "GET" -> new HttpGet(url);
            case "POST" -> new HttpPost(url);
            case "PUT" -> new HttpPut(url);
            case "DELETE" -> new HttpDelete(url);
            case "HEAD" -> new HttpHead(url);
            case "OPTIONS" -> new HttpOptions(url);
            case "PATCH" -> new HttpPatch(url);
            default -> throw new IllegalArgumentException("Unsupported HTTP method: " + method);
        };
    }

    /**
     * Add all headers from FlowFile to the request
     */
    private void addHeadersToRequest(HttpRequestBase request, FlowFile flowFile, boolean addHeaders) {
        if (!addHeaders) {
            return;
        }

        flowFile.getAttributes().entrySet().stream()
                .filter(entry -> entry.getKey().startsWith("http.header."))
                .forEach(entry -> {
                    String headerName = entry.getKey().substring(12); // "http.header.".length() = 12
                    String headerValue = entry.getValue();

                    // Skip common HTTP headers that should be managed by the client
                    if (!headerName.equalsIgnoreCase("content-length") &&
                            !headerName.equalsIgnoreCase("transfer-encoding") &&
                            !headerName.equalsIgnoreCase("host")) {
                        request.addHeader(headerName, headerValue);
                    }
                });
    }

    /**
     * Log all FlowFile attributes for debugging purposes
     */
    private void logFlowFileAttributes(FlowFile flowFile, boolean debugMode) {
        if (!debugMode) return;

        Map<String, String> attributes = flowFile.getAttributes();
        StringBuilder sb = new StringBuilder();
        sb.append("FlowFile Attributes:\n");

        attributes.forEach((key, value) -> {
            sb.append("  ").append(key).append(" = ").append(value).append("\n");
        });

        getLogger().info(sb.toString());
    }

    /**
     * Extract next link URL from the response based on pagination mode
     * Optimized to minimize JSON parsing when possible
     *
     * @param responseBody JSON response body as string
     * @param paginationMode The pagination mode (OData or Custom)
     * @param customJsonPath Custom JSONPath for next link (for Custom mode)
     * @param debugMode Whether debug mode is enabled
     * @return Next link URL or null if no next link found
     */
    private String extractNextLink(String responseBody, String paginationMode, String customJsonPath, boolean debugMode) {
        // Quick check if response is empty or null to avoid parsing
        if (responseBody == null || responseBody.isEmpty()) {
            return null;
        }

        try {
            // For OData pagination, try simple string search first for performance
            if ("OData (@odata.nextLink)".equals(paginationMode)) {
                // Simple string search for OData nextLink - much faster than parsing the entire JSON
                int nextLinkIndex = responseBody.indexOf("\"@odata.nextLink\"");
                if (nextLinkIndex >= 0) {
                    // Found the nextLink field, now extract the URL
                    int valueStart = responseBody.indexOf('"', nextLinkIndex + 18) + 1; // Skip past the field name and colon to the value
                    if (valueStart > 0) {
                        int valueEnd = responseBody.indexOf('"', valueStart);
                        if (valueEnd > valueStart) {
                            String nextLink = responseBody.substring(valueStart, valueEnd);
                            if (debugMode) {
                                getLogger().info("Found OData next link using string search: {}", new Object[]{nextLink});
                            }
                            return nextLink;
                        }
                    }
                }

                // Fallback to JSON parsing if string search failed
                JsonNode rootNode = objectMapper.readTree(responseBody);
                if (rootNode.has("@odata.nextLink")) {
                    String nextLink = rootNode.get("@odata.nextLink").asText();
                    if (debugMode) {
                        getLogger().info("Found OData next link using JSON parsing: {}", new Object[]{nextLink});
                    }
                    return nextLink;
                }
            } else if ("Custom".equals(paginationMode) && customJsonPath != null && !customJsonPath.isEmpty()) {
                // Custom pagination - use the provided JSONPath
                // Simplified JSONPath support for better performance

                // Simple JSONPath support for root level properties with string search
                if (customJsonPath.startsWith("$.")) {
                    String path = customJsonPath.substring(2); // Remove the $. prefix
                    String[] parts = path.split("\\.");

                    // For simple single-level paths, try string search first
                    if (parts.length == 1) {
                        String fieldName = "\"" + parts[0] + "\"";
                        int fieldIndex = responseBody.indexOf(fieldName);
                        if (fieldIndex >= 0) {
                            int valueStart = responseBody.indexOf('"', fieldIndex + fieldName.length() + 1) + 1;
                            if (valueStart > 0) {
                                int valueEnd = responseBody.indexOf('"', valueStart);
                                if (valueEnd > valueStart) {
                                    String nextLink = responseBody.substring(valueStart, valueEnd);
                                    if (debugMode) {
                                        getLogger().info("Found custom next link using string search: {}", new Object[]{nextLink});
                                    }
                                    return nextLink;
                                }
                            }
                        }
                    }

                    // Fallback to JSON parsing for more complex paths
                    JsonNode currentNode = objectMapper.readTree(responseBody);
                    for (String part : parts) {
                        if (currentNode != null && currentNode.has(part)) {
                            currentNode = currentNode.get(part);
                        } else {
                            currentNode = null;
                            break;
                        }
                    }

                    if (currentNode != null && !currentNode.isNull()) {
                        String nextLink = currentNode.asText();
                        if (debugMode) {
                            getLogger().info("Found custom next link using JSON path: {}", new Object[]{nextLink});
                        }
                        return nextLink;
                    }
                }
            }
        } catch (Exception e) {
            getLogger().warn("Failed to extract next link from response: {}", new Object[]{e.getMessage()});
            if (debugMode) {
                getLogger().warn("Exception details:", e);
            }
        }

        // No next link found or error
        return null;
    }

    /**
     * Combine paginated results into a single response with JSON data arrays combined
     *
     * @param allResponses List of JSON response strings from all pages
     * @param paginationJsonPath JSONPath to the data array field in responses
     * @param debugMode Whether debug mode is enabled
     * @return Combined JSON response as string, or null if combination failed
     */
    private String combineJsonResults(List<String> allResponses, String paginationJsonPath, boolean debugMode) {
        try {
            if (allResponses.isEmpty()) {
                return null;
            }

            // If only one response, just return it
            if (allResponses.size() == 1) {
                return allResponses.get(0);
            }

            // If no pagination JSON path is provided, we can't combine properly
            if (paginationJsonPath == null || paginationJsonPath.isEmpty()) {
                if (debugMode) {
                    getLogger().warn("No pagination JSON path provided, cannot combine results intelligently");
                }
                return null;
            }

            // Parse the first response to get the structure
            JsonNode firstResponse = objectMapper.readTree(allResponses.get(0));

            // Handle simple path without the $. prefix
            if (!paginationJsonPath.startsWith("$.")) {
                paginationJsonPath = "$." + paginationJsonPath;
            }

            // Extract the path components
            String path = paginationJsonPath.substring(2); // Remove the $. prefix
            String[] parts = path.split("\\.");

            // Check if the data field exists in the first response
            JsonNode dataNode = firstResponse;
            for (String part : parts) {
                if (dataNode != null && dataNode.has(part)) {
                    dataNode = dataNode.get(part);
                } else {
                    dataNode = null;
                    break;
                }
            }

            // If data field was not found or is not an array, cannot combine
            if (dataNode == null || !dataNode.isArray()) {
                if (debugMode) {
                    getLogger().warn("Data field '{}' not found or is not an array in response", new Object[]{paginationJsonPath});
                }
                return null;
            }

            // Create a combined response based on the first response
            ObjectNode combinedResponse = (ObjectNode) objectMapper.readTree(allResponses.get(0));

            // Create a new array for the combined data
            ArrayNode combinedDataArray = objectMapper.createArrayNode();

            // Add all items from first page's data array
            dataNode.forEach(item -> combinedDataArray.add(item));

            // Process all subsequent pages and add their data items
            for (int i = 1; i < allResponses.size(); i++) {
                try {
                    JsonNode pageResponse = objectMapper.readTree(allResponses.get(i));

                    // Navigate to the data array in this page
                    JsonNode pageDataNode = pageResponse;
                    for (String part : parts) {
                        if (pageDataNode != null && pageDataNode.has(part)) {
                            pageDataNode = pageDataNode.get(part);
                        } else {
                            pageDataNode = null;
                            break;
                        }
                    }

                    // If data array found, add all its items
                    if (pageDataNode != null && pageDataNode.isArray()) {
                        pageDataNode.forEach(item -> combinedDataArray.add(item));

                        if (debugMode) {
                            getLogger().debug("Added {} items from page {}",
                                    new Object[]{pageDataNode.size(), i + 1});
                        }
                    }
                } catch (Exception e) {
                    getLogger().warn("Failed to process page {}: {}", new Object[]{i + 1, e.getMessage()});
                    if (debugMode) {
                        getLogger().warn("Exception details:", e);
                    }
                }
            }

            // Set the combined data array back to the response
            // Need to navigate to the parent and set the field
            if (parts.length == 1) {
                // Simple case - field is at root level
                combinedResponse.set(parts[0], combinedDataArray);
            } else {
                // Complex case - need to navigate to parent
                ObjectNode currentNode = combinedResponse;
                for (int i = 0; i < parts.length - 1; i++) {
                    JsonNode nextNode = currentNode.get(parts[i]);
                    if (nextNode == null || !nextNode.isObject()) {
                        // Can't navigate further
                        if (debugMode) {
                            getLogger().warn("Cannot navigate to parent of data field '{}' in response",
                                    new Object[]{paginationJsonPath});
                        }
                        return null;
                    }
                    currentNode = (ObjectNode) nextNode;
                }
                // Set the field in the parent
                currentNode.set(parts[parts.length - 1], combinedDataArray);
            }

            if (debugMode) {
                getLogger().info("Combined {} pages with {} total items in '{}' field",
                        new Object[]{allResponses.size(), combinedDataArray.size(), paginationJsonPath});
            }

            // Convert the combined response to string
            return objectMapper.writeValueAsString(combinedResponse);

        } catch (Exception e) {
            getLogger().error("Failed to combine paginated results: {}", new Object[]{e.getMessage()});
            if (debugMode) {
                getLogger().error("Exception details:", e);
            }
            return null;
        }
    }

    /**
     * Get pagination settings from FlowFile attributes if available, otherwise from processor properties
     */
    private Map<String, Object> getPaginationSettings(ProcessContext context, FlowFile flowFile, boolean debugMode) {
        // Yeni bir Map oluştur - ilk yapılması gereken bu
        Map<String, Object> settings = new HashMap<>();

        // Enable Pagination ayarını kontrol et
        String enablePaginationStr = flowFile.getAttribute("http.pagination.enabled");
        if (enablePaginationStr == null) {
            PropertyValue propertyValue = context.getProperty(ENABLE_PAGINATION);
            if (propertyValue != null) {
                enablePaginationStr = propertyValue.evaluateAttributeExpressions(flowFile).getValue();
            }
        }

        // Varsayılan olarak pagination devre dışı
        boolean enablePagination = "true".equalsIgnoreCase(enablePaginationStr);
        settings.put("enablePagination", enablePagination);

        // Pagination Mode (varsayılan "OData (@odata.nextLink)")
        String paginationMode = "OData (@odata.nextLink)"; // Varsayılan değer
        if (enablePagination) {
            String modeFromAttribute = flowFile.getAttribute("http.pagination.mode");
            if (modeFromAttribute == null) {
                PropertyValue propertyValue = context.getProperty(PAGINATION_MODE);
                if (propertyValue != null) {
                    modeFromAttribute = propertyValue.evaluateAttributeExpressions(flowFile).getValue();
                }
            }
            if (modeFromAttribute != null && !modeFromAttribute.trim().isEmpty() &&
                    !modeFromAttribute.equals("no value set")) {
                paginationMode = modeFromAttribute;
            }
        }
        settings.put("paginationMode", paginationMode);

        // Custom JSONPath (varsayılan boş string)
        String customJsonPath = "";
        if (enablePagination) {
            String jsonPathFromAttribute = flowFile.getAttribute("http.pagination.jsonpath");
            if (jsonPathFromAttribute == null) {
                PropertyValue propertyValue = context.getProperty(CUSTOM_NEXT_LINK_JSONPATH);
                if (propertyValue != null) {
                    jsonPathFromAttribute = propertyValue.evaluateAttributeExpressions(flowFile).getValue();
                }
            }
            if (jsonPathFromAttribute != null && !jsonPathFromAttribute.trim().isEmpty() &&
                    !jsonPathFromAttribute.equals("no value set")) {
                customJsonPath = jsonPathFromAttribute;
            }
        }
        settings.put("customJsonPath", customJsonPath);

        // Pagination JSON Path (varsayılan "value" OData için)
        String paginationJsonPath = "value"; // OData için varsayılan değer
        if (enablePagination) {
            String jsonPathFromAttribute = flowFile.getAttribute("http.pagination.data.path");
            if (jsonPathFromAttribute == null) {
                PropertyValue propertyValue = context.getProperty(PAGINATION_JSON_PATH);
                if (propertyValue != null) {
                    jsonPathFromAttribute = propertyValue.evaluateAttributeExpressions(flowFile).getValue();
                }
            }
            if (jsonPathFromAttribute != null && !jsonPathFromAttribute.trim().isEmpty() &&
                    !jsonPathFromAttribute.equals("no value set")) {
                paginationJsonPath = jsonPathFromAttribute;
            } else if (!"OData (@odata.nextLink)".equals(paginationMode)) {
                // OData değilse ve özel bir değer belirtilmemişse, boş string kullan
                paginationJsonPath = "";
            }
        }
        settings.put("paginationJsonPath", paginationJsonPath);

        // Max Pages (varsayılan 10)
        int maxPages = 10; // Varsayılan değer
        if (enablePagination) {
            String maxPagesStr = flowFile.getAttribute("http.pagination.max.pages");
            if (maxPagesStr == null) {
                PropertyValue propertyValue = context.getProperty(MAX_PAGES);
                if (propertyValue != null) {
                    maxPagesStr = propertyValue.evaluateAttributeExpressions(flowFile).getValue();
                }
            }
            try {
                if (maxPagesStr != null && !maxPagesStr.isEmpty()) {
                    maxPages = Integer.parseInt(maxPagesStr);
                }
            } catch (NumberFormatException e) {
                if (debugMode) {
                    getLogger().warn("Invalid max pages value: {}, using default (10)", new Object[]{maxPagesStr});
                }
            }
        }
        settings.put("maxPages", maxPages);

        // Combine Results (varsayılan false)
        boolean combineResults = false; // Varsayılan değer
        if (enablePagination) {
            String combineResultsStr = flowFile.getAttribute("http.pagination.combine");
            if (combineResultsStr == null) {
                PropertyValue propertyValue = context.getProperty(COMBINE_RESULTS);
                if (propertyValue != null) {
                    combineResultsStr = propertyValue.evaluateAttributeExpressions(flowFile).getValue();
                }
            }
            if (combineResultsStr != null) {
                combineResults = "true".equalsIgnoreCase(combineResultsStr);
            }
        }
        settings.put("combineResults", combineResults);

        if (debugMode) {
            if (enablePagination) {
                getLogger().info("Using pagination settings: enabled={}, mode={}, jsonPath={}, maxPages={}, combine={}",
                        new Object[]{enablePagination, paginationMode, paginationJsonPath, maxPages, combineResults});
            } else {
                getLogger().info("Pagination is disabled");
            }
        }

        return settings;
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        // Check if debug mode is enabled
        final boolean debugMode = context.getProperty(DEBUG_MODE).asBoolean();

        // Get FlowFile (may be null if no incoming connection)
        FlowFile flowFile = session.get();

        // Create a new FlowFile if none was received
        boolean createdFlowFile = false;
        if (flowFile == null) {
            flowFile = session.create();
            createdFlowFile = true;
            if (debugMode) {
                getLogger().info("Created new FlowFile as none was received");
            }
        }

        // Log FlowFile attributes for debugging
        if (debugMode) {
            logFlowFileAttributes(flowFile, true);
        }

        // Check if HTTP client is initialized
        CloseableHttpClient httpClient = httpClientAtomicReference.get();
        if (httpClient == null) {
            initializeHttpClient(context);
            httpClient = httpClientAtomicReference.get();

            if (httpClient == null) {
                getLogger().error("Failed to initialize HTTP client");
                if (flowFile != null) {
                    session.transfer(flowFile, REL_FAILURE);
                }
                return;
            }
        }

        // Get pagination settings from FlowFile attributes or processor properties
        Map<String, Object> paginationSettings = getPaginationSettings(context, flowFile, debugMode);
        final boolean enablePagination = (boolean) paginationSettings.get("enablePagination");
        final String paginationMode = (String) paginationSettings.get("paginationMode");
        final String customJsonPath = (String) paginationSettings.get("customJsonPath");
        final String paginationJsonPath = (String) paginationSettings.get("paginationJsonPath");
        final int maxPages = (int) paginationSettings.get("maxPages");
        final boolean combineResults = (boolean) paginationSettings.get("combineResults");

        // Get URL and HTTP method and all other properties with FlowFile attribute expression evaluation
        String url;
        String method;
        String contentType;
        boolean addHeaders;
        String extractTokenHeader;
        String tokenAttributeName;
        String successCodesValue;

        try {
            // First try to get URL from context property (if specified)
            String propertyUrl = context.getProperty(URL).evaluateAttributeExpressions(flowFile).getValue();

            // If URL property is not specified or empty, try to get URL from FlowFile attribute
            String attributeUrl = flowFile.getAttribute("http.url");

            // Determine which URL to use
            if (propertyUrl != null && !propertyUrl.trim().isEmpty()) {
                url = propertyUrl.trim();
                if (debugMode) {
                    getLogger().info("Using URL from processor property: {}", new Object[]{url});
                }
            } else if (attributeUrl != null && !attributeUrl.trim().isEmpty()) {
                url = attributeUrl.trim();
                if (debugMode) {
                    getLogger().info("Using URL from FlowFile attribute: {}", new Object[]{url});
                }
            } else {
                getLogger().error("No URL provided. URL property is not set and FlowFile does not contain 'http.url' attribute");
                session.transfer(flowFile, REL_FAILURE);
                return;
            }

            // Validate URL format (basic check)
            if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://")) {
                getLogger().error("URL must start with http:// or https:// but was: {}", new Object[]{url});
                session.transfer(flowFile, REL_FAILURE);
                return;
            }

            // Get HTTP Method
            method = context.getProperty(METHOD).evaluateAttributeExpressions(flowFile).getValue();
            if (method == null || method.trim().isEmpty()) {
                method = "GET"; // Default to GET
                if (debugMode) {
                    getLogger().info("HTTP Method not specified, defaulting to GET");
                }
            }

            // Get other properties
            contentType = context.getProperty(CONTENT_TYPE).evaluateAttributeExpressions(flowFile).getValue();
            if (contentType == null || contentType.trim().isEmpty()) {
                contentType = "application/json"; // Default to JSON
                if (debugMode) {
                    getLogger().info("Content-Type not specified, defaulting to application/json");
                }
            }

            String addHeadersStr = context.getProperty(ADD_HEADERS).evaluateAttributeExpressions(flowFile).getValue();
            addHeaders = "true".equalsIgnoreCase(addHeadersStr);

            successCodesValue = context.getProperty(SUCCESS_CODES).evaluateAttributeExpressions(flowFile).getValue();
            extractTokenHeader = context.getProperty(EXTRACT_TOKEN_HEADER).evaluateAttributeExpressions(flowFile).getValue();
            tokenAttributeName = context.getProperty(TOKEN_ATTRIBUTE_NAME).evaluateAttributeExpressions(flowFile).getValue();

            if (tokenAttributeName == null || tokenAttributeName.trim().isEmpty()) {
                tokenAttributeName = "auth.token";
            }

        } catch (Exception e) {
            getLogger().error("Failed to evaluate attributes: {}", new Object[]{e.getMessage()}, e);
            session.transfer(flowFile, REL_FAILURE);
            return;
        }

        try {
            // For pagination support, store all responses
            List<String> allResponses = new ArrayList<>();
            String currentUrl = url;
            int pageCount = 0;
            boolean hasMorePages = true;

            // Make initial request and follow pagination links if enabled
            while (hasMorePages && (maxPages == 0 || pageCount < maxPages)) {
                if (debugMode && pageCount > 0) {
                    getLogger().info("Fetching page {} with URL: {}", new Object[]{pageCount + 1, currentUrl});
                }

                // Create HTTP request for current URL
                HttpRequestBase request;
                try {
                    if (debugMode) {
                        getLogger().info("Creating HTTP {} request to URL: {}", new Object[]{method, currentUrl});
                    }

                    request = createHttpRequest(method, currentUrl);

                    if (debugMode) {
                        getLogger().info("Successfully created HTTP request");
                    }
                } catch (Exception e) {
                    getLogger().error("Failed to create HTTP request: {}", new Object[]{e.getMessage()}, e);
                    session.transfer(flowFile, REL_FAILURE);
                    return;
                }

                // Add FlowFile headers to request (only for the first page)
                if ((pageCount == 0) && !createdFlowFile) {
                    addHeadersToRequest(request, flowFile, addHeaders);
                    if (debugMode && addHeaders) {
                        getLogger().info("Added headers from FlowFile to request");
                    }
                }

                // For methods other than GET and DELETE, use flowfile content as entity (only for the first page)
                if (pageCount == 0 && request instanceof HttpEntityEnclosingRequestBase entityRequest) {
                    if (!createdFlowFile && flowFile.getSize() > 0) {
                        // Read FlowFile content
                        final byte[] content = new byte[(int) flowFile.getSize()];
                        session.read(flowFile, new InputStreamCallback() {
                            @Override
                            public void process(InputStream inputStream) throws IOException {
                                StreamUtils.fillBuffer(inputStream, content, true);
                            }
                        });

                        // Content type is always application/json as we want to accept JSON format
                        ContentType requestContentType = ContentType.parse(contentType);
                        entityRequest.setEntity(new StringEntity(new String(content, StandardCharsets.UTF_8), requestContentType));

                        if (debugMode) {
                            getLogger().info("Set request entity from FlowFile content with Content-Type: {}", new Object[]{contentType});
                            String contentPreview = new String(content, StandardCharsets.UTF_8);
                            if (contentPreview.length() > 1000) {
                                contentPreview = contentPreview.substring(0, 1000) + "... (truncated)";
                            }
                            getLogger().info("Request body: {}", new Object[]{contentPreview});
                        }
                    } else {
                        // Empty entity for methods that require a body but no content is available
                        entityRequest.setEntity(new StringEntity("", ContentType.parse(contentType != null ? contentType : "application/json")));

                        if (debugMode) {
                            getLogger().info("Set empty request entity with Content-Type: {}", new Object[]{contentType});
                        }
                    }
                }

                // Send request and get response
                long startNanos = System.nanoTime();

                if (debugMode) {
                    getLogger().info("Sending {} request to {}", new Object[]{method, currentUrl});
                }

                // Using a single response variable for code clarity
                String responseBody = null;
                int statusCode = 0;
                String reasonPhrase = null;
                Map<String, String> responseHeaders = new HashMap<>();
                long responseTime = 0;

                try (CloseableHttpResponse response = httpClient.execute(request)) {
                    statusCode = response.getStatusLine().getStatusCode();
                    reasonPhrase = response.getStatusLine().getReasonPhrase();
                    responseTime = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);

                    if (debugMode) {
                        getLogger().info("Received response with status code {} in {} ms",
                                new Object[]{statusCode, responseTime});
                    }

                    // Get response headers
                    if (response.getAllHeaders() != null) {
                        for (org.apache.http.Header header : response.getAllHeaders()) {
                            String headerName = header.getName().toLowerCase();
                            String headerValue = header.getValue();
                            responseHeaders.put(headerName, headerValue);

                            if (debugMode) {
                                getLogger().info("Response header: {} = {}", new Object[]{headerName, headerValue});
                            }
                        }
                    }

                    // Parse success status codes
                    boolean isSuccess = false;
                    if (successCodesValue != null && !successCodesValue.isEmpty()) {
                        String[] successCodeRanges = successCodesValue.split(",");
                        for (String range : successCodeRanges) {
                            range = range.trim();
                            if (range.contains("-")) {
                                // Handle range (e.g., 200-299)
                                String[] parts = range.split("-");
                                int start = Integer.parseInt(parts[0].trim());
                                int end = Integer.parseInt(parts[1].trim());
                                if (statusCode >= start && statusCode <= end) {
                                    isSuccess = true;
                                    break;
                                }
                            } else if (range.equals(String.valueOf(statusCode))) {
                                // Handle exact match (e.g., 200)
                                isSuccess = true;
                                break;
                            }
                        }
                    } else {
                        // Default behavior: 2xx is success
                        isSuccess = statusCode >= 200 && statusCode < 300;
                    }

                    // If not a success status code, break the pagination loop
                    if (!isSuccess) {
                        if (debugMode) {
                            getLogger().warn("Received non-success status code: {}. Stopping pagination.",
                                    new Object[]{statusCode});
                        }
                        // Read the response body anyway for error information
                        if (response.getEntity() != null) {
                            responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                            if (debugMode) {
                                getLogger().warn("Error response body: {}", new Object[]{responseBody});
                            }
                        }
                        break;
                    }

                    // Get response body
                    if (response.getEntity() != null) {
                        responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

                        if (debugMode) {
                            String responseBodyPreview = responseBody;
                            if (responseBody.length() > 1000) {
                                responseBodyPreview = responseBodyPreview.substring(0, 1000) + "... (truncated)";
                            }
                            getLogger().info("Response body: {}", new Object[]{responseBodyPreview});
                        }

                        // Add the response to all responses for pagination
                        allResponses.add(responseBody);
                    } else {
                        // No response body
                        responseBody = "";
                        allResponses.add(responseBody);
                    }

                    // Handle pagination if enabled - only process JSON for pagination if needed
                    if (enablePagination) {
                        if (responseBody != null && !responseBody.isEmpty()) {
                            // Extract next link from response
                            String nextLink = extractNextLink(responseBody, paginationMode, customJsonPath, debugMode);

                            if (nextLink != null && !nextLink.isEmpty()) {
                                // Use the next link for the next request
                                currentUrl = nextLink;
                                pageCount++;
                            } else {
                                // No more pages
                                hasMorePages = false;
                            }
                        } else {
                            // No response body, no pagination
                            hasMorePages = false;
                        }
                    } else {
                        // Pagination not enabled
                        hasMorePages = false;
                    }
                }

                // Release request resources
                request.releaseConnection();

                // If not processing pagination, or if we've reached the maximum number of pages, exit the loop
                if (!enablePagination || (maxPages > 0 && pageCount >= maxPages)) {
                    hasMorePages = false;
                }
            } // End of pagination loop

            // Create the final FlowFile with response content
            FlowFile resultFlowFile;
            if (createdFlowFile) {
                // If we created the original FlowFile (no input), create a new one for the result
                resultFlowFile = session.create();
                if (debugMode) {
                    getLogger().info("Created new result FlowFile");
                }
            } else {
                // Use the incoming FlowFile as the result
                resultFlowFile = flowFile;
                if (debugMode) {
                    getLogger().info("Using incoming FlowFile as result FlowFile");
                }
            }

            // Determine which response to use
            final String finalResponseBody;
            if (allResponses.isEmpty()) {
                finalResponseBody = "";
                if (debugMode) {
                    getLogger().warn("No responses received");
                }
            } else if (!enablePagination || !combineResults || allResponses.size() == 1) {
                // If pagination is not enabled, or combining is not requested, or there's only one response,
                // use the last response
                finalResponseBody = allResponses.get(allResponses.size() - 1);
                if (debugMode && allResponses.size() > 1) {
                    getLogger().info("Using last response (page {}) as final result", new Object[]{allResponses.size()});
                }
            } else {
                // If pagination is enabled and combining is requested, try to intelligently combine JSON results
                // if a pagination JSON path is provided
                if (paginationJsonPath != null && !paginationJsonPath.isEmpty() ) {
                    String combinedJson = combineJsonResults(allResponses, paginationJsonPath, debugMode);
                    if (combinedJson != null) {
                        finalResponseBody = combinedJson;
                        if (debugMode) {
                            getLogger().info("Combined {} pages using JSON path: {}",
                                    new Object[]{allResponses.size(), paginationJsonPath});
                        }
                    } else {
                        // If combining failed, use the last response
                        finalResponseBody = allResponses.get(allResponses.size() - 1);
                        if (debugMode) {
                            getLogger().warn("Failed to combine responses using JSON path: {}, using last response instead",
                                    new Object[]{paginationJsonPath});
                        }
                    }
                } else {
                    // If no pagination JSON path is provided, do a simple concatenation
                    StringBuilder combined = new StringBuilder();
                    for (int i = 0; i < allResponses.size(); i++) {
                        if (i > 0) combined.append("\n");
                        combined.append(allResponses.get(i));
                    }
                    finalResponseBody = combined.toString();
                    if (debugMode) {
                        getLogger().info("Combined {} responses by simple concatenation (no JSON path provided)",
                                new Object[]{allResponses.size()});
                    }
                }
            }

            // Write the final response body to the FlowFile
            resultFlowFile = session.write(resultFlowFile, new OutputStreamCallback() {
                @Override
                public void process(OutputStream outputStream) throws IOException {
                    outputStream.write(finalResponseBody.getBytes(StandardCharsets.UTF_8));
                }
            });

            // Add attributes to the result FlowFile
            final Map<String, String> attributes = new HashMap<>();
            // Add the original request attributes
            attributes.put("http.url", url);
            attributes.put("http.method", method);

            // Add the pagination attributes if enabled
            if (enablePagination) {
                attributes.put("http.pagination.enabled", "true");
                attributes.put("http.pagination.mode", paginationMode);
                attributes.put("http.pagination.pages.fetched", String.valueOf(allResponses.size()));
                attributes.put("http.pagination.results.combined", String.valueOf(combineResults));
                if (paginationJsonPath != null && !paginationJsonPath.isEmpty()) {
                    attributes.put("http.pagination.data.path", paginationJsonPath);
                }
            }

            resultFlowFile = session.putAllAttributes(resultFlowFile, attributes);

            // Route FlowFile to success
            session.transfer(resultFlowFile, REL_SUCCESS);
            if (debugMode) {
                getLogger().info("Transferred FlowFile to SUCCESS relationship");
            } else {
                getLogger().info("Successfully processed HTTP request to {} with pagination (fetched {} pages)",
                        new Object[]{url, allResponses.size()});
            }

            // If we created the original FlowFile (when there was no input) and we're not using it as the result,
            // remove it to avoid clutter
            if (createdFlowFile && resultFlowFile != flowFile) {
                session.remove(flowFile);
                if (debugMode) {
                    getLogger().info("Removed original FlowFile as it was created by the processor");
                }
            }
        } catch (IOException e) {
            // Network error occurred, send to retry
            if (debugMode) {
                getLogger().error("Network error while sending HTTP request to {}: {}", new Object[]{url, e.getMessage()}, e);
            } else {
                getLogger().error("Network error while sending HTTP request to {}: {}", new Object[]{url, e.getMessage()}, e);
            }
            session.transfer(flowFile, REL_RETRY);
        } catch (Exception e) {
            // Other errors, send to failure
            if (debugMode) {
                getLogger().error("Failed to send HTTP request to {}: {}", new Object[]{url, e.getMessage()}, e);
                getLogger().error("Stack trace:", e);
            } else {
                getLogger().error("Failed to send HTTP request to {}: {}", new Object[]{url, e.getMessage()}, e);
            }
            session.transfer(flowFile, REL_FAILURE);
        }
    }
}