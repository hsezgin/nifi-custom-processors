package org.sezgin.processors;

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
import java.util.concurrent.atomic.AtomicInteger;
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

    // Static block for SSL setup
    static {
        try {
            // Disable SSL validation at the JVM level
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, sslSession) -> true);

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) { }
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

    // Property Descriptors
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

    // Pagination properties
    public static final PropertyDescriptor ENABLE_PAGINATION = new PropertyDescriptor.Builder()
            .name("Enable Pagination")
            .description("Whether to automatically handle pagination in responses. Can also be set via FlowFile attribute 'http.pagination.enabled'")
            .required(false)
            .allowableValues("true", "false")
            .defaultValue("false")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    public static final PropertyDescriptor PAGINATION_MODE = new PropertyDescriptor.Builder()
            .name("Pagination Mode")
            .description("Type of pagination to handle. Can also be set via FlowFile attribute 'http.pagination.mode'")
            .required(false)
            .allowableValues("OData (@odata.nextLink)", "Custom")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    public static final PropertyDescriptor CUSTOM_NEXT_LINK_JSONPATH = new PropertyDescriptor.Builder()
            .name("Custom Next Link JSONPath")
            .description("JSONPath expression to extract the next link URL from the response. Example: '$.nextPage' or '$.pagination.next'. Can also be set via FlowFile attribute 'http.pagination.jsonpath'")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    public static final PropertyDescriptor MAX_PAGES = new PropertyDescriptor.Builder()
            .name("Maximum Pages")
            .description("Maximum number of pages to retrieve. Use 0 for unlimited (use with caution). Can also be set via FlowFile attribute 'http.pagination.max.pages'")
            .required(false)
            .defaultValue("10")
            .addValidator(StandardValidators.NON_NEGATIVE_INTEGER_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    public static final PropertyDescriptor COMBINE_RESULTS = new PropertyDescriptor.Builder()
            .name("Combine Results")
            .description("Whether to combine results from all pages into a single response. If enabled and Pagination JSON Path specified, will combine the data arrays from each page. Can also be set via FlowFile attribute 'http.pagination.combine'")
            .required(false)
            .allowableValues("true", "false")
            .defaultValue("false")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    public static final PropertyDescriptor PAGINATION_JSON_PATH = new PropertyDescriptor.Builder()
            .name("Pagination JSON Path")
            .description("When combining results, specifies the JSONPath to the array field in the response that contains the data items to be combined (e.g., 'value' for OData, 'items' for other APIs). Can also be set via FlowFile attribute 'http.pagination.data.path'")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .build();

    // Existing properties
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

    public static final PropertyDescriptor AUTH_TYPE = new PropertyDescriptor.Builder()
            .name("Authentication Type")
            .description("The type of authentication to use for HTTP requests")
            .required(false)
            .allowableValues(
                    "None",
                    "Basic Authentication",
                    "Bearer Token",
                    "API Key",
                    "Custom"
            )
            .defaultValue("None")
            .build();

    // Basic Auth
    public static final PropertyDescriptor BASIC_AUTH_USERNAME = new PropertyDescriptor.Builder()
            .name("Basic Auth Username")
            .description("Username for Basic Authentication. Used only when Authentication Type is 'Basic Authentication'.")
            .required(false)
            .sensitive(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor BASIC_AUTH_PASSWORD = new PropertyDescriptor.Builder()
            .name("Basic Auth Password")
            .description("Password for Basic Authentication. Used only when Authentication Type is 'Basic Authentication'.")
            .required(false)
            .sensitive(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    // Bearer Token
    public static final PropertyDescriptor BEARER_TOKEN = new PropertyDescriptor.Builder()
            .name("Bearer Token")
            .description("Token for Bearer authentication. Used only when Authentication Type is 'Bearer Token'.")
            .required(false)
            .sensitive(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    // API Key
    public static final PropertyDescriptor API_KEY = new PropertyDescriptor.Builder()
            .name("API Key")
            .description("API Key value. Used only when Authentication Type is 'API Key'.")
            .required(false)
            .sensitive(true)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor API_KEY_HEADER = new PropertyDescriptor.Builder()
            .name("API Key Header Name")
            .description("Header name for the API Key. Used only when Authentication Type is 'API Key'.")
            .required(false)
            .defaultValue("X-API-Key")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    // CUSTOM AUTH
    public static final PropertyDescriptor CUSTOM_AUTH_HEADER = new PropertyDescriptor.Builder()
            .name("Custom Auth Header Name")
            .description("Name of the custom authentication header. Used only when Authentication Type is 'Custom'.")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor CUSTOM_AUTH_VALUE = new PropertyDescriptor.Builder()
            .name("Custom Auth Header Value")
            .description("Value for the custom authentication header. Used only when Authentication Type is 'Custom'.")
            .required(false)
            .sensitive(true)
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
        descriptors.add(PAGINATION_JSON_PATH);
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
        // Kimlik doğrulama özellikleri
        descriptors.add(AUTH_TYPE);  // Kimlik doğrulama türü seçeneği
        descriptors.add(BASIC_AUTH_USERNAME);
        descriptors.add(BASIC_AUTH_PASSWORD);
        descriptors.add(BEARER_TOKEN);
        descriptors.add(API_KEY);
        descriptors.add(API_KEY_HEADER);
        descriptors.add(CUSTOM_AUTH_HEADER);
        descriptors.add(CUSTOM_AUTH_VALUE);
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

    @Override
    protected PropertyDescriptor getSupportedDynamicPropertyDescriptor(final String propertyDescriptorName) {
        // HTTP header support
        if (propertyDescriptorName.startsWith("http.header.")) {
            boolean isSensitiveHeader = propertyDescriptorName.equalsIgnoreCase("http.header.Authorization") ||
                    propertyDescriptorName.equalsIgnoreCase("http.header.X-API-Key");

            PropertyDescriptor.Builder builder = new PropertyDescriptor.Builder()
                    .name(propertyDescriptorName)
                    .displayName(propertyDescriptorName.substring("http.header.".length()) + " Header")
                    .description("HTTP Header: Sets the '" + propertyDescriptorName.substring("http.header.".length()) +
                            "' HTTP header value for the request")
                    .required(false)
                    .sensitive(true)
                    .dynamic(true)
                    .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES);

            return builder.addValidator(StandardValidators.NON_EMPTY_VALIDATOR).build();
        }

        return null;
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
            final int connectionTimeout = context.getProperty(CONNECTION_TIMEOUT).asInteger();
            final int maxPoolSize = context.getProperty(MAX_POOL_SIZE).asInteger();
            final boolean followRedirects = context.getProperty(FOLLOW_REDIRECTS).asBoolean();

            // Close existing HTTP client
            closeHttpClient();

            // Create an insecure HTTP client with SSL validation disabled
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
        // Add validation for method and URL
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
     * Process dynamic properties from ProcessContext and add them as headers to the request
     * @param request The HTTP request to add headers to
     * @param context The ProcessContext containing properties
     * @param flowFile The FlowFile for expression evaluation
     * @param debugMode Whether to log debug information
     * @return Number of headers added
     */
    private int processDynamicPropertiesAsHeaders(HttpRequestBase request, ProcessContext context,
                                                  FlowFile flowFile, boolean debugMode) {

        int headerCount = 0;
        StringBuilder debugHeaders = new StringBuilder();

        // Iterate through all properties to find dynamic ones
        for (Map.Entry<PropertyDescriptor, String> entry : context.getProperties().entrySet()) {
            PropertyDescriptor property = entry.getKey();

            if (property.isDynamic()) {
                String propertyName = property.getName();

                // Check if it's a header property
                if (propertyName.startsWith("http.header.")) {
                    String headerName = propertyName.substring("http.header.".length());

                    // Get the evaluated value using expression language
                    String headerValue = context.getProperty(property)
                            .evaluateAttributeExpressions(flowFile).getValue();

                    if (headerValue != null && !headerValue.isEmpty()) {
                        // Add header to request
                        request.addHeader(headerName, headerValue);
                        headerCount++;

                        // Log for debugging
                        if (debugMode) {
                            boolean isSensitive = property.isSensitive();
                            String logValue = isSensitive ? "********" : headerValue;
                            debugHeaders.append("  ").append(headerName).append(": ").append(logValue).append("\n");
                            getLogger().info("Added dynamic header: {} = {}", headerName, logValue);
                        }
                    }
                }
            }
        }

        if (debugMode && headerCount > 0) {
            getLogger().info("Added {} headers from dynamic properties:\n{}", headerCount, debugHeaders.toString());
        }

        return headerCount;
    }

    /**
     * Add FlowFile attributes as headers to the request
     */
    private void addHeadersToRequest(HttpRequestBase request, FlowFile flowFile, boolean addHeaders, boolean debugMode) {
        if (!addHeaders) {
            if (debugMode) {
                getLogger().info("Add Headers to Request is set to false - not adding any headers from FlowFile attributes");
            }
            return;
        }

        final AtomicInteger headerCount = new AtomicInteger(0);
        final StringBuilder debugHeaders = new StringBuilder();

        // Filter and add FlowFile attributes as headers
        flowFile.getAttributes().entrySet().stream()
                .filter(entry -> entry.getKey().startsWith("http.header."))
                .forEach(entry -> {
                    String headerName = entry.getKey().substring("http.header.".length());
                    String headerValue = entry.getValue();

                    // Skip headers that should be managed by the client
                    if (!headerName.equalsIgnoreCase("content-length") &&
                            !headerName.equalsIgnoreCase("transfer-encoding") &&
                            !headerName.equalsIgnoreCase("host")) {

                        request.addHeader(headerName, headerValue);
                        headerCount.incrementAndGet();

                        // Add to debug log
                        if (debugMode) {
                            boolean isSensitiveHeader = headerName.equalsIgnoreCase("Authorization") ||
                                    headerName.equalsIgnoreCase("X-API-Key") ||
                                    headerName.equalsIgnoreCase("api-key");

                            String logValue = isSensitiveHeader ? "********" : headerValue;
                            debugHeaders.append("  ").append(headerName).append(": ").append(logValue).append("\n");
                        }
                    }
                });

        // Log debug info
        if (debugMode) {
            if (headerCount.get() > 0) {
                getLogger().info("Added {} HTTP headers from FlowFile attributes:\n{}",
                        headerCount.get(), debugHeaders.toString());
            } else {
                getLogger().info("No HTTP headers found in FlowFile attributes");
            }
        }
    }

    /**
     * HTTP isteğine kimlik doğrulama başlıklarını ekler
     */
    private void addAuthenticationHeaders(HttpRequestBase request, ProcessContext context, FlowFile flowFile, boolean debugMode) {
        // Kimlik doğrulama türünü al
        final String authType = context.getProperty(AUTH_TYPE).getValue();

        // Kimlik doğrulama türüne göre işlem yap
        switch (authType) {
            case "Basic Authentication":
                addBasicAuthentication(request, context, flowFile, debugMode);
                break;
            case "Bearer Token":
                addBearerAuthentication(request, context, flowFile, debugMode);
                break;
            case "API Key":
                addApiKeyAuthentication(request, context, flowFile, debugMode);
                break;
            case "Custom":
                addCustomAuthentication(request, context, flowFile, debugMode);
                break;
            case "None":
            default:
                // Kimlik doğrulama yok, bir şey yapma
                break;
        }
    }

    /**
     * Basic Authentication header'ı ekler
     */
    private void addBasicAuthentication(HttpRequestBase request, ProcessContext context, FlowFile flowFile, boolean debugMode) {
        final String username = context.getProperty(BASIC_AUTH_USERNAME).evaluateAttributeExpressions(flowFile).getValue();
        final String password = context.getProperty(BASIC_AUTH_PASSWORD).evaluateAttributeExpressions(flowFile).getValue();

        if (username != null && !username.isEmpty() && password != null) {
            String auth = username + ":" + password;
            String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
            request.addHeader("Authorization", "Basic " + encodedAuth);

            if (debugMode) {
                getLogger().info("Added Basic Authentication header for user: {}", new Object[]{username});
            }
        } else if (debugMode) {
            getLogger().warn("Basic Authentication selected but username or password is missing");
        }
    }

    /**
     * Bearer Token header'ı ekler
     */
    private void addBearerAuthentication(HttpRequestBase request, ProcessContext context, FlowFile flowFile, boolean debugMode) {
        final String token = context.getProperty(BEARER_TOKEN).evaluateAttributeExpressions(flowFile).getValue();

        if (token != null && !token.isEmpty()) {
            request.addHeader("Authorization", "Bearer " + token);

            if (debugMode) {
                getLogger().info("Added Bearer token authentication");
            }
        } else if (debugMode) {
            getLogger().warn("Bearer Token Authentication selected but token is missing");
        }
    }

    /**
     * API Key header'ı ekler
     */
    private void addApiKeyAuthentication(HttpRequestBase request, ProcessContext context, FlowFile flowFile, boolean debugMode) {
        final String apiKey = context.getProperty(API_KEY).evaluateAttributeExpressions(flowFile).getValue();

        if (apiKey != null && !apiKey.isEmpty()) {
            String headerName = context.getProperty(API_KEY_HEADER).evaluateAttributeExpressions(flowFile).getValue();
            if (headerName == null || headerName.isEmpty()) {
                headerName = "X-API-Key"; // varsayılan header adı
            }

            request.addHeader(headerName, apiKey);

            if (debugMode) {
                getLogger().info("Added API Key authentication with header: {}", new Object[]{headerName});
            }
        } else if (debugMode) {
            getLogger().warn("API Key Authentication selected but API key is missing");
        }
    }

    /**
     * Özel kimlik doğrulama header'ı ekler
     */
    private void addCustomAuthentication(HttpRequestBase request, ProcessContext context, FlowFile flowFile, boolean debugMode) {
        final String headerName = context.getProperty(CUSTOM_AUTH_HEADER).evaluateAttributeExpressions(flowFile).getValue();
        final String headerValue = context.getProperty(CUSTOM_AUTH_VALUE).evaluateAttributeExpressions(flowFile).getValue();

        if (headerName != null && !headerName.isEmpty() && headerValue != null && !headerValue.isEmpty()) {
            request.addHeader(headerName, headerValue);

            if (debugMode) {
                getLogger().info("Added custom authentication header: {}", new Object[]{headerName});
            }
        } else if (debugMode) {
            getLogger().warn("Custom Authentication selected but header name or value is missing");
        }
    }

    /**
     * Log all FlowFile attributes for debugging
     */
    private void logFlowFileAttributes(FlowFile flowFile, boolean debugMode) {
        if (!debugMode) return;

        Map<String, String> attributes = flowFile.getAttributes();
        StringBuilder sb = new StringBuilder();
        sb.append("FlowFile Attributes:\n");

        attributes.forEach((key, value) -> {
            // Mask sensitive values
            boolean isSensitive = key.equals("http.header.Authorization") ||
                    key.equals("http.header.X-API-Key") ||
                    key.contains("password") ||
                    key.contains("secret") ||
                    key.contains("token");

            String logValue = isSensitive ? "********" : value;
            sb.append("  ").append(key).append(" = ").append(logValue).append("\n");
        });

        getLogger().info(sb.toString());
    }

    /**
     * Extract next link URL from the response based on pagination mode
     */
    private String extractNextLink(String responseBody, String paginationMode, String customJsonPath, boolean debugMode) {
        // Quick check if response is empty or null to avoid parsing
        if (responseBody == null || responseBody.isEmpty()) {
            return null;
        }

        try {
            // For OData pagination, try simple string search first for performance
            if ("OData (@odata.nextLink)".equals(paginationMode)) {
                // String search for OData nextLink - faster than parsing the entire JSON
                int nextLinkIndex = responseBody.indexOf("\"@odata.nextLink\"");
                if (nextLinkIndex >= 0) {
                    // Found the nextLink field, extract the URL
                    int valueStart = responseBody.indexOf('"', nextLinkIndex + 18) + 1; // Skip field name and colon
                    if (valueStart > 0) {
                        int valueEnd = responseBody.indexOf('"', valueStart);
                        if (valueEnd > valueStart) {
                            String nextLink = responseBody.substring(valueStart, valueEnd);
                            if (debugMode) {
                                getLogger().info("Found OData next link using string search: {}", nextLink);
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
                        getLogger().info("Found OData next link using JSON parsing: {}", nextLink);
                    }
                    return nextLink;
                }
            } else if ("Custom".equals(paginationMode) && customJsonPath != null && !customJsonPath.isEmpty()) {
                // Custom pagination - use the provided JSONPath

                // For simple paths, try string search first
                if (customJsonPath.startsWith("$.")) {
                    String path = customJsonPath.substring(2); // Remove the $. prefix
                    String[] parts = path.split("\\.");

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
                                        getLogger().info("Found custom next link using string search: {}", nextLink);
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
                            getLogger().info("Found custom next link using JSON path: {}", nextLink);
                        }
                        return nextLink;
                    }
                }
            }
        } catch (Exception e) {
            getLogger().warn("Failed to extract next link from response: {}", e.getMessage());
            if (debugMode) {
                getLogger().warn("Exception details:", e);
            }
        }

        // No next link found or error occurred
        return null;
    }

    /**
     * Combine paginated results into a single response with JSON data arrays combined
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

            // Handle path without the $. prefix
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
                    getLogger().warn("Data field '{}' not found or is not an array in response", paginationJsonPath);
                }
                return null;
            }

            // Create a combined response based on the first response
            ObjectNode combinedResponse = (ObjectNode) objectMapper.readTree(allResponses.get(0));

            // Create a new array for the combined data
            ArrayNode combinedDataArray = objectMapper.createArrayNode();

            // Add all items from first page's data array
            dataNode.forEach(combinedDataArray::add);

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
                        pageDataNode.forEach(combinedDataArray::add);

                        if (debugMode) {
                            getLogger().debug("Added {} items from page {}",
                                    pageDataNode.size(), i + 1);
                        }
                    }
                } catch (Exception e) {
                    getLogger().warn("Failed to process page {}: {}", i + 1, e.getMessage());
                    if (debugMode) {
                        getLogger().warn("Exception details:", e);
                    }
                }
            }

            // Set the combined data array back to the response
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
                            getLogger().warn("Cannot navigate to parent of data field '{}'", paginationJsonPath);
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
                        allResponses.size(), combinedDataArray.size(), paginationJsonPath);
            }

            // Convert the combined response to string
            return objectMapper.writeValueAsString(combinedResponse);

        } catch (Exception e) {
            getLogger().error("Failed to combine paginated results: {}", e.getMessage());
            if (debugMode) {
                getLogger().error("Exception details:", e);
            }
            return null;
        }
    }

    /**
     * Get pagination settings from FlowFile attributes or processor properties
     */
    private Map<String, Object> getPaginationSettings(ProcessContext context, FlowFile flowFile, boolean debugMode) {
        Map<String, Object> settings = new HashMap<>();

        // Enable Pagination setting
        String enablePaginationStr = flowFile.getAttribute("http.pagination.enabled");
        if (enablePaginationStr == null) {
            PropertyValue propertyValue = context.getProperty(ENABLE_PAGINATION);
            if (propertyValue != null) {
                enablePaginationStr = propertyValue.evaluateAttributeExpressions(flowFile).getValue();
            }
        }

        // Default is pagination disabled
        boolean enablePagination = "true".equalsIgnoreCase(enablePaginationStr);
        settings.put("enablePagination", enablePagination);

        // Pagination Mode (default "OData (@odata.nextLink)")
        String paginationMode = "OData (@odata.nextLink)";
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

        // Custom JSONPath (default empty string)
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

        // Pagination JSON Path (default "value" for OData)
        String paginationJsonPath = "value"; // Default for OData
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
                // If not OData and no custom value, use empty string
                paginationJsonPath = "";
            }
        }
        settings.put("paginationJsonPath", paginationJsonPath);

        // Max Pages (default 10)
        int maxPages = 10;
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
                    getLogger().warn("Invalid max pages value: {}, using default (10)", maxPagesStr);
                }
            }
        }
        settings.put("maxPages", maxPages);

        // Combine Results (default false)
        boolean combineResults = false;
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

        if (debugMode && enablePagination) {
            getLogger().info("Using pagination settings: enabled={}, mode={}, jsonPath={}, maxPages={}, combine={}",
                    enablePagination, paginationMode, paginationJsonPath, maxPages, combineResults);
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
                session.transfer(flowFile, REL_FAILURE);
                return;
            }
        }

        // Get pagination settings
        Map<String, Object> paginationSettings = getPaginationSettings(context, flowFile, debugMode);
        final boolean enablePagination = (boolean) paginationSettings.get("enablePagination");
        final String paginationMode = (String) paginationSettings.get("paginationMode");
        final String customJsonPath = (String) paginationSettings.get("customJsonPath");
        final String paginationJsonPath = (String) paginationSettings.get("paginationJsonPath");
        final int maxPages = (int) paginationSettings.get("maxPages");
        final boolean combineResults = (boolean) paginationSettings.get("combineResults");

        // Get request properties
        String url;
        String method;
        String contentType;
        boolean addHeaders;
        String successCodesValue;

        try {
            // Try to get URL from property or attribute
            String propertyUrl = context.getProperty(URL).evaluateAttributeExpressions(flowFile).getValue();
            String attributeUrl = flowFile.getAttribute("http.url");

            if (propertyUrl != null && !propertyUrl.trim().isEmpty()) {
                url = propertyUrl.trim();
                if (debugMode) {
                    getLogger().info("Using URL from processor property: {}", url);
                }
            } else if (attributeUrl != null && !attributeUrl.trim().isEmpty()) {
                url = attributeUrl.trim();
                if (debugMode) {
                    getLogger().info("Using URL from FlowFile attribute: {}", url);
                }
            } else {
                getLogger().error("No URL provided. URL property is not set and FlowFile does not contain 'http.url' attribute");
                session.transfer(flowFile, REL_FAILURE);
                return;
            }

            // Validate URL format
            if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://")) {
                getLogger().error("URL must start with http:// or https://: {}", url);
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

            if (debugMode) {
                getLogger().info("Add Headers to Request is set to: {}", addHeaders);
            }

            successCodesValue = context.getProperty(SUCCESS_CODES).evaluateAttributeExpressions(flowFile).getValue();

        } catch (Exception e) {
            getLogger().error("Failed to evaluate request properties: {}", e.getMessage(), e);
            session.transfer(flowFile, REL_FAILURE);
            return;
        }

        try {
            // For pagination support, store all responses
            List<String> allResponses = new ArrayList<>();
            String currentUrl = url;
            int pageCount = 0;
            boolean hasMorePages = true;

            // For tracking response status across pages
            int finalStatusCode = 0;
            String finalReasonPhrase = "";
            Map<String, String> finalResponseHeaders = new HashMap<>();
            long totalResponseTime = 0;

            // Make initial request and follow pagination links if enabled
            while (hasMorePages && (maxPages == 0 || pageCount < maxPages)) {
                if (debugMode && pageCount > 0) {
                    getLogger().info("Fetching page {} with URL: {}", pageCount + 1, currentUrl);
                }

                // Create HTTP request
                HttpRequestBase request;
                try {
                    if (debugMode) {
                        getLogger().info("Creating HTTP {} request to URL: {}", method, currentUrl);
                    }

                    request = createHttpRequest(method, currentUrl);

                    if (debugMode) {
                        getLogger().info("Successfully created HTTP request");
                    }
                } catch (Exception e) {
                    getLogger().error("Failed to create HTTP request: {}", e.getMessage(), e);
                    session.transfer(flowFile, REL_FAILURE);
                    return;
                }

                // Add authentication headers first
                addAuthenticationHeaders(request, context, flowFile, debugMode);

                // Then add dynamic property headers
                int dynamicHeadersAdded = processDynamicPropertiesAsHeaders(request, context, flowFile, debugMode);

                // Then add headers from FlowFile attributes (if enabled and it's the first page)
                if (pageCount == 0) {
                    addHeadersToRequest(request, flowFile, addHeaders, debugMode);

                    if (debugMode) {
                        // Log all request headers for verification
                        StringBuilder allHeaders = new StringBuilder("Final request headers:\n");
                        for (org.apache.http.Header header : request.getAllHeaders()) {
                            // Mask sensitive headers
                            String headerName = header.getName();
                            String headerValue = header.getValue();
                            boolean isSensitive = headerName.equalsIgnoreCase("Authorization") ||
                                    headerName.equalsIgnoreCase("X-API-Key") ||
                                    headerName.equalsIgnoreCase("api-key");
                            String logValue = isSensitive ? "********" : headerValue;

                            allHeaders.append("  ").append(headerName).append(": ").append(logValue).append("\n");
                        }
                        getLogger().info(allHeaders.toString());
                    }
                }

                // For methods that require a body, set request entity (only for first page)
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

                        // Set entity with appropriate content type
                        ContentType requestContentType = ContentType.parse(contentType);
                        entityRequest.setEntity(new StringEntity(new String(content, StandardCharsets.UTF_8), requestContentType));

                        if (debugMode) {
                            getLogger().info("Set request entity from FlowFile content with Content-Type: {}", contentType);
                            // Log content preview (limited length)
                            String contentPreview = new String(content, StandardCharsets.UTF_8);
                            if (contentPreview.length() > 1000) {
                                contentPreview = contentPreview.substring(0, 1000) + "... (truncated)";
                            }
                            getLogger().info("Request body: {}", contentPreview);
                        }
                    } else {
                        // Empty entity for methods that require a body
                        entityRequest.setEntity(new StringEntity("", ContentType.parse(contentType)));

                        if (debugMode) {
                            getLogger().info("Set empty request entity with Content-Type: {}", contentType);
                        }
                    }
                }

                // Send request and get response
                long startNanos = System.nanoTime();

                if (debugMode) {
                    getLogger().info("Sending {} request to {}", method, currentUrl);
                }

                // Response variables
                String responseBody = null;
                int statusCode = 0;
                String reasonPhrase = null;
                Map<String, String> responseHeaders = new HashMap<>();
                long responseTime = 0;

                try (CloseableHttpResponse response = httpClient.execute(request)) {
                    statusCode = response.getStatusLine().getStatusCode();
                    reasonPhrase = response.getStatusLine().getReasonPhrase();
                    responseTime = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);

                    // Save the status code of the first or last response (for pagination)
                    if (pageCount == 0 || !hasMorePages) {
                        finalStatusCode = statusCode;
                        finalReasonPhrase = reasonPhrase;
                    }

                    // Accumulate response time
                    totalResponseTime += responseTime;

                    getLogger().info("Received HTTP response: status={}, reason={}, time={}ms",
                            statusCode, reasonPhrase, responseTime);

                    // Get response headers
                    if (response.getAllHeaders() != null) {
                        for (org.apache.http.Header header : response.getAllHeaders()) {
                            String headerName = header.getName().toLowerCase();
                            String headerValue = header.getValue();
                            responseHeaders.put(headerName, headerValue);

                            if (debugMode) {
                                getLogger().info("Response header: {} = {}", headerName, headerValue);
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
                                // Handle exact match
                                isSuccess = true;
                                break;
                            }
                        }
                    } else {
                        // Default: 2xx is success
                        isSuccess = statusCode >= 200 && statusCode < 300;
                    }

                    // If error status code, stop pagination
                    if (!isSuccess) {
                        if (debugMode) {
                            getLogger().warn("Received non-success status code: {}. Stopping pagination.", statusCode);
                        }

                        // Read error response body
                        if (response.getEntity() != null) {
                            responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                            getLogger().warn("Error response body: {}", responseBody);
                        }
                        break;
                    }

                    // Get response body
                    if (response.getEntity() != null) {
                        responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

                        if (debugMode) {
                            // Log preview of response body
                            String responseBodyPreview = responseBody;
                            if (responseBody.length() > 1000) {
                                responseBodyPreview = responseBodyPreview.substring(0, 1000) + "... (truncated)";
                            }
                            getLogger().info("Response body: {}", responseBodyPreview);
                        }

                        // Add the response to all responses for pagination
                        allResponses.add(responseBody);
                    } else {
                        // No response body
                        responseBody = "";
                        allResponses.add(responseBody);
                    }

                    // Handle pagination if enabled
                    if (enablePagination && responseBody != null && !responseBody.isEmpty()) {
                        // Extract next link from response
                        String nextLink = extractNextLink(responseBody, paginationMode, customJsonPath, debugMode);

                        if (nextLink != null && !nextLink.isEmpty()) {
                            // Use the next link for the next request
                            currentUrl = nextLink;
                            pageCount++;
                        } else {// No more pages
                            hasMorePages = false;
                        }
                    } else {
                        // Pagination not enabled or no response body
                        hasMorePages = false;
                    }
                }

                // Release request resources
                request.releaseConnection();

                // Stop pagination if reached max pages
                if (maxPages > 0 && pageCount >= maxPages) {
                    hasMorePages = false;
                }
            } // End pagination loop

            // Create the final FlowFile with response content
            FlowFile resultFlowFile;
            if (createdFlowFile) {
                // Create new FlowFile for result
                resultFlowFile = session.create();
                if (debugMode) {
                    getLogger().info("Created new result FlowFile");
                }
            } else {
                // Use the incoming FlowFile as result
                resultFlowFile = flowFile;
                if (debugMode) {
                    getLogger().info("Using incoming FlowFile as result FlowFile");
                }
            }

            // Determine which response to use for the final result
            final String finalResponseBody;
            if (allResponses.isEmpty()) {
                finalResponseBody = "";
                if (debugMode) {
                    getLogger().warn("No responses received");
                }
            } else if (!enablePagination || !combineResults || allResponses.size() == 1) {
                // Use the last response if pagination not enabled, combining not requested, or only one response
                finalResponseBody = allResponses.get(allResponses.size() - 1);
                if (debugMode && allResponses.size() > 1) {
                    getLogger().info("Using last response (page {}) as final result", allResponses.size());
                }
            } else {
                // Try to combine results if pagination is enabled and combining is requested
                if (paginationJsonPath != null && !paginationJsonPath.isEmpty()) {
                    String combinedJson = combineJsonResults(allResponses, paginationJsonPath, debugMode);
                    if (combinedJson != null) {
                        finalResponseBody = combinedJson;
                        if (debugMode) {
                            getLogger().info("Combined {} pages using JSON path: {}",
                                    allResponses.size(), paginationJsonPath);
                        }
                    } else {
                        // If combining failed, use the last response
                        finalResponseBody = allResponses.get(allResponses.size() - 1);
                        if (debugMode) {
                            getLogger().warn("Failed to combine responses using JSON path: {}, using last response",
                                    paginationJsonPath);
                        }
                    }
                } else {
                    // Simple concatenation if no JSON path provided
                    StringBuilder combined = new StringBuilder();
                    for (int i = 0; i < allResponses.size(); i++) {
                        if (i > 0) combined.append("\n");
                        combined.append(allResponses.get(i));
                    }
                    finalResponseBody = combined.toString();
                    if (debugMode) {
                        getLogger().info("Combined {} responses by simple concatenation", allResponses.size());
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

            // Add the HTTP response status information
            attributes.put("http.status.code", String.valueOf(finalStatusCode));
            attributes.put("http.status.message", finalReasonPhrase);
            attributes.put("http.response.time", String.valueOf(totalResponseTime));

            // Add content-type if available
            if (finalResponseHeaders.containsKey("content-type")) {
                attributes.put("http.content.type", finalResponseHeaders.get("content-type"));
            }

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
                        url, allResponses.size());
            }

            // Clean up
            if (createdFlowFile && resultFlowFile != flowFile) {
                session.remove(flowFile);
                if (debugMode) {
                    getLogger().info("Removed original FlowFile as it was created by the processor");
                }
            }
        } catch (IOException e) {
            // Network error occurred, send to retry
            flowFile = session.putAttribute(flowFile, "http.error.message", e.getMessage());
            flowFile = session.putAttribute(flowFile, "http.status.code", "-1"); // Indicate network error with -1
            getLogger().error("Network error while sending HTTP request to {}: {}", url, e.getMessage());
            if (debugMode) {
                getLogger().error("Network error details:", e);
            }
            session.transfer(flowFile, REL_RETRY);
        } catch (Exception e) {
            // Other errors, send to failure
            flowFile = session.putAttribute(flowFile, "http.error.message", e.getMessage());
            flowFile = session.putAttribute(flowFile, "http.status.code", "-2"); // Indicate general error with -2
            getLogger().error("Failed to send HTTP request to {}: {}", url, e.getMessage());
            if (debugMode) {
                getLogger().error("Error details:", e);
            }
            session.transfer(flowFile, REL_FAILURE);
        }
    }
}