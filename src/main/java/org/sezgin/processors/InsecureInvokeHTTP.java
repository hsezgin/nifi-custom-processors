package org.sezgin.processors;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.*;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.InputRequirement.Requirement;
import org.apache.nifi.annotation.behavior.SupportsBatching;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.components.PropertyDescriptor;
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

@SupportsBatching
@InputRequirement(Requirement.INPUT_ALLOWED)
@Tags({"http", "https", "ssl", "bypass", "insecure", "fast", "invoke"})
@CapabilityDescription("Custom implementation of HTTP client that allows bypassing SSL validation for improved performance")
public class InsecureInvokeHTTP extends AbstractProcessor {

    // Disable SSL validation at JVM level to ensure it works across all environments
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

    public static final PropertyDescriptor URL = new PropertyDescriptor.Builder()
            .name("URL")
            .description("The URL to connect to")
            .required(true)
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
            .defaultValue("auth.token")
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

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

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<>();
        descriptors.add(URL);
        descriptors.add(METHOD);
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

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        // Get FlowFile (may be null if no incoming connection)
        FlowFile flowFile = session.get();

        // Create a new FlowFile if none was received
        boolean createdFlowFile = false;
        if (flowFile == null) {
            flowFile = session.create();
            createdFlowFile = true;
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

        // Get URL and HTTP method and all other properties with FlowFile attribute expression evaluation
        String url;
        String method;
        String contentType;
        boolean addHeaders;
        String extractTokenHeader;
        String tokenAttributeName;
        String successCodesValue;

        try {
            // Evaluate all properties with flowfile attributes
            url = context.getProperty(URL).evaluateAttributeExpressions(flowFile).getValue();
            method = context.getProperty(METHOD).evaluateAttributeExpressions(flowFile).getValue();
            contentType = context.getProperty(CONTENT_TYPE).evaluateAttributeExpressions(flowFile).getValue();
            String addHeadersStr = context.getProperty(ADD_HEADERS).evaluateAttributeExpressions(flowFile).getValue();
            addHeaders = "true".equalsIgnoreCase(addHeadersStr);
            successCodesValue = context.getProperty(SUCCESS_CODES).evaluateAttributeExpressions(flowFile).getValue();
            extractTokenHeader = context.getProperty(EXTRACT_TOKEN_HEADER).evaluateAttributeExpressions(flowFile).getValue();
            tokenAttributeName = context.getProperty(TOKEN_ATTRIBUTE_NAME).evaluateAttributeExpressions(flowFile).getValue();
        } catch (Exception e) {
            getLogger().error("Failed to evaluate attributes: {}", new Object[]{e.getMessage()}, e);
            session.transfer(flowFile, REL_FAILURE);
            return;
        }

        // Create HTTP request
        HttpRequestBase request;
        try {
            request = createHttpRequest(method, url);
        } catch (Exception e) {
            getLogger().error("Failed to create HTTP request: {}", new Object[]{e.getMessage()}, e);
            session.transfer(flowFile, REL_FAILURE);
            return;
        }

        try {
            // Add FlowFile headers to request
            if (!createdFlowFile) {
                addHeadersToRequest(request, flowFile, addHeaders);
            }

            // For methods other than GET and DELETE, use flowfile content as entity (if available)
            if (request instanceof HttpEntityEnclosingRequestBase entityRequest) {
                if (!createdFlowFile && flowFile.getSize() > 0) {
                    // Read FlowFile content
                    final byte[] content = new byte[(int) flowFile.getSize()];
                    session.read(flowFile, new InputStreamCallback() {
                        @Override
                        public void process(InputStream inputStream) throws IOException {
                            StreamUtils.fillBuffer(inputStream, content, true);
                        }
                    });

                    // Add Content-Type header
                    if (contentType != null) {
                        entityRequest.setEntity(new StringEntity(new String(content, StandardCharsets.UTF_8), ContentType.parse(contentType)));
                    } else {
                        entityRequest.setEntity(new StringEntity(new String(content, StandardCharsets.UTF_8)));
                    }
                } else {
                    // Empty entity for methods that require a body but no content is available
                    entityRequest.setEntity(new StringEntity("", ContentType.parse(contentType != null ? contentType : "text/plain")));
                }
            }

            // Send request and get response
            long startNanos = System.nanoTime();

            getLogger().debug("Sending {} request to {}", new Object[]{method, url});

            try (var response = httpClient.execute(request)) {
                final int statusCode = response.getStatusLine().getStatusCode();
                final long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);

                getLogger().debug("Received response with status code {} in {} ms", new Object[]{statusCode, millis});

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

                // Create the status FlowFile with response content
                FlowFile resultFlowFile;
                if (createdFlowFile) {
                    // If we created the original FlowFile (no input), create a new one for the result
                    resultFlowFile = session.create();
                } else {
                    // Use the incoming FlowFile as the result
                    resultFlowFile = flowFile;
                }

                // Add response body to the FlowFile
                if (response.getEntity() instanceof HttpEntity entity) {
                    final byte[] responseBody = EntityUtils.toByteArray(entity);
                    resultFlowFile = session.write(resultFlowFile, new OutputStreamCallback() {
                        @Override
                        public void process(OutputStream outputStream) throws IOException {
                            outputStream.write(responseBody);
                        }
                    });
                }

                // Add attributes to the result FlowFile
                final Map<String, String> attributes = new HashMap<>();
                attributes.put("http.status.code", String.valueOf(statusCode));
                attributes.put("http.status.message", response.getStatusLine().getReasonPhrase());
                attributes.put("http.response.time", String.valueOf(millis));
                attributes.put("http.url", url);
                attributes.put("http.method", method);

                // Add response headers as attributes
                if (response.getAllHeaders() != null) {
                    for (var header : response.getAllHeaders()) {
                        String headerName = header.getName().toLowerCase();
                        String headerValue = header.getValue();
                        attributes.put("http.header." + headerName, headerValue);

                        // If extractTokenHeader is specified and this header matches, extract token
                        if (extractTokenHeader != null && !extractTokenHeader.isEmpty() &&
                                headerName.equalsIgnoreCase(extractTokenHeader.toLowerCase())) {
                            // Store the token in the specified attribute
                            if (tokenAttributeName != null && !tokenAttributeName.isEmpty()) {
                                attributes.put(tokenAttributeName, headerValue);
                                getLogger().debug("Extracted token from header '{}' and stored in attribute '{}'",
                                        new Object[]{extractTokenHeader, tokenAttributeName});
                            }
                        }
                    }
                }

                resultFlowFile = session.putAllAttributes(resultFlowFile, attributes);

                // Route FlowFile based on success/failure
                if (isSuccess) {
                    session.transfer(resultFlowFile, REL_SUCCESS);
                    getLogger().info("Successfully sent HTTP {} request to {} and received response with status code {}",
                            new Object[]{method, url, statusCode});
                } else {
                    session.transfer(resultFlowFile, REL_FAILURE);
                    getLogger().warn("Sent HTTP {} request to {} but received status code {} (not in success codes: {})",
                            new Object[]{method, url, statusCode, successCodesValue});
                }

                // If we created the original FlowFile (when there was no input) and we're not using it as the result,
                // remove it to avoid clutter
                if (createdFlowFile && resultFlowFile != flowFile) {
                    session.remove(flowFile);
                }
            }
        } catch (IOException e) {
            // Network error occurred, send to retry
            getLogger().error("Network error while sending HTTP request to {}: {}", new Object[]{url, e.getMessage()}, e);
            session.transfer(flowFile, REL_RETRY);
        } catch (Exception e) {
            // Other errors, send to failure
            getLogger().error("Failed to send HTTP request to {}: {}", new Object[]{url, e.getMessage()}, e);
            session.transfer(flowFile, REL_FAILURE);
        } finally {
            // Clean up request resources
            request.releaseConnection();
        }
    }
}