package org.sezgin.processors;

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

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.*;
import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

@SupportsBatching
@InputRequirement(Requirement.INPUT_ALLOWED)
@Tags({"ldap", "directory", "authentication", "crud", "ssl", "bypass", "insecure"})
@CapabilityDescription("Custom implementation of LDAP client that allows CRUD operations on LDAP directories with optional SSL validation bypass")
public class InsecureLDAPProcessor extends AbstractProcessor {

    // Static block for SSL setup
    static {
        try {
            // Disable SSL validation at the JVM level for LDAP connections
            TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());

            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            SSLContext.setDefault(sc);

            // Disable hostname verification
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

            // Also disable SSL-related security properties
            System.setProperty("com.sun.jndi.ldap.object.disableEndpointIdentification", "true");

        } catch (Exception e) {
            System.err.println("Failed to disable SSL validation for LDAP: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Property Descriptors
    public static final PropertyDescriptor LDAP_URL = new PropertyDescriptor.Builder()
            .name("LDAP URL")
            .description("The URL of the LDAP server. Format: ldap://hostname:port or ldaps://hostname:port")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor LDAP_OPERATION = new PropertyDescriptor.Builder()
            .name("LDAP Operation")
            .description("The LDAP operation to perform")
            .required(true)
            .allowableValues("SEARCH", "ADD", "MODIFY", "DELETE", "BIND", "UNBIND")
            .defaultValue("SEARCH")
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .build();

    public static final PropertyDescriptor BASE_DN = new PropertyDescriptor.Builder()
            .name("Base DN")
            .description("The base DN for LDAP operations")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor SEARCH_FILTER = new PropertyDescriptor.Builder()
            .name("Search Filter")
            .description("The filter to use for LDAP search operations (e.g., (objectClass=person))")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor SEARCH_SCOPE = new PropertyDescriptor.Builder()
            .name("Search Scope")
            .description("The scope for LDAP search operations")
            .required(false)
            .allowableValues("OBJECT_SCOPE", "ONELEVEL_SCOPE", "SUBTREE_SCOPE")
            .defaultValue("SUBTREE_SCOPE")
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .build();

    public static final PropertyDescriptor RETURN_ATTRIBUTES = new PropertyDescriptor.Builder()
            .name("Return Attributes")
            .description("Comma-separated list of attributes to return in search results. Leave blank for all attributes.")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .addValidator(StandardValidators.NON_BLANK_VALIDATOR)
            .build();

    public static final PropertyDescriptor BINARY_ATTRIBUTES = new PropertyDescriptor.Builder()
            .name("Binary Attributes")
            .description("Comma-separated list of LDAP attributes that should be treated as binary data and " +
                    "converted to readable format (objectGUID to UUID, objectSid to SID string, etc). " +
                    "Example: objectGUID,objectSid,nTSecurityDescriptor")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor USERNAME = new PropertyDescriptor.Builder()
            .name("Bind DN")
            .description("The username (DN) to bind to the LDAP server")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .sensitive(false)
            .build();

    public static final PropertyDescriptor PASSWORD = new PropertyDescriptor.Builder()
            .name("Bind Password")
            .description("The password to use when binding to the LDAP server")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .sensitive(true)
            .build();

    public static final PropertyDescriptor PAGE_SIZE = new PropertyDescriptor.Builder()
            .name("Page Size")
            .description("The page size to use for paged LDAP search operations. Set to 0 to disable paging.")
            .required(false)
            .defaultValue("1000")
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .addValidator(StandardValidators.NON_NEGATIVE_INTEGER_VALIDATOR)
            .build();

    public static final PropertyDescriptor CONNECTION_TIMEOUT = new PropertyDescriptor.Builder()
            .name("Connection Timeout")
            .description("Maximum time allowed for connection to LDAP server (in milliseconds)")
            .required(true)
            .defaultValue("5000")
            .addValidator(StandardValidators.POSITIVE_INTEGER_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .build();

    public static final PropertyDescriptor READ_TIMEOUT = new PropertyDescriptor.Builder()
            .name("Read Timeout")
            .description("Maximum time allowed for LDAP operations to complete (in milliseconds)")
            .required(true)
            .defaultValue("30000")
            .addValidator(StandardValidators.POSITIVE_INTEGER_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .build();

    public static final PropertyDescriptor BYPASS_SSL_VALIDATION = new PropertyDescriptor.Builder()
            .name("Bypass SSL Validation")
            .description("Whether to bypass SSL certificate validation for LDAPS connections")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("false")
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .build();

    public static final PropertyDescriptor REFERRAL_HANDLING = new PropertyDescriptor.Builder()
            .name("Referral Handling")
            .description("How to handle LDAP referrals")
            .required(true)
            .allowableValues("follow", "ignore", "throw")
            .defaultValue("ignore")
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .build();

    public static final PropertyDescriptor DEBUG_MODE = new PropertyDescriptor.Builder()
            .name("Debug Mode")
            .description("Enable/disable debug mode with extensive logging")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("false")
            .build();

    public static final PropertyDescriptor OUTPUT_FORMAT = new PropertyDescriptor.Builder()
            .name("Output Format")
            .description("The format of the output data")
            .required(true)
            .allowableValues("JSON", "LDIF")
            .defaultValue("JSON")
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .build();

    // Yeni eklenen LDAP Kontrol Desteği özellikleri
    public static final PropertyDescriptor LDAP_CONTROLS = new PropertyDescriptor.Builder()
            .name("LDAP Controls")
            .description("Comma-separated list of LDAP controls to send with requests. Format: OID|critical|value " +
                    "Example: 1.2.840.113556.1.4.801|true|7 for SD Flags control. " +
                    "Value can be decimal, hex (0x prefix), or empty. " +
                    "For complex controls, leave value empty and use Control Value Format property.")
            .required(false)
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor CONTROL_VALUE_FORMAT = new PropertyDescriptor.Builder()
            .name("Control Value Format")
            .description("Format of the control value(s). For simple values, leave blank. " +
                    "Options: empty, int8, hex, ber. " +
                    "For ber, the value is a hex string representing BER encoded data.")
            .required(false)
            .allowableValues("", "int8", "hex", "ber")
            .defaultValue("")
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .build();

    // Relationships
    public static final Relationship REL_SUCCESS = new Relationship.Builder()
            .name("success")
            .description("All FlowFiles that are successfully processed are routed to this relationship")
            .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("failure")
            .description("All FlowFiles that fail to be processed are routed to this relationship")
            .build();

    private List<PropertyDescriptor> descriptors;
    private Set<Relationship> relationships;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<>();
        descriptors.add(LDAP_URL);
        descriptors.add(LDAP_OPERATION);
        descriptors.add(BASE_DN);
        descriptors.add(SEARCH_FILTER);
        descriptors.add(SEARCH_SCOPE);
        descriptors.add(RETURN_ATTRIBUTES);
        descriptors.add(BINARY_ATTRIBUTES);
        descriptors.add(USERNAME);
        descriptors.add(PASSWORD);
        descriptors.add(PAGE_SIZE);
        descriptors.add(CONNECTION_TIMEOUT);
        descriptors.add(READ_TIMEOUT);
        descriptors.add(BYPASS_SSL_VALIDATION);
        descriptors.add(REFERRAL_HANDLING);
        descriptors.add(DEBUG_MODE);
        descriptors.add(OUTPUT_FORMAT);
        // Yeni LDAP Kontrol özellikleri eklendi
        descriptors.add(LDAP_CONTROLS);
        descriptors.add(CONTROL_VALUE_FORMAT);
        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<>();
        relationships.add(REL_SUCCESS);
        relationships.add(REL_FAILURE);
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
     * LDAP kontrol listesini ayrıştırıp oluşturan yardımcı metot
     */
    private Control[] parseAndCreateLdapControls(String controlsConfig, String valueFormat, boolean debugMode) {
        if (controlsConfig == null || controlsConfig.trim().isEmpty()) {
            return null;
        }

        List<Control> controls = new ArrayList<>();
        String[] controlConfigs = controlsConfig.split(",");

        for (String controlConfig : controlConfigs) {
            controlConfig = controlConfig.trim();
            if (controlConfig.isEmpty()) {
                continue;
            }

            try {
                // OID|critical|value formatını ayrıştır
                String[] parts = controlConfig.split("\\|");
                if (parts.length < 2) {
                    getLogger().warn("Invalid control format: {}, expected OID|critical|value", new Object[]{controlConfig});
                    continue;
                }

                String oid = parts[0].trim();
                boolean critical = Boolean.parseBoolean(parts[1].trim());
                String valueStr = parts.length > 2 ? parts[2].trim() : "";

                // Kontrol değerini formatına göre dönüştür
                byte[] value = null;
                if (!valueStr.isEmpty()) {
                    if ("int8".equals(valueFormat)) {
                        // Tek bayt değeri
                        int intValue = valueStr.startsWith("0x")
                                ? Integer.parseInt(valueStr.substring(2), 16)
                                : Integer.parseInt(valueStr);
                        value = new byte[]{(byte) intValue};
                    } else if ("hex".equals(valueFormat)) {
                        // Hex değer
                        String hexStr = valueStr.startsWith("0x") ? valueStr.substring(2) : valueStr;
                        value = hexStringToByteArray(hexStr);
                    } else if ("ber".equals(valueFormat)) {
                        // BER kodlanmış değer
                        String hexStr = valueStr.startsWith("0x") ? valueStr.substring(2) : valueStr;
                        value = hexStringToByteArray(hexStr);
                    } else {
                        // Standart SD Flags için otomatik BER formatı oluştur
                        if (oid.equals("1.2.840.113556.1.4.801")) {
                            int intValue = valueStr.startsWith("0x")
                                    ? Integer.parseInt(valueStr.substring(2), 16)
                                    : Integer.parseInt(valueStr);
                            // 0x30 = SEQUENCE, 0x03 = length, 0x02 = INTEGER, 0x01 = length, son bayt = değer
                            value = new byte[]{0x30, 0x03, 0x02, 0x01, (byte) intValue};
                        } else {
                            // Değer bir tamsayı olarak değerlendir
                            try {
                                int intValue = valueStr.startsWith("0x")
                                        ? Integer.parseInt(valueStr.substring(2), 16)
                                        : Integer.parseInt(valueStr);
                                value = new byte[]{(byte) intValue};
                            } catch (NumberFormatException e) {
                                getLogger().warn("Invalid control value: {}, expected number or hex", new Object[]{valueStr});
                            }
                        }
                    }
                }

                // Kontrol nesnesini oluştur
                Control control = new BasicControl(oid, critical, value);
                controls.add(control);

                if (debugMode) {
                    getLogger().info("Added LDAP control: OID={}, critical={}, value={}",
                            new Object[]{oid, critical, value != null ? bytesToHex(value) : "null"});
                }
            } catch (Exception e) {
                getLogger().error("Failed to parse control config: {}", new Object[]{controlConfig}, e);
            }
        }

        return controls.isEmpty() ? null : controls.toArray(new Control[0]);
    }

    /**
     * Hex string'i byte dizisine dönüştürür
     */
    private byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }

        return data;
    }

    /**
     * Byte dizisini hex string'e dönüştürür
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    /**
     * Create LDAP initial context with the given parameters
     */
    private LdapContext createLdapContext(String ldapUrl, String username, String password,
                                          int connectTimeout, int readTimeout,
                                          boolean bypassSslValidation, String referralHandling,
                                          Set<String> binaryAttributes, boolean debugMode) throws NamingException {

        // Set up the environment for creating the initial context
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);

        // Set security credentials if provided
        if (username != null && !username.isEmpty()) {
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, username);
            env.put(Context.SECURITY_CREDENTIALS, password != null ? password : "");
        }

        // Set connection and read timeouts
        env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(connectTimeout));
        env.put("com.sun.jndi.ldap.read.timeout", String.valueOf(readTimeout));

        // Handle SSL bypass if requested and using LDAPS
        if (bypassSslValidation && ldapUrl != null && ldapUrl.toLowerCase().startsWith("ldaps://")) {
            env.put("java.naming.ldap.factory.socket", "org.sezgin.processors.InsecureLDAPSocketFactory");
        }

        // Set referral handling
        env.put(Context.REFERRAL, referralHandling);

        // Configure binary attributes
        if (!binaryAttributes.isEmpty()) {
            StringBuilder binaryAttrsBuilder = new StringBuilder();
            for (String attr : binaryAttributes) {
                if (binaryAttrsBuilder.length() > 0) {
                    binaryAttrsBuilder.append(" ");
                }
                binaryAttrsBuilder.append(attr);
            }

            String binaryAttrsConfig = binaryAttrsBuilder.toString();
            env.put("java.naming.ldap.attributes.binary", binaryAttrsConfig);

            if (debugMode) {
                getLogger().info("Configured binary attributes for LDAP: {}", new Object[]{binaryAttrsConfig});
            }
        }

        if (debugMode) {
            getLogger().info("Creating LDAP context with URL: {}, Username: {}, Bypass SSL: {}, Referral: {}",
                    new Object[]{ldapUrl, username, bypassSslValidation, referralHandling});
        }

        try {
            // Create initial context
            return new InitialLdapContext(env, null);
        } catch (NamingException ne) {
            getLogger().error("Failed to create LDAP context: {}", new Object[]{ne.getMessage()}, ne);
            throw ne;
        } catch (Exception e) {
            getLogger().error("Unexpected error creating LDAP context: {}", new Object[]{e.getMessage()}, e);
            NamingException ne = new NamingException("Failed to create LDAP context: " + e.getMessage());
            ne.initCause(e);
            throw ne;
        }
    }

    /**
     * Perform LDAP search operation
     */
    private List<SearchResult> performSearch(LdapContext ctx, String baseDn, String filter,
                                             String scope, String[] returnAttributes,
                                             int pageSize, Control[] additionalControls,
                                             boolean debugMode) throws NamingException {

        List<SearchResult> allResults = new ArrayList<>();
        NamingEnumeration<SearchResult> results = null;

        try {
            // Set up search controls
            SearchControls searchControls = new SearchControls();

            // Set search scope
            switch (scope) {
                case "OBJECT_SCOPE":
                    searchControls.setSearchScope(SearchControls.OBJECT_SCOPE);
                    break;
                case "ONELEVEL_SCOPE":
                    searchControls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
                    break;
                case "SUBTREE_SCOPE":
                default:
                    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                    break;
            }

            // Set attributes to return
            if (returnAttributes != null && returnAttributes.length > 0) {
                searchControls.setReturningAttributes(returnAttributes);
            }

            if (debugMode) {
                getLogger().info("Performing LDAP search: BaseDN: {}, Filter: {}, Scope: {}, Attributes: {}, Page Size: {}",
                        new Object[]{baseDn, filter, scope, returnAttributes != null ? String.join(",", returnAttributes) : "all", pageSize});
            }

            // Kontrolleri birleştir
            List<Control> requestControls = new ArrayList<>();

            // Sayfalama kontrolü ekle
            if (pageSize > 0) {
                requestControls.add(new PagedResultsControl(pageSize, Control.CRITICAL));
            }

            // Ek kontrolleri ekle
            if (additionalControls != null && additionalControls.length > 0) {
                Collections.addAll(requestControls, additionalControls);

                if (debugMode) {
                    getLogger().info("Added {} additional controls to LDAP search", new Object[]{additionalControls.length});
                }
            }

            // Kontrolleri ayarla
            if (!requestControls.isEmpty()) {
                ctx.setRequestControls(requestControls.toArray(new Control[0]));

                if (debugMode) {
                    getLogger().info("Set {} request controls for LDAP search", new Object[]{requestControls.size()});
                }
            }

            // If paging is enabled
            if (pageSize > 0) {
                // Initialize paged results control
                byte[] cookie = null;

                do {
                    try {
                        // Perform the search
                        results = ctx.search(baseDn, filter, searchControls);

                        // Process all results in this page
                        while (results != null && results.hasMoreElements()) {
                            allResults.add(results.nextElement());
                        }
                    } finally {
                        if (results != null) {
                            results.close();
                        }
                    }

                    // Examine the response controls
                    cookie = null;
                    Control[] controls = ctx.getResponseControls();
                    if (controls != null) {
                        for (Control control : controls) {
                            if (control instanceof PagedResultsResponseControl) {
                                cookie = ((PagedResultsResponseControl) control).getCookie();
                                break;
                            }
                        }
                    }

                    // Re-activate paged results with additional controls
                    if (cookie != null && cookie.length > 0) {
                        requestControls = new ArrayList<>();
                        requestControls.add(new PagedResultsControl(pageSize, cookie, Control.CRITICAL));

                        // Ek kontrolleri yeniden ekle
                        if (additionalControls != null && additionalControls.length > 0) {
                            Collections.addAll(requestControls, additionalControls);
                        }

                        ctx.setRequestControls(requestControls.toArray(new Control[0]));
                    }

                } while (cookie != null && cookie.length > 0);

            } else {
                // Non-paged search
                try {
                    results = ctx.search(baseDn, filter, searchControls);

                    // Process all results
                    while (results != null && results.hasMoreElements()) {
                        allResults.add(results.nextElement());
                    }
                } finally {
                    if (results != null) {
                        results.close();
                    }
                }
            }

            if (debugMode) {
                getLogger().info("LDAP search returned {} results", new Object[]{allResults.size()});
            }

            return allResults;

        } catch (NamingException e) {
            getLogger().error("LDAP search error: {}", new Object[]{e.getMessage()}, e);
            throw e;
        } catch (Exception e) {
            getLogger().error("Unexpected error during LDAP search: {}", new Object[]{e.getMessage()}, e);
            throw new NamingException("Unexpected error: " + e.getMessage());
        }
    }

    /**
     * Convert search results to JSON format
     */
    private String convertResultsToJson(List<SearchResult> results, boolean debugMode, Set<String> binaryAttributes) {
        try {
            ObjectNode rootNode = objectMapper.createObjectNode();
            ArrayNode entriesNode = objectMapper.createArrayNode();

            for (SearchResult result : results) {
                ObjectNode entryNode = objectMapper.createObjectNode();

                // Add the DN
                entryNode.put("dn", result.getNameInNamespace());

                // Process attributes
                ObjectNode attributesNode = objectMapper.createObjectNode();
                Attributes attributes = result.getAttributes();
                NamingEnumeration<? extends Attribute> allAttributes = attributes.getAll();

                while (allAttributes.hasMore()) {
                    Attribute attribute = allAttributes.next();
                    String attributeName = attribute.getID();
                    String attributeNameLower = attributeName.toLowerCase();

                    // Check if this is a binary attribute that needs conversion
                    boolean isBinaryAttribute = binaryAttributes.contains(attributeNameLower);

                    // Handle multi-valued attributes
                    if (attribute.size() > 1) {
                        ArrayNode valuesNode = objectMapper.createArrayNode();
                        NamingEnumeration<?> values = attribute.getAll();

                        while (values.hasMore()) {
                            Object value = values.next();
                            if (value != null) {
                                if (isBinaryAttribute && value instanceof byte[]) {
                                    // Convert binary data to formatted string
                                    String formattedValue = formatBinaryAttribute((byte[]) value, attributeNameLower);
                                    valuesNode.add(formattedValue);
                                } else {
                                    valuesNode.add(value.toString());
                                }
                            }
                        }

                        attributesNode.set(attributeName, valuesNode);
                    } else if (attribute.size() == 1) {
                        // Single-valued attribute
                        Object value = attribute.get();
                        if (value != null) {
                            if (isBinaryAttribute && value instanceof byte[]) {
                                // Convert binary data to formatted string
                                String formattedValue = formatBinaryAttribute((byte[]) value, attributeNameLower);
                                attributesNode.put(attributeName, formattedValue);
                            } else {
                                attributesNode.put(attributeName, value.toString());
                            }
                        }
                    }
                }

                entryNode.set("attributes", attributesNode);
                entriesNode.add(entryNode);
            }

            rootNode.set("entries", entriesNode);
            rootNode.put("count", results.size());

            return objectMapper.writeValueAsString(rootNode);

        } catch (Exception e) {
            getLogger().error("Failed to convert LDAP results to JSON: {}", new Object[]{e.getMessage()}, e);
            return "{\"error\":\"Failed to convert results to JSON\"}";
        }
    }

    /**
     * Formats binary attribute values based on attribute type
     * @param binaryData The binary data to format
     * @param attributeName The name of the attribute (lowercase)
     * @return A formatted string representation of the binary data
     */
    private String formatBinaryAttribute(byte[] binaryData, String attributeName) {
        if (binaryData == null || binaryData.length == 0) {
            return "";
        }

        try {
            // Format GUID
            if (attributeName.equals("objectguid")) {
                if (binaryData.length != 16) {
                    return Base64.getEncoder().encodeToString(binaryData);
                }

                return String.format("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        binaryData[3] & 0xFF, binaryData[2] & 0xFF, binaryData[1] & 0xFF, binaryData[0] & 0xFF,
                        binaryData[5] & 0xFF, binaryData[4] & 0xFF,
                        binaryData[7] & 0xFF, binaryData[6] & 0xFF,
                        binaryData[8] & 0xFF, binaryData[9] & 0xFF,
                        binaryData[10] & 0xFF, binaryData[11] & 0xFF, binaryData[12] & 0xFF,
                        binaryData[13] & 0xFF, binaryData[14] & 0xFF, binaryData[15] & 0xFF);
            }

            // Format SID
            else if (attributeName.equals("objectsid")) {
                if (binaryData.length < 8) {
                    return Base64.getEncoder().encodeToString(binaryData);
                }

                StringBuilder strSid = new StringBuilder("S-");

                // SID-Revision (1 byte)
                strSid.append(binaryData[0]).append("-");

                // Authority (6 bytes)
                long authority = 0;
                for (int i = 2; i <= 7; i++) {
                    authority = (authority << 8) | (binaryData[i] & 0xFF);
                }
                strSid.append(authority);

                // Sub-authorities
                int subAuthorityCount = binaryData[1] & 0xFF;
                int offset = 8;
                for (int i = 0; i < subAuthorityCount; i++) {
                    if (offset + 4 <= binaryData.length) {
                        long subAuthority = 0;
                        for (int j = 0; j < 4; j++) {
                            subAuthority |= (long)(binaryData[offset + j] & 0xFF) << (8 * j);
                        }
                        strSid.append("-").append(subAuthority);
                        offset += 4;
                    }
                }

                return strSid.toString();
            }

            // nTSecurityDescriptor formatını işle
            else if (attributeName.equals("ntsecuritydescriptor")) {
                // Base64 kodlamasına ek olarak, bazı temel bilgileri çıkarabiliriz
                String base64Value = Base64.getEncoder().encodeToString(binaryData);

                StringBuilder sdInfo = new StringBuilder();
                sdInfo.append("Security Descriptor (");

                try {
                    // Temel bilgileri ekle
                    int revision = binaryData[0] & 0xFF;
                    int controlFlags = ((binaryData[1] & 0xFF) << 8) | (binaryData[2] & 0xFF);

                    sdInfo.append("Rev:").append(revision).append(", ");
                    sdInfo.append("Flags:0x").append(Integer.toHexString(controlFlags));

                    // Bayrağı yorumla
                    if ((controlFlags & 0x01) != 0) sdInfo.append(" SE_OWNER_DEFAULTED");
                    if ((controlFlags & 0x02) != 0) sdInfo.append(" SE_GROUP_DEFAULTED");
                    if ((controlFlags & 0x04) != 0) sdInfo.append(" SE_DACL_PRESENT");
                    if ((controlFlags & 0x08) != 0) sdInfo.append(" SE_DACL_DEFAULTED");
                    if ((controlFlags & 0x10) != 0) sdInfo.append(" SE_SACL_PRESENT");
                    if ((controlFlags & 0x20) != 0) sdInfo.append(" SE_SACL_DEFAULTED");

                    sdInfo.append(")");

                    // Offset değerlerini ekle
                    if (binaryData.length >= 20) {
                        int ownerOffset = bytesToInt(binaryData, 4);
                        int groupOffset = bytesToInt(binaryData, 8);
                        int saclOffset = bytesToInt(binaryData, 12);
                        int daclOffset = bytesToInt(binaryData, 16);

                        sdInfo.append(" Offsets: Owner=").append(ownerOffset);
                        sdInfo.append(", Group=").append(groupOffset);
                        sdInfo.append(", SACL=").append(saclOffset);
                        sdInfo.append(", DACL=").append(daclOffset);
                    }

                    return sdInfo.toString();
                } catch (Exception e) {
                    // Hata durumunda sadece Base64 değerini döndür
                    return base64Value;
                }
            }

            // For other binary attributes, just return Base64 encoding
            return Base64.getEncoder().encodeToString(binaryData);

        } catch (Exception e) {
            getLogger().warn("Error formatting binary attribute: " + e.getMessage());
            return Base64.getEncoder().encodeToString(binaryData);
        }
    }

    /**
     * Little-endian byte dizisinden int değeri çıkarır
     */
    private int bytesToInt(byte[] bytes, int offset) {
        return ((bytes[offset + 3] & 0xFF) << 24) |
                ((bytes[offset + 2] & 0xFF) << 16) |
                ((bytes[offset + 1] & 0xFF) << 8) |
                (bytes[offset] & 0xFF);
    }

    /**
     * Convert search results to LDIF format
     */
    private String convertResultsToLdif(List<SearchResult> results, boolean debugMode) {
        StringBuilder ldifBuilder = new StringBuilder();

        try {
            for (SearchResult result : results) {
                // Add the DN
                ldifBuilder.append("dn: ").append(result.getNameInNamespace()).append("\n");

                // Process attributes
                Attributes attributes = result.getAttributes();
                NamingEnumeration<? extends Attribute> allAttributes = attributes.getAll();

                while (allAttributes.hasMore()) {
                    Attribute attribute = allAttributes.next();
                    String attributeName = attribute.getID();

                    // Skip binary attributes
                    if (attributeName.toLowerCase().contains(";binary")) {
                        continue;
                    }

                    // Handle all values
                    NamingEnumeration<?> values = attribute.getAll();
                    while (values.hasMore()) {
                        Object value = values.next();
                        if (value != null) {
                            String stringValue = value.toString();

                            // Check if value needs special encoding
                            if (stringValue.startsWith(" ") || stringValue.startsWith(":") ||
                                    stringValue.startsWith("<") || stringValue.contains("\n")) {
                                // Base64 encode the value
                                String encodedValue = Base64.getEncoder().encodeToString(stringValue.getBytes(StandardCharsets.UTF_8));
                                ldifBuilder.append(attributeName).append(":: ").append(encodedValue).append("\n");
                            } else {
                                ldifBuilder.append(attributeName).append(": ").append(stringValue).append("\n");
                            }
                        }
                    }
                }

                // Add empty line between entries
                ldifBuilder.append("\n");
            }

            return ldifBuilder.toString();

        } catch (Exception e) {
            getLogger().error("Failed to convert LDAP results to LDIF: {}", new Object[]{e.getMessage()}, e);
            return "# Error: Failed to convert results to LDIF\n";
        }
    }

    /**
     * Perform LDAP add operation
     */
    private boolean performAdd(LdapContext ctx, String entryDn, String jsonData, boolean debugMode, Control[] additionalControls) {
        try {
            if (debugMode) {
                getLogger().info("Performing LDAP add operation for DN: {}", new Object[]{entryDn});
            }

            // Set additional controls if any
            if (additionalControls != null && additionalControls.length > 0) {
                ctx.setRequestControls(additionalControls);

                if (debugMode) {
                    getLogger().info("Set {} request controls for LDAP add", new Object[]{additionalControls.length});
                }
            }

            // Parse the JSON data
            JsonNode rootNode = objectMapper.readTree(jsonData);
            JsonNode attributesNode = rootNode.get("attributes");

            if (attributesNode == null || !attributesNode.isObject()) {
                getLogger().error("Invalid JSON data format for add operation. Expected 'attributes' object.");
                return false;
            }

            // Create attributes object
            BasicAttributes attributes = new BasicAttributes();

            // Process each attribute
            Iterator<Map.Entry<String, JsonNode>> fields = attributesNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String attributeName = field.getKey();
                JsonNode valueNode = field.getValue();

                if (valueNode.isArray()) {
                    // Multi-valued attribute
                    BasicAttribute attribute = new BasicAttribute(attributeName);
                    for (JsonNode value : valueNode) {
                        attribute.add(value.asText());
                    }
                    attributes.put(attribute);
                } else {
                    // Single-valued attribute
                    attributes.put(attributeName, valueNode.asText());
                }
            }

            // Perform the add operation
            ctx.createSubcontext(entryDn, attributes);

            if (debugMode) {
                getLogger().info("Successfully added entry with DN: {}", new Object[]{entryDn});
            }

            return true;

        } catch (Exception e) {
            getLogger().error("Failed to perform LDAP add operation: {}", new Object[]{e.getMessage()}, e);
            return false;
        }
    }

    /**
     * Perform LDAP modify operation
     */
    private boolean performModify(LdapContext ctx, String entryDn, String jsonData, boolean debugMode, Control[] additionalControls) {
        try {
            if (debugMode) {
                getLogger().info("Performing LDAP modify operation for DN: {}", new Object[]{entryDn});
            }

            // Set additional controls if any
            if (additionalControls != null && additionalControls.length > 0) {
                ctx.setRequestControls(additionalControls);

                if (debugMode) {
                    getLogger().info("Set {} request controls for LDAP modify", new Object[]{additionalControls.length});
                }
            }

            // Parse the JSON data
            JsonNode rootNode = objectMapper.readTree(jsonData);
            JsonNode modificationsNode = rootNode.get("modifications");

            if (modificationsNode == null || !modificationsNode.isArray()) {
                getLogger().error("Invalid JSON data format for modify operation. Expected 'modifications' array.");
                return false;
            }

            // Create modifications list
            List<ModificationItem> modificationItems = new ArrayList<>();

            // Process each modification
            for (JsonNode modNode : modificationsNode) {
                String operation = modNode.get("operation").asText();
                String attributeName = modNode.get("attribute").asText();
                JsonNode valuesNode = modNode.get("values");

                BasicAttribute attribute = new BasicAttribute(attributeName);

                // Add values to attribute
                if (valuesNode.isArray()) {
                    for (JsonNode value : valuesNode) {
                        attribute.add(value.asText());
                    }
                } else {
                    attribute.add(valuesNode.asText());
                }

                // Determine modification type
                int modType;
                switch (operation.toUpperCase()) {
                    case "ADD":
                        modType = DirContext.ADD_ATTRIBUTE;
                        break;
                    case "REPLACE":
                        modType = DirContext.REPLACE_ATTRIBUTE;
                        break;
                    case "REMOVE":
                        modType = DirContext.REMOVE_ATTRIBUTE;
                        break;
                    default:
                        getLogger().error("Unknown modification operation: {}", new Object[]{operation});
                        return false;
                }

                modificationItems.add(new ModificationItem(modType, attribute));
            }

            // Perform the modify operation
            ctx.modifyAttributes(entryDn, modificationItems.toArray(new ModificationItem[0]));

            if (debugMode) {
                getLogger().info("Successfully modified entry with DN: {}", new Object[]{entryDn});
            }

            return true;

        } catch (Exception e) {
            getLogger().error("Failed to perform LDAP modify operation: {}", new Object[]{e.getMessage()}, e);
            return false;
        }
    }

    /**
     * Perform LDAP delete operation
     */
    private boolean performDelete(LdapContext ctx, String entryDn, boolean debugMode, Control[] additionalControls) {
        try {
            if (debugMode) {
                getLogger().info("Performing LDAP delete operation for DN: {}", new Object[]{entryDn});
            }

            // Set additional controls if any
            if (additionalControls != null && additionalControls.length > 0) {
                ctx.setRequestControls(additionalControls);

                if (debugMode) {
                    getLogger().info("Set {} request controls for LDAP delete", new Object[]{additionalControls.length});
                }
            }

            // Perform the delete operation
            ctx.destroySubcontext(entryDn);

            if (debugMode) {
                getLogger().info("Successfully deleted entry with DN: {}", new Object[]{entryDn});
            }

            return true;

        } catch (Exception e) {
            getLogger().error("Failed to perform LDAP delete operation: {}", new Object[]{e.getMessage()}, e);
            return false;
        }
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        // Get FlowFile (may be null if no incoming connection)
        FlowFile flowFile = session.get();

        // Check if debug mode is enabled
        final boolean debugMode = context.getProperty(DEBUG_MODE).asBoolean();

        // Create a new FlowFile if none was received
        boolean createdFlowFile = false;
        if (flowFile == null) {
            flowFile = session.create();
            createdFlowFile = true;
            if (debugMode) {
                getLogger().info("Created new FlowFile as none was received");
            }
        }

        // Get property values with FlowFile attribute expression evaluation
        final String ldapUrl = context.getProperty(LDAP_URL).evaluateAttributeExpressions(flowFile).getValue();
        final String operation = context.getProperty(LDAP_OPERATION).evaluateAttributeExpressions(flowFile).getValue();
        final String baseDn = context.getProperty(BASE_DN).evaluateAttributeExpressions(flowFile).getValue();
        final String searchFilter = context.getProperty(SEARCH_FILTER).evaluateAttributeExpressions(flowFile).getValue();
        final String searchScope = context.getProperty(SEARCH_SCOPE).evaluateAttributeExpressions(flowFile).getValue();
        final String returnAttributesStr = context.getProperty(RETURN_ATTRIBUTES).evaluateAttributeExpressions(flowFile).getValue();
        final String username = context.getProperty(USERNAME).evaluateAttributeExpressions(flowFile).getValue();
        final String password = context.getProperty(PASSWORD).evaluateAttributeExpressions(flowFile).getValue();
        final int pageSize = context.getProperty(PAGE_SIZE).evaluateAttributeExpressions(flowFile).asInteger();
        final int connectTimeout = context.getProperty(CONNECTION_TIMEOUT).evaluateAttributeExpressions(flowFile).asInteger();
        final int readTimeout = context.getProperty(READ_TIMEOUT).evaluateAttributeExpressions(flowFile).asInteger();
        final boolean bypassSslValidation = context.getProperty(BYPASS_SSL_VALIDATION).evaluateAttributeExpressions(flowFile).asBoolean();
        final String referralHandling = context.getProperty(REFERRAL_HANDLING).evaluateAttributeExpressions(flowFile).getValue();
        final String outputFormat = context.getProperty(OUTPUT_FORMAT).evaluateAttributeExpressions(flowFile).getValue();

        // LDAP kontrollerini yapılandır
        final String ldapControlsConfig = context.getProperty(LDAP_CONTROLS).evaluateAttributeExpressions(flowFile).getValue();
        final String controlValueFormat = context.getProperty(CONTROL_VALUE_FORMAT).evaluateAttributeExpressions(flowFile).getValue();
        Control[] additionalControls = parseAndCreateLdapControls(ldapControlsConfig, controlValueFormat, debugMode);

        // Get binary attributes list
        final String binaryAttrsStr = context.getProperty(BINARY_ATTRIBUTES).evaluateAttributeExpressions(flowFile).getValue();
        Set<String> binaryAttributes = new HashSet<>();

        // nTSecurityDescriptor her zaman ikili bir niteliktir, varsayılan olarak ekle
        binaryAttributes.add("ntsecuritydescriptor");

        if (binaryAttrsStr != null && !binaryAttrsStr.trim().isEmpty()) {
            for (String attr : binaryAttrsStr.split(",")) {
                binaryAttributes.add(attr.trim().toLowerCase());
            }
        }

        // Process return attributes
        String[] returnAttributes = null;
        if (returnAttributesStr != null && !returnAttributesStr.trim().isEmpty()) {
            returnAttributes = returnAttributesStr.split(",");
            for (int i = 0; i < returnAttributes.length; i++) {
                returnAttributes[i] = returnAttributes[i].trim();
            }
        }

        // Prepare for LDAP operations
        LdapContext ldapContext = null;
        try {
            // Create LDAP context
            ldapContext = createLdapContext(ldapUrl, username, password, connectTimeout, readTimeout,
                    bypassSslValidation, referralHandling, binaryAttributes, debugMode);

            // Prepare result - using AtomicReference to make it effectively final for inner classes
            final AtomicReference<String> resultRef = new AtomicReference<>("");
            boolean operationSuccess = false;

            // Process based on operation
            switch (operation.toUpperCase()) {
                case "SEARCH":
                    // Perform search operation
                    List<SearchResult> searchResults = performSearch(ldapContext, baseDn, searchFilter,
                            searchScope, returnAttributes, pageSize,
                            additionalControls, // Ek kontroller eklendi
                            debugMode);

                    // Convert results to requested format
                    if ("JSON".equalsIgnoreCase(outputFormat)) {
                        resultRef.set(convertResultsToJson(searchResults, debugMode, binaryAttributes));
                    } else {
                        resultRef.set(convertResultsToLdif(searchResults, debugMode));
                    }

                    operationSuccess = true;
                    break;

                case "ADD":
                    // Read FlowFile content for add operation
                    final byte[] content = new byte[(int) flowFile.getSize()];
                    session.read(flowFile, new InputStreamCallback() {
                        @Override
                        public void process(InputStream inputStream) throws IOException {
                            StreamUtils.fillBuffer(inputStream, content, true);
                        }
                    });

                    String jsonData = new String(content, StandardCharsets.UTF_8);
                    operationSuccess = performAdd(ldapContext, baseDn, jsonData, debugMode, additionalControls);

                    if (operationSuccess) {
                        resultRef.set("{\"status\":\"success\",\"message\":\"Entry added successfully\"}");
                    } else {
                        resultRef.set("{\"status\":\"error\",\"message\":\"Failed to add entry\"}");
                    }
                    break;

                case "MODIFY":
                    // Read FlowFile content for modify operation
                    final byte[] modifyContent = new byte[(int) flowFile.getSize()];
                    session.read(flowFile, new InputStreamCallback() {
                        @Override
                        public void process(InputStream inputStream) throws IOException {
                            StreamUtils.fillBuffer(inputStream, modifyContent, true);
                        }
                    });

                    String modifyJsonData = new String(modifyContent, StandardCharsets.UTF_8);
                    operationSuccess = performModify(ldapContext, baseDn, modifyJsonData, debugMode, additionalControls);

                    if (operationSuccess) {
                        resultRef.set("{\"status\":\"success\",\"message\":\"Entry modified successfully\"}");
                    } else {
                        resultRef.set("{\"status\":\"error\",\"message\":\"Failed to modify entry\"}");
                    }
                    break;

                case "DELETE":
                    operationSuccess = performDelete(ldapContext, baseDn, debugMode, additionalControls);

                    if (operationSuccess) {
                        resultRef.set("{\"status\":\"success\",\"message\":\"Entry deleted successfully\"}");
                    } else {
                        resultRef.set("{\"status\":\"error\",\"message\":\"Failed to delete entry\"}");
                    }
                    break;

                case "BIND":
                    // Just testing authentication - already done when creating context
                    resultRef.set("{\"status\":\"success\",\"message\":\"Bind successful\"}");
                    operationSuccess = true;
                    break;

                case "UNBIND":
                    // Just close the context
                    ldapContext.close();
                    resultRef.set("{\"status\":\"success\",\"message\":\"Unbind successful\"}");
                    operationSuccess = true;
                    break;

                default:
                    getLogger().error("Unsupported LDAP operation: {}", new Object[]{operation});
                    resultRef.set("{\"status\":\"error\",\"message\":\"Unsupported LDAP operation: " + operation + "\"}");
                    operationSuccess = false;
            }

            // Write result to FlowFile
            try {
                FlowFile resultFlowFile = session.write(flowFile, new OutputStreamCallback() {
                    @Override
                    public void process(OutputStream outputStream) throws IOException {
                        try {
                            String finalResult = resultRef.get();
                            outputStream.write(finalResult.getBytes(StandardCharsets.UTF_8));
                        } catch (IOException e) {
                            getLogger().error("Error writing to output stream: {}", new Object[]{e.getMessage()}, e);
                            throw e; // Re-throw to be handled by session.write's exception handling
                        }
                    }
                });

                // Add attributes to the result FlowFile
                Map<String, String> attributes = new HashMap<>();
                attributes.put("ldap.operation", operation);
                attributes.put("ldap.url", ldapUrl);
                if (baseDn != null) {
                    attributes.put("ldap.baseDn", baseDn);
                }
                attributes.put("ldap.operation.success", String.valueOf(operationSuccess));

                // Kontrol kullanımıyla ilgili bilgileri ekle
                if (additionalControls != null && additionalControls.length > 0) {
                    attributes.put("ldap.controls.count", String.valueOf(additionalControls.length));

                    // İlk kontrolün OID'sini ekle (genellikle sadece bir tane kontrol kullanılır)
                    if (additionalControls.length > 0) {
                        attributes.put("ldap.controls.oid", additionalControls[0].getID());
                    }
                }

                resultFlowFile = session.putAllAttributes(resultFlowFile, attributes);

                // Transfer to appropriate relationship
                if (operationSuccess) {
                    session.transfer(resultFlowFile, REL_SUCCESS);
                    if (debugMode) {
                        getLogger().info("LDAP operation successful, transferred to SUCCESS");
                    }
                } else {
                    session.transfer(resultFlowFile, REL_FAILURE);
                    if (debugMode) {
                        getLogger().info("LDAP operation failed, transferred to FAILURE");
                    }
                }

                // If we created the original FlowFile (when there was no input) and we're not using it as the result,
                // remove it to avoid clutter
                if (createdFlowFile && operationSuccess == false) {
                    session.remove(flowFile);
                    if (debugMode) {
                        getLogger().info("Removed original FlowFile as it was created by the processor");
                    }
                }
            } catch (Exception e) {
                getLogger().error("Error during FlowFile processing: {}", new Object[]{e.getMessage()}, e);
                session.transfer(flowFile, REL_FAILURE);
            }

        } catch (NamingException e) {
            getLogger().error("LDAP error: {}", new Object[]{e.getMessage()}, e);
            flowFile = session.putAttribute(flowFile, "ldap.error", e.getMessage());
            session.transfer(flowFile, REL_FAILURE);
        } catch (Exception e) {
            getLogger().error("Error processing LDAP operation: {}", new Object[]{e.getMessage()}, e);
            flowFile = session.putAttribute(flowFile, "ldap.error", e.getMessage());
            session.transfer(flowFile, REL_FAILURE);
        } finally {
            // Close LDAP context
            if (ldapContext != null) {
                try {
                    ldapContext.close();
                } catch (NamingException e) {
                    getLogger().warn("Error closing LDAP context: {}", new Object[]{e.getMessage()}, e);
                }
            }
        }
    }
}