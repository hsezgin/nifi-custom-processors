package org.sezgin.processors;

import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;

import org.xbill.DNS.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

// Nested record for DNS query results
record DnsResult(String query, String type, List<String> results, long queryTimeMs) {}

@Tags({"dns", "network", "lookup", "resolve", "hostname", "IP", "domain"})
@CapabilityDescription("""
        Performs DNS lookups for various record types (A, AAAA, MX, etc.) using either JSON or text input,
        and produces either JSON or text output based on configuration.
        """)
@ReadsAttributes({
        @ReadsAttribute(attribute="dns.query", description="The hostname or IP address to query if not provided in the FlowFile content"),
        @ReadsAttribute(attribute="dns.type", description="The DNS record type to query if not set via processor property")
})
@WritesAttributes({
        @WritesAttribute(attribute="dns.query.result", description="Summary of the query result"),
        @WritesAttribute(attribute="dns.query.time", description="Time in milliseconds to perform the DNS lookup"),
        @WritesAttribute(attribute="dns.query.status", description="Status of the DNS lookup (success/failure)")
})
public class DNSClientProcessor extends AbstractProcessor {

    // Static constants for DNS record types
    public static final String TYPE_A = "A";
    public static final String TYPE_AAAA = "AAAA";
    public static final String TYPE_MX = "MX";
    public static final String TYPE_NS = "NS";
    public static final String TYPE_TXT = "TXT";
    public static final String TYPE_CNAME = "CNAME";
    public static final String TYPE_SOA = "SOA";
    public static final String TYPE_PTR = "PTR";
    public static final String TYPE_SRV = "SRV";

    // Input/Output format types
    public static final String FORMAT_JSON = "JSON";
    public static final String FORMAT_TEXT = "TEXT";

    // Property Descriptors with text blocks for descriptions
    public static final PropertyDescriptor DNS_SERVER = new PropertyDescriptor.Builder()
            .name("DNS Server")
            .description("""
                    DNS Server to use for lookups
                    If not specified, the system's default DNS server will be used.
                    """)
            .required(false)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor DNS_RECORD_TYPE = new PropertyDescriptor.Builder()
            .name("DNS Record Type")
            .description("The type of DNS record to lookup")
            .required(true)
            .allowableValues(TYPE_A, TYPE_AAAA, TYPE_MX, TYPE_NS, TYPE_TXT, TYPE_CNAME, TYPE_SOA, TYPE_PTR, TYPE_SRV)
            .defaultValue(TYPE_A)
            .build();

    public static final PropertyDescriptor INPUT_FORMAT = new PropertyDescriptor.Builder()
            .name("Input Format")
            .description("The format of the input data (JSON or TEXT)")
            .required(true)
            .allowableValues(FORMAT_JSON, FORMAT_TEXT)
            .defaultValue(FORMAT_TEXT)
            .build();

    public static final PropertyDescriptor OUTPUT_FORMAT = new PropertyDescriptor.Builder()
            .name("Output Format")
            .description("The format of the output data (JSON or TEXT)")
            .required(true)
            .allowableValues(FORMAT_JSON, FORMAT_TEXT)
            .defaultValue(FORMAT_JSON)
            .build();

    public static final PropertyDescriptor TIMEOUT = new PropertyDescriptor.Builder()
            .name("Timeout")
            .description("The timeout for DNS queries in milliseconds")
            .required(true)
            .defaultValue("5000")
            .addValidator(StandardValidators.POSITIVE_INTEGER_VALIDATOR)
            .build();

    public static final PropertyDescriptor FAIL_ON_EMPTY_RESULT = new PropertyDescriptor.Builder()
            .name("Fail On Empty Result")
            .description("If true, the processor will route to failure when DNS query returns no results")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("false")
            .build();

    // Relationships
    public static final Relationship REL_SUCCESS = new Relationship.Builder()
            .name("success")
            .description("Successful DNS lookups will be routed to this relationship")
            .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("failure")
            .description("Failed DNS lookups will be routed to this relationship")
            .build();

    private List<PropertyDescriptor> descriptors;
    private Set<Relationship> relationships;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void init(final ProcessorInitializationContext context) {
        // Using Java 17+ List.of() for immutable lists
        this.descriptors = List.of(
                DNS_SERVER,
                DNS_RECORD_TYPE,
                INPUT_FORMAT,
                OUTPUT_FORMAT,
                TIMEOUT,
                FAIL_ON_EMPTY_RESULT
        );

        // Using Java 17+ Set.of() for immutable sets
        this.relationships = Set.of(REL_SUCCESS, REL_FAILURE);
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
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        FlowFile flowFile = session.get();
        if (flowFile == null) {
            return;
        }

        // Get processor properties
        final String dnsServer = context.getProperty(DNS_SERVER).getValue();
        final String recordType = context.getProperty(DNS_RECORD_TYPE).getValue();
        final String inputFormat = context.getProperty(INPUT_FORMAT).getValue();
        final String outputFormat = context.getProperty(OUTPUT_FORMAT).getValue();
        final int timeout = context.getProperty(TIMEOUT).asInteger();
        final boolean failOnEmptyResult = context.getProperty(FAIL_ON_EMPTY_RESULT).asBoolean();

        // Reference to hold the DNS query
        final AtomicReference<String> queryRef = new AtomicReference<>("");
        final AtomicReference<String> effectiveRecordTypeRef = new AtomicReference<>(recordType);

        try {
            // Process the input based on the specified format - using switch expressions
            switch (inputFormat) {
                case FORMAT_TEXT -> {
                    // flowFile lambda içinde kullanılacak ve effectively final olmalı
                    final FlowFile immutableFlowFile = flowFile;
                    session.read(immutableFlowFile, (in) -> {
                        byte[] buffer = new byte[(int) immutableFlowFile.getSize()];
                        int len = in.read(buffer);
                        if (len > 0) {
                            String domain = new String(buffer, 0, len, StandardCharsets.UTF_8).trim();
                            queryRef.set(domain);
                        }
                    });
                }
                case FORMAT_JSON ->
                    // flowFile zaten effectively final olduğu için doğrudan kullanabiliriz
                    session.read(flowFile, (in) -> {
                        try {
                            JsonNode rootNode = objectMapper.readTree(in);

                            // Using pattern matching with instanceof (Java 16+)
                            if (rootNode instanceof ObjectNode objNode) {
                                // Extract domain using Optional for more elegant handling
                                Stream.of("domain", "hostname", "query")
                                        .filter(objNode::has)
                                        .findFirst()
                                        .map(field -> objNode.get(field).asText())
                                        .ifPresent(queryRef::set);

                                // Check if the JSON specifies a record type to override the property
                                Optional.ofNullable(objNode.get("type"))
                                        .map(JsonNode::asText)
                                        .map(String::toUpperCase)
                                        .filter(DNSClientProcessor.this::isValidRecordType)
                                        .ifPresent(effectiveRecordTypeRef::set);
                            }
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    });

                default -> throw new ProcessException("Unsupported input format: " + inputFormat);
            }

            // If query is still empty, check the attributes
            String query = queryRef.get();
            if (query == null || query.isEmpty()) {
                query = flowFile.getAttribute("dns.query");
            }

            if (query == null || query.isEmpty()) {
                getLogger().error("No DNS query found in FlowFile content or attributes");
                session.transfer(flowFile, REL_FAILURE);
                return;
            }

            // Get effective record type
            String effectiveRecordType = effectiveRecordTypeRef.get();

            // Check if attribute overrides the record type
            String attributeRecordType = flowFile.getAttribute("dns.type");
            if (attributeRecordType != null && !attributeRecordType.isEmpty() &&
                    isValidRecordType(attributeRecordType.toUpperCase())) {
                effectiveRecordType = attributeRecordType.toUpperCase();
            }

            // Perform the DNS lookup with timing
            long startTime = System.nanoTime();
            List<String> dnsResults = performDnsLookup(query, effectiveRecordType, dnsServer, timeout);
            long endTime = System.nanoTime();
            long queryTimeMs = TimeUnit.NANOSECONDS.toMillis(endTime - startTime);

            // Use the new record class to hold query results
            DnsResult dnsResult = new DnsResult(query, effectiveRecordType, dnsResults, queryTimeMs);

            // Check if we have empty results and need to route to failure
            if (dnsResults.isEmpty() && failOnEmptyResult) {
                flowFile = session.putAttribute(flowFile, "dns.query.status", "no_results");
                flowFile = session.putAttribute(flowFile, "dns.query.time", String.valueOf(dnsResult.queryTimeMs()));
                session.transfer(flowFile, REL_FAILURE);
                return;
            }

            // Create the output based on the specified format
            final DnsResult immutableResult = dnsResult;
            flowFile = session.write(flowFile, (out) -> {
                try {
                    switch (outputFormat) {
                        case FORMAT_JSON -> writeJsonOutput(out, immutableResult);
                        case FORMAT_TEXT -> writeTextOutput(out, immutableResult);
                        default -> throw new ProcessException("Unsupported output format: " + outputFormat);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });

            // Set attributes with information about the query
            Map<String, String> attributes = Map.of(
                    "dns.query.result", dnsResults.isEmpty() ? "no_records" : dnsResults.size() + "_records",
                    "dns.query.time", Long.toString(dnsResult.queryTimeMs()),  // Daha açık olmak için Long.toString kullanabilirsiniz
                    "dns.query.status", "success"
            );

            flowFile = session.putAllAttributes(flowFile, attributes);

            // Transfer to success
            session.transfer(flowFile, REL_SUCCESS);

        } catch (Exception e) {
            getLogger().error("Failed to process DNS query", e);

            flowFile = session.putAttribute(flowFile, "dns.query.status", "error");
            flowFile = session.putAttribute(flowFile, "dns.query.error", e.getMessage());
            session.transfer(flowFile, REL_FAILURE);
        }
    }

    /**
     * Writes JSON formatted output to the output stream
     */
    private void writeJsonOutput(OutputStream out, DnsResult result) throws IOException {
        // Create JSON output
        ObjectNode rootNode = objectMapper.createObjectNode();
        rootNode.put("query", result.query());
        rootNode.put("type", result.type());

        // Format the results based on record type using switch expression
        switch (result.type()) {
            case TYPE_A -> {
                ObjectNode aRecords = objectMapper.createObjectNode();

                // IP adreslerini ayrı bir diziye ekle
                ArrayNode ipArray = aRecords.putArray("ip_addresses");

                // CNAME kayıtlarını ayrı bir diziye ekle
                ArrayNode cnameArray = aRecords.putArray("cnames");

                // Sonuçları ayrıştır - 'item' adını kullanarak çakışmayı önlüyoruz
                for (String item : result.results()) {
                    if (item.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                        // IPv4 adresi
                        ipArray.add(item);
                    } else {
                        // Hostname/CNAME
                        cnameArray.add(item);
                    }
                }

                // Ana JSON nesnesine ekle
                if (!ipArray.isEmpty()) {
                    rootNode.set("ip_addresses", ipArray);
                }

                if (!cnameArray.isEmpty()) {
                    rootNode.set("cnames", cnameArray);
                }
            }
            case TYPE_AAAA -> {
                if (result.results().size() == 1) {
                    // Single AAAA record
                    rootNode.put("ipv6", result.results().getFirst());
                } else {
                    // Multiple AAAA records
                    ArrayNode ipv6Array = rootNode.putArray("ipv6s");
                    result.results().forEach(ipv6Array::add);
                }
            }
            case TYPE_MX -> {
                ArrayNode mxArray = rootNode.putArray("mx_records");
                for (String mxRecord : result.results()) {
                    // ObjectNode'u if bloğunun dışına çıkarın
                    ObjectNode mxNode = objectMapper.createObjectNode();

                    String[] parts = mxRecord.split("\\s+", 2);
                    if (parts.length == 2) {
                        try {
                            mxNode.put("priority", Integer.parseInt(parts[0]));
                            mxNode.put("hostname", parts[1]);
                        } catch (NumberFormatException e) {
                            // Handle malformed MX record
                            mxNode.put("record", mxRecord);
                        }
                    } else {
                        // Unexpected format
                        mxNode.put("record", mxRecord);
                    }

                    // mxNode'u her durumda ekleyin
                    mxArray.add(mxNode);
                }
            }
            default -> {
                // Generic handling for other record types
                ArrayNode resultsArray = rootNode.putArray("results");
                result.results().forEach(resultsArray::add);
            }
        }

        // Write the JSON to the output stream
        out.write(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(rootNode).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Writes text formatted output to the output stream
     */
    private void writeTextOutput(OutputStream out, DnsResult result) throws IOException {
        String content;

        if (result.results().isEmpty()) {
            content = String.format("No records found for %s (%s)", result.query(), result.type());
        } else {
            content = String.join("\n", result.results());
        }

        out.write(content.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Validates if the given string is a valid record type using enhanced switch expressions
     */
    private boolean isValidRecordType(String recordType) {
        return switch (recordType) {
            case TYPE_A, TYPE_AAAA, TYPE_MX, TYPE_NS, TYPE_TXT,
                 TYPE_CNAME, TYPE_SOA, TYPE_PTR, TYPE_SRV -> true;
            default -> false;
        };
    }

    /**
     * Performs the actual DNS lookup using dnsjava library
     */
    private List<String> performDnsLookup(String query, String recordType, String dnsServer, int timeout)
            throws IOException {
        List<String> results = new ArrayList<>();

        try {
            // Create a resolver
            Resolver resolver;
            if (dnsServer != null && !dnsServer.isEmpty()) {
                // Use specified DNS server
                resolver = new SimpleResolver(dnsServer);
            } else {
                // Use system default
                resolver = new SimpleResolver();
            }

            // Set timeout
            resolver.setTimeout(java.time.Duration.ofSeconds(timeout / 1000));

            // Create the appropriate record type using enhanced switch
            int dnsRecordType = switch (recordType) {
                case TYPE_AAAA -> Type.AAAA;
                case TYPE_MX -> Type.MX;
                case TYPE_NS -> Type.NS;
                case TYPE_TXT -> Type.TXT;
                case TYPE_CNAME -> Type.CNAME;
                case TYPE_SOA -> Type.SOA;
                case TYPE_PTR -> Type.PTR;
                case TYPE_SRV -> Type.SRV;
                default -> Type.A;
            };

            // Create the query message - değişken adını değiştirin
            Message dnsQuery = Message.newQuery(org.xbill.DNS.Record.newRecord(Name.fromString(query + "."), dnsRecordType, DClass.IN));

            // Send the query
            Message response = resolver.send(dnsQuery);

            // Process the response using pattern matching
            for (org.xbill.DNS.Record record : response.getSection(Section.ANSWER)) {
                // Using pattern matching with instanceof (Java 16+)
                String result = switch (record) {
                    case ARecord r -> r.getAddress().getHostAddress();
                    case AAAARecord r -> r.getAddress().getHostAddress();
                    case MXRecord r -> r.getPriority() + " " + r.getTarget().toString(true);
                    case NSRecord r -> r.getTarget().toString(true);
                    case TXTRecord r -> {
                        StringBuilder sb = new StringBuilder();
                        // TXTRecord'ın tüm string parçalarını alıp birleştiriyoruz
                        for (String txtPart : r.getStrings()) {
                            // TXTRecord'ın her bir parçasını temiz şekilde alıyoruz
                            sb.append(txtPart);
                        }
                        yield sb.toString();
                    }
                    case CNAMERecord r -> r.getTarget().toString(true);
                    case SOARecord r -> r.rdataToString();
                    case PTRRecord r -> r.getTarget().toString(true);
                    case SRVRecord r -> r.rdataToString();
                    default -> record.rdataToString();
                };

                results.add(result);
            }

        } catch (TextParseException e) {
            throw new IOException("Invalid domain name format: " + query, e);
        }

        return results;
    }
}