package org.sezgin.processors;

import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.InputRequirement.Requirement;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.SupportsBatching;
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
import org.apache.nifi.processor.io.InputStreamCallback;
import org.apache.nifi.processor.io.OutputStreamCallback;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

@SupportsBatching
@InputRequirement(Requirement.INPUT_REQUIRED)
@Tags({"json", "schema", "validation", "generation", "converter"})
@CapabilityDescription("Analyzes JSON input and generates a JSON Schema automatically. " +
        "This processor examines the structure of input JSON data and produces a schema definition " +
        "that conforms to the specified JSON Schema version.")
@ReadsAttributes({
        @ReadsAttribute(attribute="mime.type", description="If the mime type is 'application/json', the content will be treated as JSON.")
})
@WritesAttributes({
        @WritesAttribute(attribute="schema.generation.status", description="The status of schema generation (success/failure)"),
        @WritesAttribute(attribute="schema.version", description="The version of JSON Schema used in generation")
})
public class JSONSchemaGeneratorProcessor extends AbstractProcessor {

    // Define a class for schema context to make parameter passing cleaner
    private static class SchemaContext {
        private final Set<String> path;
        private final boolean inferFieldTypes;
        private final boolean requireAllFields;
        private final boolean includeExamples;
        private final int maxArraySamples;
        
        public SchemaContext(Set<String> path, boolean inferFieldTypes, 
                             boolean requireAllFields, boolean includeExamples,
                             int maxArraySamples) {
            this.path = path;
            this.inferFieldTypes = inferFieldTypes;
            this.requireAllFields = requireAllFields;
            this.includeExamples = includeExamples;
            this.maxArraySamples = maxArraySamples;
        }
        
        public Set<String> getPath() {
            return path;
        }
        
        public boolean isInferFieldTypes() {
            return inferFieldTypes;
        }
        
        public boolean isRequireAllFields() {
            return requireAllFields;
        }
        
        public boolean isIncludeExamples() {
            return includeExamples;
        }
        
        public int getMaxArraySamples() {
            return maxArraySamples;
        }
    }
    
    // Define enums for schema version and node types
    public enum SchemaVersion {
        DRAFT_07("draft-07", "http://json-schema.org/draft-07/schema#"),
        DRAFT_2019_09("2019-09", "https://json-schema.org/draft/2019-09/schema"),
        DRAFT_2020_12("2020-12", "https://json-schema.org/draft/2020-12/schema");
        
        private final String code;
        private final String url;
        
        SchemaVersion(String code, String url) {
            this.code = code;
            this.url = url;
        }
        
        public String getCode() {
            return code;
        }
        
        public String getUrl() {
            return url;
        }
        
        public static SchemaVersion fromCode(String code) {
            for (SchemaVersion version : values()) {
                if (version.getCode().equals(code)) {
                    return version;
                }
            }
            return DRAFT_07; // Default
        }
    }
    
    public enum NodeType {
        OBJECT("object"),
        ARRAY("array"),
        STRING("string"),
        INTEGER("integer"),
        NUMBER("number"),
        BOOLEAN("boolean"),
        NULL("null"),
        UNKNOWN("string"); // Default to string for unknown types
        
        private final String schemaType;
        
        NodeType(String schemaType) {
            this.schemaType = schemaType;
        }
        
        public String getSchemaType() {
            return schemaType;
        }
    }

    public static final PropertyDescriptor INFER_FIELD_TYPES = new PropertyDescriptor.Builder()
            .name("Infer Field Types")
            .description("Whether to infer data types for fields based on values")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("true")
            .build();

    public static final PropertyDescriptor REQUIRE_ALL_FIELDS = new PropertyDescriptor.Builder()
            .name("Require All Fields")
            .description("Whether all detected fields should be marked as required in the schema")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("false")
            .build();

    public static final PropertyDescriptor TITLE = new PropertyDescriptor.Builder()
            .name("Schema Title")
            .description("The title to use for the generated schema")
            .required(false)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor DESCRIPTION = new PropertyDescriptor.Builder()
            .name("Schema Description")
            .description("The description to use for the generated schema")
            .required(false)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor INCLUDE_EXAMPLES = new PropertyDescriptor.Builder()
            .name("Include Examples")
            .description("Whether to include example values in the schema")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("true")
            .build();

    public static final PropertyDescriptor MAX_ARRAY_SAMPLES = new PropertyDescriptor.Builder()
            .name("Max Array Samples")
            .description("Maximum number of array items to sample for type inference")
            .required(true)
            .addValidator(StandardValidators.POSITIVE_INTEGER_VALIDATOR)
            .defaultValue("5")
            .build();

    public static final PropertyDescriptor PRETTY_PRINT = new PropertyDescriptor.Builder()
            .name("Pretty Print")
            .description("Whether to format the output schema with indentation")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("true")
            .build();

    // Relationships
    public static final Relationship REL_SUCCESS = new Relationship.Builder()
            .name("success")
            .description("Successfully generated JSON Schema")
            .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("failure")
            .description("Failed to generate JSON Schema")
            .build();

    // Property Descriptors
    public static final PropertyDescriptor SCHEMA_VERSION = new PropertyDescriptor.Builder()
            .name("Schema Version")
            .description("The JSON Schema version to generate")
            .required(true)
            .allowableValues("draft-07", "2019-09", "2020-12")
            .defaultValue("draft-07")
            .build();

    private List<PropertyDescriptor> descriptors;
    private Set<Relationship> relationships;
    private ObjectMapper objectMapper;

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }

    @Override
    protected void init(final ProcessorInitializationContext context) {
        // Initialize with comprehensive logging for easier debugging
        String logMessage = "Initializing JSONSchemaGeneratorProcessor with the following properties:\n" +
                            "- Schema versions supported: draft-07, 2019-09, 2020-12\n" +
                            "- Type inference: enabled by default\n" +
                            "- Format detection: email, date, uuid, uri";

        if (context.getLogger().isDebugEnabled()) {
            context.getLogger().debug(logMessage);
        }

        final List<PropertyDescriptor> descriptors = new ArrayList<>();
        descriptors.add(SCHEMA_VERSION);
        descriptors.add(INFER_FIELD_TYPES);
        descriptors.add(REQUIRE_ALL_FIELDS);
        descriptors.add(TITLE);
        descriptors.add(DESCRIPTION);
        descriptors.add(INCLUDE_EXAMPLES);
        descriptors.add(MAX_ARRAY_SAMPLES);
        descriptors.add(PRETTY_PRINT);
        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<>();
        relationships.add(REL_SUCCESS);
        relationships.add(REL_FAILURE);
        this.relationships = Collections.unmodifiableSet(relationships);

        this.objectMapper = new ObjectMapper();
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        FlowFile flowFile = session.get();
        if (flowFile == null) {
            return;
        }

        // Get processor properties
        final String schemaVersionCode = context.getProperty(SCHEMA_VERSION).getValue();
        final boolean inferFieldTypes = context.getProperty(INFER_FIELD_TYPES).asBoolean();
        final boolean requireAllFields = context.getProperty(REQUIRE_ALL_FIELDS).asBoolean();
        final String title = context.getProperty(TITLE).getValue();
        final String description = context.getProperty(DESCRIPTION).getValue();
        final boolean includeExamples = context.getProperty(INCLUDE_EXAMPLES).asBoolean();
        final int maxArraySamples = context.getProperty(MAX_ARRAY_SAMPLES).asInteger();
        final boolean prettyPrint = context.getProperty(PRETTY_PRINT).asBoolean();

        // Read input JSON content
        final AtomicReference<JsonNode> jsonReference = new AtomicReference<>();
        try {
            session.read(flowFile, new InputStreamCallback() {
                @Override
                public void process(InputStream inputStream) throws IOException {
                    try {
                        JsonNode rootNode = objectMapper.readTree(inputStream);
                        jsonReference.set(rootNode);
                    } catch (Exception e) {
                        throw new IOException("Failed to parse JSON input: " + e.getMessage(), e);
                    }
                }
            });
        } catch (Exception e) {
            String errorMsg = String.format("Failed to read JSON input: %s", e.getMessage());
            getLogger().error(errorMsg, e);
            session.transfer(session.putAttribute(flowFile, "schema.generation.status", "failure"), REL_FAILURE);
            return;
        }

        // Generate schema from JSON
        final JsonNode inputJson = jsonReference.get();
        final AtomicReference<String> schemaReference = new AtomicReference<>();

        try {
            // Create context for schema generation
            SchemaContext schemaContext = new SchemaContext(
                    new HashSet<>(), inferFieldTypes, requireAllFields, includeExamples, maxArraySamples);

            // Convert string version code to enum
            SchemaVersion schemaVersion = SchemaVersion.fromCode(schemaVersionCode);
            
            // Generate schema
            JsonNode schemaNode = generateSchema(inputJson, schemaVersion, title, description, schemaContext);

            // Convert schema to string
            String schemaJson;
            if (prettyPrint) {
                schemaJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(schemaNode);
            } else {
                schemaJson = objectMapper.writeValueAsString(schemaNode);
            }

            schemaReference.set(schemaJson);
        } catch (Exception e) {
            String errorMsg = String.format("Failed to generate JSON Schema: %s", e.getMessage());
            getLogger().error(errorMsg, e);
            session.transfer(session.putAttribute(flowFile, "schema.generation.status", "failure"), REL_FAILURE);
            return;
        }

        // Write schema to output FlowFile
        FlowFile outputFlowFile = session.write(flowFile, new OutputStreamCallback() {
            @Override
            public void process(OutputStream outputStream) throws IOException {
                try {
                    outputStream.write(schemaReference.get().getBytes(StandardCharsets.UTF_8));
                } catch (Exception e) {
                    throw new IOException("Failed to write schema to output: " + e.getMessage(), e);
                }
            }
        });

        // Add attributes
        Map<String, String> attributes = new HashMap<>();
        attributes.put("schema.generation.status", "success");
        attributes.put("schema.version", schemaVersionCode);
        attributes.put("mime.type", "application/schema+json");

        // Transfer to success
        session.transfer(session.putAllAttributes(outputFlowFile, attributes), REL_SUCCESS);
    }

    /**
     * Generate JSON Schema from input JSON
     */
    private JsonNode generateSchema(JsonNode inputJson, SchemaVersion schemaVersion,
                                  String title, String description, SchemaContext context) {

        ObjectNode schemaNode = objectMapper.createObjectNode();

        // Add schema version URL
        schemaNode.put("$schema", schemaVersion.getUrl());

        // Add title and description if provided
        if (title != null && !title.isEmpty()) {
            schemaNode.put("title", title);
        }
        if (description != null && !description.isEmpty()) {
            schemaNode.put("description", description);
        }

        // Log schema version for debugging
        String schemaVersionTemplate = "Schema Version: " + schemaVersion.getCode() + "\n" +
                                      "Schema URL: " + schemaVersion.getUrl();

        getLogger().debug(schemaVersionTemplate);

        // Analyze the root node
        analyzeNode(schemaNode, inputJson, context);

        return schemaNode;
    }

    /**
     * Determine NodeType enum from JsonNode
     */
    private NodeType getNodeType(JsonNode node) {
        if (node.isObject()) {
            return NodeType.OBJECT;
        } else if (node.isArray()) {
            return NodeType.ARRAY;
        } else if (node.isTextual()) {
            return NodeType.STRING;
        } else if (node.isNumber()) {
            return node.isIntegralNumber() ? NodeType.INTEGER : NodeType.NUMBER;
        } else if (node.isBoolean()) {
            return NodeType.BOOLEAN;
        } else if (node.isNull()) {
            return NodeType.NULL;
        }
        return NodeType.UNKNOWN;
    }

    /**
     * Recursively analyze a JSON node and build the corresponding schema
     */
    private void analyzeNode(ObjectNode schemaNode, JsonNode jsonNode, SchemaContext context) {
        // Get node type
        NodeType nodeType = getNodeType(jsonNode);
        
        // Process node based on type
        switch (nodeType) {
            case OBJECT:
                handleObjectNode(schemaNode, jsonNode, context);
                break;
            case ARRAY:
                handleArrayNode(schemaNode, jsonNode, context);
                break;
            default:
                handlePrimitiveNode(schemaNode, jsonNode, nodeType, context);
                break;
        }
    }

    /**
     * Handle object node type
     */
    private void handleObjectNode(ObjectNode schemaNode, JsonNode jsonNode, SchemaContext context) {
        schemaNode.put("type", NodeType.OBJECT.getSchemaType());
        ObjectNode properties = objectMapper.createObjectNode();
        schemaNode.set("properties", properties);

        // Track required fields
        ArrayNode requiredFields = objectMapper.createArrayNode();

        // Process each field in the object
        Iterator<Map.Entry<String, JsonNode>> fields = jsonNode.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            String fieldName = field.getKey();
            JsonNode fieldValue = field.getValue();

            // Create schema for this field
            ObjectNode fieldSchema = objectMapper.createObjectNode();
            properties.set(fieldName, fieldSchema);

            // Add to required fields if necessary
            if (context.isRequireAllFields() && !fieldValue.isNull()) {
                requiredFields.add(fieldName);
            }

            // Avoid infinite recursion by tracking path
            Set<String> newPath = new HashSet<>(context.getPath());
            String fullPath = String.join(".", context.getPath()) + "." + fieldName;
            if (!newPath.add(fullPath) && (fieldValue.isObject() || fieldValue.isArray())) {
                // We've seen this path before - handle circular reference
                NodeType fieldType = getNodeType(fieldValue);
                fieldSchema.put("type", fieldType.getSchemaType());
                if (fieldType == NodeType.OBJECT) {
                    fieldSchema.put("description", "Circular reference detected");
                }
                continue;
            }

            // Recursively analyze this field with a new context containing the updated path
            SchemaContext newContext = new SchemaContext(
                    newPath,
                    context.isInferFieldTypes(),
                    context.isRequireAllFields(),
                    context.isIncludeExamples(),
                    context.getMaxArraySamples()
            );
            analyzeNode(fieldSchema, fieldValue, newContext);
        }

        // Add required fields if any
        if (requiredFields.size() > 0) {
            schemaNode.set("required", requiredFields);
        }
    }

    /**
     * Handle array node type
     */
    private void handleArrayNode(ObjectNode schemaNode, JsonNode jsonNode, SchemaContext context) {
        schemaNode.put("type", NodeType.ARRAY.getSchemaType());

        // Sample array items to determine schema
        JsonNode itemSchema = null;
        int itemCount = Math.min(jsonNode.size(), context.getMaxArraySamples());

        if (itemCount > 0) {
            // Build items schema based on array content
            NodeType firstItemType = getNodeType(jsonNode.get(0));
            
            if (firstItemType == NodeType.OBJECT || firstItemType == NodeType.ARRAY) {
                // For complex types, use the first item as template and refine
                itemSchema = objectMapper.createObjectNode();
                analyzeNode((ObjectNode)itemSchema, jsonNode.get(0), context);

                // Check additional items to see if we need to adjust for variety
                boolean consistent = true;
                for (int i = 1; i < itemCount; i++) {
                    JsonNode item = jsonNode.get(i);
                    // If different types, switch to less specific schema
                    if (getNodeType(item) != firstItemType) {
                        consistent = false;
                        break;
                    }
                }
                
                // If types are inconsistent, use a generic schema
                if (!consistent) {
                    itemSchema = objectMapper.createObjectNode();
                }
            } else {
                // For simple types, just get the type
                NodeType itemType = context.isInferFieldTypes() ?
                        getNodeType(jsonNode.get(0)) : NodeType.STRING;

                // Check all sampled items for consistent type
                boolean consistent = true;
                for (int i = 1; i < itemCount; i++) {
                    if (getNodeType(jsonNode.get(i)) != itemType) {
                        consistent = false;
                        break;
                    }
                }

                if (consistent) {
                    itemSchema = objectMapper.createObjectNode();
                    ((ObjectNode)itemSchema).put("type", itemType.getSchemaType());
                } else {
                    // Mixed types, don't set a specific type for items
                    itemSchema = objectMapper.createObjectNode();
                }
            }
        } else {
            // Empty array, use generic item schema
            itemSchema = objectMapper.createObjectNode();
        }

        // Set items schema
        schemaNode.set("items", itemSchema);

        // Add example if requested
        if (context.isIncludeExamples() && jsonNode.size() > 0) {
            JsonNode example = jsonNode.size() > 2 ?
                    jsonNode.get(0) : jsonNode;
            schemaNode.set("examples", objectMapper.createArrayNode().add(example));
        }
    }

    /**
     * Handle primitive value node type
     */
    private void handlePrimitiveNode(ObjectNode schemaNode, JsonNode jsonNode, NodeType nodeType, SchemaContext context) {
        // Use the type from enum or infer it based on context
        String type = context.isInferFieldTypes() ? nodeType.getSchemaType() : NodeType.STRING.getSchemaType();
        schemaNode.put("type", type);

        // Add constraints based on node type
        switch (nodeType) {
            case INTEGER:
            case NUMBER:
                if (jsonNode.isNumber()) {
                    handleNumericConstraints(schemaNode, jsonNode, nodeType);
                }
                break;
            case STRING:
                if (jsonNode.isTextual()) {
                    handleStringConstraints(schemaNode, jsonNode.asText());
                }
                break;
            default:
                // No additional constraints for other types
                break;
        }

        // Add example value if requested
        if (context.isIncludeExamples() && !jsonNode.isNull()) {
            addExampleValue(schemaNode, jsonNode);
        }
    }

    /**
     * Add numeric constraints to schema
     */
    private void handleNumericConstraints(ObjectNode schemaNode, JsonNode jsonNode, NodeType nodeType) {
        switch (nodeType) {
            case INTEGER:
                // Example of setting a minimum
                if (jsonNode.asLong() < 0) {
                    schemaNode.put("minimum", Long.MIN_VALUE); // Or any appropriate minimum
                } else {
                    schemaNode.put("minimum", 0);
                }
                break;
            case NUMBER:
                // For non-integers, we can set more appropriate bounds
                if (jsonNode.asDouble() < 0) {
                    schemaNode.put("type", NodeType.NUMBER.getSchemaType());
                }
                break;
            default:
                // Shouldn't happen as we're only called with INTEGER or NUMBER
                break;
        }
    }

    /**
     * Add string format and constraints to schema
     */
    private void handleStringConstraints(ObjectNode schemaNode, String value) {
        // String format detection
        if (value.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
            schemaNode.put("format", "uuid");
        } else if (value.matches("\\d{4}-\\d{2}-\\d{2}")) {
            schemaNode.put("format", "date");
        } else if (value.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.*")) {
            schemaNode.put("format", "date-time");
        } else if (value.matches("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")) {
            schemaNode.put("format", "email");
        } else if (value.toLowerCase().startsWith("http://") || value.toLowerCase().startsWith("https://")) {
            schemaNode.put("format", "uri");
        }

        // Add string length constraints
        if (value.length() > 0 && value.length() <= 100) {
            // Only set maxLength for reasonably sized strings to avoid outliers
            schemaNode.put("maxLength", 100);
        }
    }

    /**
     * Add example value to schema based on node type
     */
    private void addExampleValue(ObjectNode schemaNode, JsonNode jsonNode) {
        if (jsonNode.isTextual()) {
            schemaNode.put("example", jsonNode.asText());
        } else if (jsonNode.isInt()) {
            schemaNode.put("example", jsonNode.asInt());
        } else if (jsonNode.isLong()) {
            schemaNode.put("example", jsonNode.asLong());
        } else if (jsonNode.isDouble() || jsonNode.isFloat()) {
            schemaNode.put("example", jsonNode.asDouble());
        } else if (jsonNode.isBoolean()) {
            schemaNode.put("example", jsonNode.asBoolean());
        }
        // No example for other types
    }
}