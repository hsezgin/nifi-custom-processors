package org.sezgin.processors;

import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.processors.standard.InvokeHTTP;
import org.apache.nifi.ssl.SSLContextService;

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Tags({"http", "https", "ssl", "bypass", "insecure", "fast"})
@CapabilityDescription("Modified version of InvokeHTTP processor that allows bypassing SSL validation and has optimized performance")
public class InsecureInvokeHTTP extends InvokeHTTP {

    public static final PropertyDescriptor BYPASS_SSL_VALIDATION = new PropertyDescriptor.Builder()
            .name("Bypass SSL Validation")
            .description("Whether to bypass SSL certificate validation")
            .required(true)
            .allowableValues("true", "false")
            .defaultValue("false")
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
            .expressionLanguageSupported(ExpressionLanguageScope.NONE)
            .build();

    @Override
    protected List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        final List<PropertyDescriptor> properties = new ArrayList<>(super.getSupportedPropertyDescriptors());
        properties.add(BYPASS_SSL_VALIDATION);
        properties.add(CONNECTION_TIMEOUT);
        properties.add(MAX_POOL_SIZE);
        return properties;
    }

    @Override
    protected SSLContext createSSLContext(SSLContextService sslService) throws ProcessException {
        boolean bypassSSL = "true".equalsIgnoreCase(
                this.context.getProperty(BYPASS_SSL_VALIDATION).getValue());

        if (bypassSSL) {
            try {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                TrustManager[] trustAllCerts = new TrustManager[]{
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
                sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
                return sslContext;
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                throw new ProcessException("Failed to create insecure SSL context", e);
            }
        } else {
            return super.createSSLContext(sslService);
        }
    }

    @Override
    protected HostnameVerifier getHostnameVerifier(boolean hostnameVerificationEnabled) {
        boolean bypassSSL = "true".equalsIgnoreCase(
                this.context.getProperty(BYPASS_SSL_VALIDATION).getValue());

        if (bypassSSL) {
            return (hostname, session) -> true;
        } else {
            return super.getHostnameVerifier(hostnameVerificationEnabled);
        }
    }

    @Override
    protected int getMaxConnections() {
        return this.context.getProperty(MAX_POOL_SIZE).asInteger();
    }

    @Override
    protected int getConnectionTimeout() {
        return this.context.getProperty(CONNECTION_TIMEOUT).asInteger();
    }
}