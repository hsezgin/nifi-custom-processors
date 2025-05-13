package org.sezgin.processors;

import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;

/**
 * Custom SocketFactory for LDAP connections that bypasses SSL certificate validation.
 * This is used when the Bypass SSL Validation property is set to true.
 */
public class InsecureLDAPSocketFactory extends SocketFactory {

    private static final InsecureLDAPSocketFactory DEFAULT = new InsecureLDAPSocketFactory();

    /**
     * Get the default instance of this socket factory
     */
    public static SocketFactory getDefault() {
        return DEFAULT;
    }

    /**
     * Creates an SSL socket that accepts all certificates
     */
    private SSLSocket createSSLSocket() throws IOException {
        try {
            // Create SSL context that trusts all certificates
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{
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

            // Create SSL socket factory
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            // Create socket
            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket();

            // Disable hostname verification
            socket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"});

            return socket;
        } catch (Exception e) {
            throw new IOException("Failed to create insecure SSL socket", e);
        }
    }

    @Override
    public Socket createSocket() throws IOException {
        return createSSLSocket();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        SSLSocket socket = createSSLSocket();
        socket.connect(new java.net.InetSocketAddress(host, port));
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        SSLSocket socket = createSSLSocket();
        socket.bind(new java.net.InetSocketAddress(localHost, localPort));
        socket.connect(new java.net.InetSocketAddress(host, port));
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        SSLSocket socket = createSSLSocket();
        socket.connect(new java.net.InetSocketAddress(host, port));
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        SSLSocket socket = createSSLSocket();
        socket.bind(new java.net.InetSocketAddress(localAddress, localPort));
        socket.connect(new java.net.InetSocketAddress(address, port));
        return socket;
    }
}