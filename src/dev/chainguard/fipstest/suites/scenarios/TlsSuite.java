package dev.chainguard.fipstest.suites.scenarios;

import dev.chainguard.fipstest.harness.Capabilities;
import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.TestCerts;
import dev.chainguard.fipstest.util.TestKeys;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * In-process TLS over loopback with BCJSSE and BCFKS-backed identities - the
 * kafka/zookeeper/elasticsearch/tomcat pattern in miniature. Covers TLS 1.3
 * and 1.2 handshakes (RSA and ECDSA server credentials), mutual TLS, an
 * HTTPS client (the jmx-exporter FIPS package test pattern), session
 * resumption, and the protocol/cipher rejection set from kafka-fips.
 */
public final class TlsSuite implements TestSuite {

    private static final char[] PASSWORD = "FipsTest-Tls-Passw0rd!".toCharArray();

    @Override
    public String name() {
        return "scenarios.tls";
    }

    @Override
    public Set<String> tags() {
        return Set.of("scenarios", "tls");
    }

    @Override
    public void register(TestContext ctx) {
        ctx.add("context/default-provider-is-bcjsse", () -> {
            requireTls();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            Expect.assertEquals("BCJSSE", sslContext.getProvider().getName(),
                    "SSLContext provider");
        });

        ctx.add("tls13/handshake-echo-aes128gcm", () ->
                handshake("RSA", "TLSv1.3", "TLS_AES_128_GCM_SHA256", false));
        ctx.add("tls13/handshake-echo-aes256gcm", () ->
                handshake("RSA", "TLSv1.3", "TLS_AES_256_GCM_SHA384", false));
        ctx.add("tls12/handshake-echo-ecdhe-rsa", () ->
                handshake("RSA", "TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false));
        ctx.add("tls12/handshake-echo-ecdhe-ecdsa", () ->
                handshake("EC", "TLSv1.2", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", false));

        ctx.add("mtls/client-certificate-accepted", () ->
                handshake("RSA", "TLSv1.3", "TLS_AES_128_GCM_SHA256", true));

        ctx.add("mtls/negative/client-without-certificate-rejected", () -> {
            requireTls();
            Identity server = Identity.create("RSA");
            SSLContext serverContext = server.serverContext();
            SSLContext anonymousClient = clientContext(server.certificate, null);

            try (EchoServer echo = EchoServer.start(serverContext, true)) {
                Expect.mustFail("mTLS handshake without a client certificate", () -> {
                    try (SSLSocket socket = (SSLSocket) anonymousClient.getSocketFactory()
                            .createSocket(InetAddress.getLoopbackAddress(), echo.port())) {
                        socket.setSoTimeout(10_000);
                        socket.startHandshake();
                        // BCJSSE may fail on first I/O rather than handshake
                        roundTripLine(socket, "must-not-arrive");
                    }
                });
            }
        });

        ctx.add("https/client-against-in-process-server", () -> {
            requireTls();
            Identity server = Identity.create("RSA");
            try (EchoServer echo = EchoServer.startHttp(server.serverContext())) {
                SSLContext trust = clientContext(server.certificate, null);
                HttpsURLConnection connection = (HttpsURLConnection)
                        new URL("https://localhost:" + echo.port() + "/health")
                                .openConnection();
                connection.setSSLSocketFactory(trust.getSocketFactory());
                connection.setConnectTimeout(10_000);
                connection.setReadTimeout(10_000);
                Expect.assertEquals(200, connection.getResponseCode(), "HTTPS status");
                // getCipherSuite() only works while the connection is open.
                String suite = connection.getCipherSuite();
                Expect.assertTrue(suite != null && suite.contains("AES"),
                        "HTTPS negotiated suite: " + suite);
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                        connection.getInputStream(), StandardCharsets.US_ASCII))) {
                    Expect.assertEquals("OK", reader.readLine(), "HTTPS body");
                }
            }
        });

        // Resumption depends on clean close_notify semantics that a minimal
        // echo server does not guarantee, so this is a smoke test: both
        // sequential connections must work; whether the session was resumed
        // is logged for cross-version comparison, not asserted.
        ctx.add("session/sequential-connections-smoke", () -> {
            requireTls();
            Identity server = Identity.create("RSA");
            SSLContext serverContext = server.serverContext();
            SSLContext clientContext = clientContext(server.certificate, null);

            try (EchoServer echo = EchoServer.start(serverContext, false)) {
                byte[] firstId;
                try (SSLSocket first = connect(clientContext, echo.port(),
                        "TLSv1.2", null)) {
                    roundTripLine(first, "hello-1");
                    firstId = first.getSession().getId();
                }
                try (SSLSocket second = connect(clientContext, echo.port(),
                        "TLSv1.2", null)) {
                    roundTripLine(second, "hello-2");
                    SSLSession session = second.getSession();
                    System.out.println("INFO|tls session resumed on 2nd connection: "
                            + java.util.Arrays.equals(firstId, session.getId()));
                }
            }
        });

        ctx.add("negative/tlsv11-handshake-rejected", () -> {
            requireTls();
            Identity server = Identity.create("RSA");
            try (EchoServer echo = EchoServer.start(server.serverContext(), false)) {
                SSLContext client = clientContext(server.certificate, null);
                Expect.mustFail("TLSv1.1 handshake against FIPS config", () -> {
                    try (SSLSocket socket = (SSLSocket) client.getSocketFactory()
                            .createSocket(InetAddress.getLoopbackAddress(), echo.port())) {
                        socket.setSoTimeout(10_000);
                        socket.setEnabledProtocols(new String[] {"TLSv1.1"});
                        socket.startHandshake();
                    }
                });
            }
        });

        ctx.add("negative/chacha20-suite-unavailable", () -> {
            requireTls();
            Identity server = Identity.create("RSA");
            try (EchoServer echo = EchoServer.start(server.serverContext(), false)) {
                SSLContext client = clientContext(server.certificate, null);
                Expect.mustFail("TLS_CHACHA20_POLY1305_SHA256-only handshake", () -> {
                    try (SSLSocket socket = (SSLSocket) client.getSocketFactory()
                            .createSocket(InetAddress.getLoopbackAddress(), echo.port())) {
                        socket.setSoTimeout(10_000);
                        socket.setEnabledCipherSuites(
                                new String[] {"TLS_CHACHA20_POLY1305_SHA256"});
                        socket.startHandshake();
                    }
                });
            }
        });

        // kafka-fips rejection pattern: an Ed25519 server credential must not
        // produce a working TLS server in approved mode.
        ctx.addApproved("negative/ed25519-server-credential-rejected-approved", () -> {
            requireTls();
            Capabilities.require("Signature", "Ed25519", "BCFIPS");
            Expect.mustFail("TLS handshake with Ed25519 server credential", () -> {
                KeyPair kp = TestKeys.eddsa("Ed25519");
                X509Certificate cert = TestCerts.selfSignedCa(kp,
                        "CN=localhost", "Ed25519");
                Identity identity = new Identity(kp, cert);
                try (EchoServer echo = EchoServer.start(identity.serverContext(), false)) {
                    SSLContext client = clientContext(cert, null);
                    try (SSLSocket socket = connect(client, echo.port(), null, null)) {
                        roundTripLine(socket, "must-not-arrive");
                    }
                }
            });
        });
    }

    /** Full handshake + negotiation assertions + echo round-trip. */
    private static void handshake(String serverKeyType, String protocol,
                                  String cipherSuite, boolean mutual) throws Exception {
        requireTls();
        Identity server = Identity.create(serverKeyType);
        Identity client = mutual ? Identity.createClient() : null;

        SSLContext serverContext = mutual
                ? server.serverContextTrusting(client.certificate)
                : server.serverContext();
        SSLContext clientContext = clientContext(server.certificate, client);

        try (EchoServer echo = EchoServer.start(serverContext, mutual)) {
            try (SSLSocket socket = connect(clientContext, echo.port(),
                    protocol, cipherSuite)) {
                roundTripLine(socket, "fips-echo-payload");
                SSLSession session = socket.getSession();
                Expect.assertEquals(protocol, session.getProtocol(),
                        "negotiated protocol");
                Expect.assertEquals(cipherSuite, session.getCipherSuite(),
                        "negotiated cipher suite");
            }
        }
    }

    private static SSLSocket connect(SSLContext clientContext, int port,
                                     String protocol, String cipherSuite)
            throws IOException {
        SSLSocket socket = (SSLSocket) clientContext.getSocketFactory()
                .createSocket(InetAddress.getLoopbackAddress(), port);
        socket.setSoTimeout(15_000);
        if (protocol != null) {
            socket.setEnabledProtocols(new String[] {protocol});
        }
        if (cipherSuite != null) {
            socket.setEnabledCipherSuites(new String[] {cipherSuite});
        }
        socket.startHandshake();
        return socket;
    }

    private static void roundTripLine(SSLSocket socket, String line) throws IOException {
        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
        writer.println(line);
        String echoed = reader.readLine();
        Expect.assertEquals(line, echoed, "echoed line");
    }

    private static SSLContext clientContext(X509Certificate serverCert, Identity client)
            throws Exception {
        KeyStore trust = KeyStore.getInstance("BCFKS", "BCFIPS");
        trust.load(null, null);
        trust.setCertificateEntry("server", serverCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(trust);

        SSLContext context = SSLContext.getInstance("TLS", "BCJSSE");
        if (client == null) {
            context.init(null, tmf.getTrustManagers(), null);
        } else {
            context.init(client.keyManagers(), tmf.getTrustManagers(), null);
        }
        return context;
    }

    /** BCFKS-backed server/client identity, keytool-flow equivalent. */
    private static final class Identity {
        final KeyPair keyPair;
        final X509Certificate certificate;

        Identity(KeyPair keyPair, X509Certificate certificate) {
            this.keyPair = keyPair;
            this.certificate = certificate;
        }

        static Identity create(String keyType) throws Exception {
            KeyPair kp = "EC".equals(keyType) ? TestKeys.ec("P-256")
                    : TestKeys.rsaSign(2048);
            String sigAlg = "EC".equals(keyType) ? "SHA256withECDSA" : "SHA256withRSA";
            // serverLeaf provides SAN=localhost; self-issued for simplicity.
            X509Certificate cert = TestCerts.serverLeaf(kp.getPublic(),
                    "CN=localhost", kp, "CN=localhost", sigAlg);
            return new Identity(kp, cert);
        }

        /** Distinct key and a client-auth (no serverAuth EKU) certificate. */
        static Identity createClient() throws Exception {
            KeyPair kp = TestKeys.rsaSign(3072);
            X509Certificate cert = TestCerts.clientLeaf(kp.getPublic(),
                    "CN=fipstest-client", kp, "CN=fipstest-client", "SHA256withRSA");
            return new Identity(kp, cert);
        }

        javax.net.ssl.KeyManager[] keyManagers() throws Exception {
            KeyStore store = KeyStore.getInstance("BCFKS", "BCFIPS");
            store.load(null, null);
            store.setKeyEntry("identity", keyPair.getPrivate(), PASSWORD,
                    new Certificate[] {certificate});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
            kmf.init(store, PASSWORD);
            return kmf.getKeyManagers();
        }

        SSLContext serverContext() throws Exception {
            SSLContext context = SSLContext.getInstance("TLS", "BCJSSE");
            context.init(keyManagers(), null, null);
            return context;
        }

        SSLContext serverContextTrusting(X509Certificate clientCert) throws Exception {
            KeyStore trust = KeyStore.getInstance("BCFKS", "BCFIPS");
            trust.load(null, null);
            trust.setCertificateEntry("client", clientCert);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(trust);
            SSLContext context = SSLContext.getInstance("TLS", "BCJSSE");
            context.init(keyManagers(), tmf.getTrustManagers(), null);
            return context;
        }
    }

    /** Minimal loopback echo/HTTP server on its own thread. */
    private static final class EchoServer implements AutoCloseable {
        private final SSLServerSocket serverSocket;
        private final ExecutorService executor;
        private final Future<?> loop;

        private EchoServer(SSLServerSocket serverSocket, ExecutorService executor,
                           Future<?> loop) {
            this.serverSocket = serverSocket;
            this.executor = executor;
            this.loop = loop;
        }

        int port() {
            return serverSocket.getLocalPort();
        }

        static EchoServer start(SSLContext context, boolean needClientAuth)
                throws IOException {
            return launch(context, needClientAuth, EchoServer::echoLines);
        }

        static EchoServer startHttp(SSLContext context) throws IOException {
            return launch(context, false, EchoServer::answerHttp);
        }

        private interface Handler {
            void handle(SSLSocket socket) throws IOException;
        }

        private static EchoServer launch(SSLContext context, boolean needClientAuth,
                                         Handler handler) throws IOException {
            SSLServerSocket serverSocket = (SSLServerSocket) context
                    .getServerSocketFactory().createServerSocket(0, 8,
                            InetAddress.getLoopbackAddress());
            serverSocket.setNeedClientAuth(needClientAuth);
            serverSocket.setSoTimeout(30_000);
            ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "fipstest-tls-server");
                t.setDaemon(true);
                return t;
            });
            Future<?> loop = executor.submit(() -> {
                while (!serverSocket.isClosed()) {
                    try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                        socket.setSoTimeout(15_000);
                        handler.handle(socket);
                    } catch (IOException e) {
                        if (serverSocket.isClosed()) {
                            return;
                        }
                        // handshake failures from negative tests are expected;
                        // keep serving
                    }
                }
            });
            return new EchoServer(serverSocket, executor, loop);
        }

        private static void echoLines(SSLSocket socket) throws IOException {
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.US_ASCII));
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
            String line;
            while ((line = reader.readLine()) != null) {
                writer.println(line);
            }
        }

        private static void answerHttp(SSLSocket socket) throws IOException {
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.US_ASCII));
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                // drain request headers
            }
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
            writer.print("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n"
                    + "Connection: close\r\n\r\nOK\n");
            writer.flush();
        }

        @Override
        public void close() {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
                // closing is best-effort
            }
            loop.cancel(true);
            executor.shutdownNow();
            try {
                executor.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static void requireTls() {
        Capabilities.requireProvider("BCJSSE");
        Capabilities.requireClass("org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder");
    }
}
