package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestFailure;
import dev.chainguard.fipstest.util.VectorFile;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * Shared Wycheproof signature-verification vector driver, used by the RSA,
 * ECDSA and EdDSA suites. Wycheproof semantics: result=valid must verify;
 * result=invalid must NOT verify (returning false and throwing are both
 * legitimate rejections); result=acceptable tolerates either outcome.
 * These vectors carry the classic provider-regression cases: DER/BER
 * malleability, r/s boundary values, padding tricks.
 */
final class SignatureVectors {

    private SignatureVectors() {
    }

    static void register(TestContext ctx, String label, String vectorFile,
                         String keyFactoryAlgorithm, String signatureAlgorithm)
            throws Exception {
        VectorFile vf = ctx.vectors(vectorFile);
        for (VectorFile.Record rec : vf.records()) {
            ctx.add(label + "/wycheproof/" + rec.id(), () -> {
                PublicKey publicKey;
                try {
                    KeyFactory kf = KeyFactory.getInstance(keyFactoryAlgorithm, "BCFIPS");
                    publicKey = kf.generatePublic(
                            new X509EncodedKeySpec(rec.bytes("publicKeyDer")));
                } catch (Throwable t) {
                    throw new TestFailure(label + " " + rec.id()
                            + ": test public key rejected: " + t, t);
                }

                boolean verified;
                try {
                    Signature sig = Signature.getInstance(signatureAlgorithm, "BCFIPS");
                    sig.initVerify(publicKey);
                    sig.update(rec.bytes("msg"));
                    verified = sig.verify(rec.bytes("sig"));
                } catch (Throwable t) {
                    verified = false; // an exception is a rejection
                }

                String result = rec.result();
                if ("valid".equals(result) && !verified) {
                    throw new TestFailure(label + " " + rec.id()
                            + " valid signature did not verify (" + rec.comment() + ")");
                }
                if ("invalid".equals(result) && verified) {
                    throw new TestFailure(label + " " + rec.id()
                            + " invalid signature verified (failure to fail: "
                            + rec.comment() + ", flags="
                            + rec.getOrDefault("flags", "") + ")");
                }
                // "acceptable": either outcome passes.
            });
        }
    }
}
