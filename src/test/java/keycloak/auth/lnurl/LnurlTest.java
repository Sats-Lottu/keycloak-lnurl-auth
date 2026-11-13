package keycloak.auth.lnurl;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.HexFormat;

import com.google.zxing.qrcode.decoder.Decoder;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.junit.jupiter.api.Test;

class LnurlTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final String URL = "https://service.com/api?q=3fc3645b439ce8e7f2553a69e5267081d96dcd340693afabe04be7b0ccd178df";
    private static final String ENCODED = "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZEPEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS";

    @Test
    void encodesTheLud01Example() {
        assertEquals(ENCODED, Lnurl.encode(URL));
    }

    @Test
    void qrHasQuietZoneAndDecodesToLnurl() throws Exception {
        var qr = Lnurl.qr(ENCODED);
        var modules = new boolean[qr.size() - 8][qr.size() - 8];
        var coordinates = java.util.regex.Pattern.compile("M(\\d+) (\\d+)h1v1h-1z").matcher(qr.path());
        while (coordinates.find()) {
            int x = Integer.parseInt(coordinates.group(1));
            int y = Integer.parseInt(coordinates.group(2));
            modules[y - 4][x - 4] = true;
        }
        assertEquals(ENCODED, new Decoder().decode(modules).getText());
    }

    @Test
    void verifiesRawChallengeAndStrictDer() throws Exception {
        var curve = CustomNamedCurves.getByName("secp256k1");
        var secret = BigInteger.valueOf(42);
        String challenge = "ab".repeat(32);
        String key = HEX.formatHex(curve.getG().multiply(secret).getEncoded(true));
        var signer = new ECDSASigner();
        signer.init(true, new ECPrivateKeyParameters(secret, new ECDomainParameters(curve)));
        var rs = signer.generateSignature(HEX.parseHex(challenge));
        String sig = HEX.formatHex(StandardDSAEncoding.INSTANCE.encode(curve.getN(), rs[0], rs[1]));

        assertTrue(Lnurl.verify(challenge, key, sig));
        assertFalse(Lnurl.verify("cd".repeat(32), key, sig));
        assertFalse(Lnurl.verify(challenge, "02" + "ff".repeat(32), sig));
        assertFalse(Lnurl.verify(challenge, key, sig + "00"));
        assertFalse(Lnurl.verify(challenge, key, null));
    }
}
