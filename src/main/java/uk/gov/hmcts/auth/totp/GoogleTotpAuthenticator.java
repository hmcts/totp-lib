package uk.gov.hmcts.auth.totp;

import lombok.SneakyThrows;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Clock;

import static com.google.common.io.BaseEncoding.base32;

public class GoogleTotpAuthenticator implements TotpAuthenticator {

    /**
     * Recommended time step by RFC 6238
     */
    static final int TIME_STEP = 30000;

    private final Clock clock;

    public GoogleTotpAuthenticator() {
        this(Clock.systemDefaultZone());
    }

    public GoogleTotpAuthenticator(Clock clock) {
        this.clock = clock;
    }

    @Override
    public String issueOneTimePassword(String base32Key) {
        return issueOneTimePassword(base32Key, clock.millis());
    }

    String issueOneTimePassword(String base32Key, long millis) {
        byte[] key = base32().decode(base32Key);
        byte[] hash = calculateHash(millis / TIME_STEP, key);
        long truncatedHash = truncateHash(hash);
        return String.format("%06d", truncatedHash);
    }

    @Override
    public boolean isOneTimePasswordValid(String base32Key, String token) {

        long time = clock.millis();

        if (issueOneTimePassword(base32Key, time).equals(token)) {
            return true;
        }

        //RFC 6238 Suggests accepting at least one previous window, which should suffice.
        return issueOneTimePassword(base32Key, time - TIME_STEP).equals(token);
    }

    @SneakyThrows
    private byte[] calculateHash(long value, byte[] key) {
        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        return mac.doFinal(toBytes(value));
    }

    private byte[] toBytes(long value) {
        byte[] data = new byte[8];
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }
        return data;
    }

    private long truncateHash(byte[] hash) {
        int offset = hash[20 - 1] & 0xF;

        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash |= (hash[offset + i] & 0xFF);
        }

        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;
        return truncatedHash;
    }
}
