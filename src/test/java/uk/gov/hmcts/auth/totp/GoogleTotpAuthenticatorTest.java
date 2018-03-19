package uk.gov.hmcts.auth.totp;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class GoogleTotpAuthenticatorTest {

    @Test
    public void tokensAreTheSameAsGeneratedByGoogleAuthenticator() {
        // QR codes for google authenticator:
        // - https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/User?secret=AAAAAAAAAAAAAAAA
        // - https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/User?secret=BBBBBBBBBBBBBBBB
        GoogleTotpAuthenticator totpAuthenticator = authenticatorAt("2017-02-17T12:14:03.00Z");
        assertThat(totpAuthenticator.issueOneTimePassword("AAAAAAAAAAAAAAAA")).isEqualTo("082380");
        assertThat(totpAuthenticator.issueOneTimePassword("BBBBBBBBBBBBBBBB")).isEqualTo("638802");
    }

    @Test
    public void isTokenValid() {
        assertThat(authenticatorAt("2017-02-17T12:14:03.00Z").isOneTimePasswordValid("AAAAAAAAAAAAAAAA", "082380")).isTrue();
        assertThat(authenticatorAt("2017-02-17T12:14:03.00Z").isOneTimePasswordValid("AAAAAAAAAAAAAAAA", "082381")).isFalse();
        assertThat(authenticatorAt("2017-02-17T12:14:29.99Z").isOneTimePasswordValid("AAAAAAAAAAAAAAAA", "082380")).isTrue();
        assertThat(authenticatorAt("2017-02-17T12:15:00.00Z").isOneTimePasswordValid("AAAAAAAAAAAAAAAA", "082380")).isFalse();
    }

    @Test
    public void isTokenValidOnPreviousTimeStep() {

        String key = "AAAAAAAAAAAAAAAA";
        Instant now = Instant.now();

        String otp =  authenticatorAt(now).issueOneTimePassword(key);

        assertThat( authenticatorAt(now).isOneTimePasswordValid(key, otp)).isTrue();

        /* On next window */
        assertThat(authenticatorAt(now.plusMillis(GoogleTotpAuthenticator.TIME_STEP)).isOneTimePasswordValid(key, otp)).isTrue();

        /* On 2 next windows where token wont be valid */
        assertThat(authenticatorAt(now.plusMillis(GoogleTotpAuthenticator.TIME_STEP * 2)).isOneTimePasswordValid(key, otp)).isFalse();

    }

    @Test
    public void isTokenValidWhenIssuedAtEndOfWindow() {

        String key = "AAAAAAAAAAAAAAAA";

        long now = System.currentTimeMillis();

        long windowStart = now - now % GoogleTotpAuthenticator.TIME_STEP;

        String tokenAtEndOfWindow = authenticatorAt(Instant.ofEpochMilli(windowStart + GoogleTotpAuthenticator.TIME_STEP - 1)).issueOneTimePassword(key);

        assertThat(authenticatorAt(Instant.ofEpochMilli(windowStart + GoogleTotpAuthenticator.TIME_STEP + 1)).isOneTimePasswordValid(key, tokenAtEndOfWindow)).isTrue();
        assertThat(authenticatorAt(Instant.ofEpochMilli(windowStart + GoogleTotpAuthenticator.TIME_STEP * 2 + 1)).isOneTimePasswordValid(key, tokenAtEndOfWindow)).isFalse();
    }

    private GoogleTotpAuthenticator authenticatorAt(Instant instant) {
        return new GoogleTotpAuthenticator(withTime(instant));
    }


    private GoogleTotpAuthenticator authenticatorAt(String dateTime) {
        return new GoogleTotpAuthenticator(withTime(dateTime));
    }

    private Clock withTime(String dateTime) {
        return Clock.fixed(Instant.parse(dateTime), ZoneId.of("GMT"));
    }

    private Clock withTime(Instant instant) {
        return Clock.fixed(instant , ZoneId.of("GMT"));
    }
}
