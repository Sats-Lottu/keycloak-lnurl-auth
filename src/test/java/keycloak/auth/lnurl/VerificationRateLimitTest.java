package keycloak.auth.lnurl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;
import org.keycloak.models.SingleUseObjectProvider;

class VerificationRateLimitTest {
    private final Set<String> entries = ConcurrentHashMap.newKeySet();
    private final SingleUseObjectProvider cache = (SingleUseObjectProvider) Proxy.newProxyInstance(
            SingleUseObjectProvider.class.getClassLoader(), new Class<?>[]{SingleUseObjectProvider.class},
            (proxy, method, arguments) -> switch (method.getName()) {
                case "contains" -> entries.contains(arguments[0]);
                case "putIfAbsent" -> entries.add((String) arguments[0]);
                default -> throw new UnsupportedOperationException(method.getName());
            });

    @Test
    void capsConcurrentVerificationAcrossAddressesForTheSameChallenge() {
        long accepted = IntStream.range(0, 40).parallel()
                .filter(attempt -> VerificationRateLimit.allow(cache, "address-" + attempt, "challenge", 101, 280))
                .count();
        assertEquals(5, accepted);
        assertFalse(VerificationRateLimit.allow(cache, "new-address", "challenge", 111, 280));
        assertTrue(VerificationRateLimit.allow(cache, "new-address", "new-challenge", 111, 280));
    }

    @Test
    void capsAnAddressAcrossChallengesAndResetsAtTheNextWindow() {
        long accepted = IntStream.range(0, 40).parallel()
                .filter(attempt -> VerificationRateLimit.allow(cache, "address", "challenge-" + attempt, 101, 280))
                .count();
        assertEquals(20, accepted);
        assertFalse(VerificationRateLimit.allow(cache, "address", "unused-challenge", 109, 280));
        assertTrue(VerificationRateLimit.allow(cache, "address", "unused-challenge", 110, 280));
        assertTrue(VerificationRateLimit.allow(cache, "other-address", "another-challenge", 109, 280));
    }

    @Test
    void rejectsExpiredChallengesBeforeReservingAttempts() {
        assertFalse(VerificationRateLimit.allow(cache, "address", "challenge", 280, 280));
        assertTrue(entries.isEmpty());
    }
}
