package keycloak.auth.lnurl;

import org.keycloak.models.SingleUseObjectProvider;

final class VerificationRateLimit {
    private static final int ADDRESS_ATTEMPTS = 20;
    private static final long ADDRESS_WINDOW_SECONDS = 10;
    private static final int CHALLENGE_ATTEMPTS = 5;

    private VerificationRateLimit() {}

    static boolean allow(SingleUseObjectProvider cache, String addressKey, String challengeKey,
                         long now, long expiresAt) {
        if (expiresAt <= now) return false;

        long window = Math.floorDiv(now, ADDRESS_WINDOW_SECONDS);
        long windowRemaining = ADDRESS_WINDOW_SECONDS - Math.floorMod(now, ADDRESS_WINDOW_SECONDS);
        return claim(cache, addressKey + ":" + window, ADDRESS_ATTEMPTS, windowRemaining)
                && claim(cache, challengeKey, CHALLENGE_ATTEMPTS, expiresAt - now);
    }

    private static boolean claim(SingleUseObjectProvider cache, String key, int attempts, long ttl) {
        // Each successful atomic insertion reserves one attempt across the Keycloak cluster.
        if (cache.contains(key + ":" + attempts)) return false;
        for (int attempt = 1; attempt <= attempts; attempt++) {
            if (cache.putIfAbsent(key + ":" + attempt, ttl)) return true;
        }
        return false;
    }
}
