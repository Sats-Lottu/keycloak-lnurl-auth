package keycloak.auth.lnurl;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;

import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

public final class LnurlIdentityProvider extends AbstractIdentityProvider<IdentityProviderModel> {
    private static final long LIFETIME = 180;
    private static final SecureRandom RANDOM = new SecureRandom();

    public LnurlIdentityProvider(KeycloakSession session, IdentityProviderModel config) {
        super(session, config);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        var auth = request.getAuthenticationSession();
        if (auth == null || request.getState() == null) return invalid(auth);

        URI endpoint = URI.create(request.getRedirectUri());
        if (!walletTransportAllowed(endpoint)) {
            return invalid(auth);
        }

        String challenge = randomHex();
        String ticket = randomHex();
        auth.setAuthNote(note(), ticket);
        session.singleUseObjects().put(key("pending", challenge), LIFETIME, Map.of(
                "ticket", ticket, "expires", Long.toString(now() + LIFETIME)));

        URI wallet = UriBuilder.fromUri(endpoint).path("wallet")
                .queryParam("tag", "login").queryParam("k1", challenge).build();
        String lnurl = Lnurl.encode(wallet.toASCIIString());
        var qr = Lnurl.qr(lnurl);
        return session.getProvider(LoginFormsProvider.class).setAuthenticationSession(auth)
                .setAttribute("brokerState", request.getState().getEncoded())
                .setAttribute("brokerTicket", ticket)
                .setAttribute("finishUrl", UriBuilder.fromUri(endpoint).path("finish").build())
                .setAttribute("statusUrl", UriBuilder.fromUri(endpoint).path("status").build())
                .setAttribute("lnurl", lnurl)
                .setAttribute("loopbackWallet", isLoopbackHost(wallet.getHost()))
                .setAttribute("qrSize", qr.size())
                .setAttribute("qrPath", qr.path())
                .createForm("kc-lnurl-auth.ftl");
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(this, callback);
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity,
                                  UserSessionModel userSession, UserModel user) {
        return retrieveToken(session, identity);
    }

    private Response invalid(AuthenticationSessionModel auth) {
        return ErrorPage.error(session, auth, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    private String note() {
        return "keycloak.auth.lnurl." + getConfig().getAlias();
    }

    private String key(String purpose, String token) {
        return note() + ":" + session.getContext().getRealm().getId() + ":" + purpose + ":" + token;
    }

    private static String randomHex() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    private static boolean walletTransportAllowed(URI endpoint) {
        String host = endpoint.getHost();
        return "https".equals(endpoint.getScheme()) ||
                ("http".equals(endpoint.getScheme()) && host != null && (host.endsWith(".onion") ||
                isLoopbackHost(host)));
    }

    private static boolean isLoopbackHost(String host) {
        return "localhost".equals(host) || "127.0.0.1".equals(host) || "[::1]".equals(host);
    }

    @Provider
    @Vetoed // The broker constructs this resource with the active provider and callback.
    public static final class Endpoint {
        private final LnurlIdentityProvider provider;
        private final AuthenticationCallback callback;

        Endpoint(LnurlIdentityProvider provider, AuthenticationCallback callback) {
            this.provider = provider;
            this.callback = callback;
        }

        @GET
        @Path("wallet")
        @Produces(MediaType.APPLICATION_JSON)
        public Response wallet(@jakarta.ws.rs.core.Context UriInfo uri) {
            var query = uri.getQueryParameters();
            String challenge = single(query.get("k1"));
            String signature = single(query.get("sig"));
            String publicKey = single(query.get("key"));
            if (!"login".equals(single(query.get("tag"))) || !Lnurl.matches(Lnurl.CHALLENGE, challenge)) {
                return walletResult(false);
            }

            var objects = provider.session.singleUseObjects();
            String pendingKey = provider.key("pending", challenge);
            var pending = objects.get(pendingKey);
            if (pending == null) return walletResult(false);

            long expiresAt = Long.parseLong(pending.get("expires"));
            String address = provider.session.getContext().getConnection().getRemoteAddr();
            if (!VerificationRateLimit.allow(objects, provider.key("rate-address", address),
                    provider.key("rate-challenge", challenge), now(), expiresAt)) {
                return walletError("Too many attempts or expired LNURL-auth request");
            }
            if (!Lnurl.verify(challenge, publicKey, signature)) {
                return walletResult(false);
            }

            if (objects.remove(pendingKey) == null) return walletResult(false);
            long remaining = expiresAt - now();
            if (remaining <= 0) return walletResult(false);

            objects.put(provider.key("ready", pending.get("ticket")), remaining,
                    Map.of("subject", publicKey.toLowerCase(Locale.ROOT)));
            return walletResult(true);
        }

        @POST
        @Path("status")
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        public Response status(@FormParam("ticket") String ticket) {
            boolean ready = Lnurl.matches(Lnurl.CHALLENGE, ticket)
                    && provider.session.singleUseObjects().contains(provider.key("ready", ticket));
            return Response.status(ready ? 204 : 404).header("Cache-Control", "no-store").build();
        }

        @POST
        @Path("finish")
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        public Response finish(@FormParam("state") String state, @FormParam("ticket") String ticket) {
            if (state == null || !Lnurl.matches(Lnurl.CHALLENGE, ticket)) return provider.invalid(null);
            var auth = callback.getAndVerifyAuthenticationSession(state);
            if (!ticket.equals(auth.getAuthNote(provider.note()))) return provider.invalid(auth);
            var proof = provider.session.singleUseObjects().remove(provider.key("ready", ticket));
            if (proof == null) return provider.invalid(auth);

            provider.session.getContext().setAuthenticationSession(auth);
            auth.removeAuthNote(provider.note());
            String subject = proof.get("subject");
            var identity = new BrokeredIdentityContext(subject, provider.getConfig());
            identity.setUsername("ln-" + subject);
            identity.setIdp(provider);
            identity.setAuthenticationSession(auth);
            return callback.authenticated(identity);
        }

        private static String single(java.util.List<String> values) {
            return values != null && values.size() == 1 ? values.getFirst() : null;
        }

        private static Response walletResult(boolean success) {
            return success ? walletResponse(Map.of("status", "OK"))
                    : walletError("Invalid, expired or already used LNURL-auth request");
        }

        private static Response walletError(String reason) {
            return walletResponse(Map.of("status", "ERROR", "reason", reason));
        }

        private static Response walletResponse(Map<String, String> result) {
            return Response.ok(result).header("Cache-Control", "no-store")
                    .header("Access-Control-Allow-Origin", "*").build();
        }
    }
}
