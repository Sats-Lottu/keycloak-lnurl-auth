package keycloak.auth.lnurl;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public final class LnurlIdentityProviderFactory extends AbstractIdentityProviderFactory<LnurlIdentityProvider> {
    @Override
    public String getId() {
        return "lnurl-auth";
    }

    @Override
    public String getName() {
        return "Lightning wallet";
    }

    @Override
    public LnurlIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new LnurlIdentityProvider(session, model);
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new IdentityProviderModel();
    }
}
