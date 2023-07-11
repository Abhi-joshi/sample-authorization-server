package com.abhishek.sampleauthorizationserver.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Component
public class ClientRegistration implements ApplicationRunner {
    private final RegisteredClientRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final Set<String> redirectUris;
    private final Set<String> scopes;
    private final int accessTokenDuration;
    private final int refreshTokenDuration;


    public ClientRegistration(RegisteredClientRepository repository, PasswordEncoder passwordEncoder, @Value("${app.redirect-uris}") Set<String> redirectUris, @Value("${app.scopes}") Set<String> scopes, @Value("${app.access-token-duration}") int accessTokenDuration,  @Value("${app.refresh-token-duration}") int refreshTokenDuration) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.redirectUris = redirectUris;
        this.scopes = scopes;
        this.accessTokenDuration = accessTokenDuration;
        this.refreshTokenDuration = refreshTokenDuration;
    }


    @Override
    public void run(ApplicationArguments args) {
        RegisteredClient existingOidcClient = this.repository.findByClientId("oidc-client");
        if (existingOidcClient == null) {
            RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("oidc-client")
                    .clientSecret(this.passwordEncoder.encode("oidc"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .redirectUris(redirectUris -> redirectUris.addAll(new HashSet<>(this.redirectUris)))
                    .scopes(scopes -> scopes.addAll(new HashSet<>(this.scopes)))
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).requireProofKey(true).build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofMinutes(this.accessTokenDuration))
                            .refreshTokenTimeToLive(Duration.ofHours(this.refreshTokenDuration))
                            .accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
                    .build();
            repository.save(oidcClient);
        }

    }
}
