package co.com.lucasian.auth.britto.cloud.security;

import co.com.lucasian.auth.britto.cloud.service.CustomerUserDetails;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;



/**
 *
 * @author DavidBritto
 */

@Configuration
public class SecurityConfig {
    
    private static final String LOGIN_RESOURCE = "/login";
    private static final String RSA = "RSA";
    private static final Integer RSA_SIZE = 2048;
    private static final String APPLICATION_OWNER = "Debuggeando ideas";
    
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity htpp) throws Exception{
        
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(htpp);
        
        htpp.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        
        htpp.exceptionHandling( e -> 
                e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(LOGIN_RESOURCE)));
                
        return htpp.build();
        
    }
    
    @Bean
    SecurityFilterChain PublicSecurityFilterChain(HttpSecurity http ) throws Exception {
      
        http.formLogin(Customizer.withDefaults()).csrf(csrf -> csrf.disable());
        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        
        return http.build();
        
    }
    
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    AuthenticationProvider authenticationProvider(PasswordEncoder encoder,  CustomerUserDetails userDetails){
        var authProvider = new DaoAuthenticationProvider();
        authProvider.setPasswordEncoder(encoder);
        authProvider.setUserDetailsService(userDetails);
        return authProvider;
    }
    
    @Bean
    AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder().build();
    }
    
    @Bean
    JWKSource<SecurityContext> jwkSource(){
        var rsa = generateKeys();
        var jwkSet = new JWKSet(rsa);
        
        return (jwkSelector,securityContext) -> jwkSelector.select(jwkSet);
    }
    
    @Bean
    JwtDecoder jwtDecoder( JWKSource<SecurityContext> jwkSource){
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
    
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer(){
        return context ->{
            var authentication = context.getPrincipal();
            var authorities = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());            
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN) ||  context.getTokenType().equals(OAuth2TokenType.REFRESH_TOKEN)) {
                context.getClaims().claims(claim -> 
                        claim.putAll(Map.of(
                                "roles", authorities,
                                "owner", APPLICATION_OWNER,
                                "date_request",LocalDateTime.now().toString())));
            }
        };
    }
    
    @Bean
    RegisteredClientRepository registeredClient(){
         RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                 .clientId("debuggeandoideas")
                 .clientSecret("$2a$10$v2jjQdxObou5FktwHIaTvOZGxThhIyDu28U8z5b8Jku1TemjUuwO2")
                 .clientName("debuggeando ideas")
                 .redirectUri("http://localhost:9000/authorized")                 
                 .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)                                 
                 .scope("read")
                 .scope("write")
                 .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)          
                 .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                 .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) 
                 .tokenSettings(this.tokenSettings())
                 .build();
         
         return new InMemoryRegisteredClientRepository(registeredClient);      
    }
    
    private static KeyPair generateRSA(){
        KeyPair keyPair = null;
        try {
            var keyPairGenerator =KeyPairGenerator.getInstance(RSA);
            keyPairGenerator.initialize(RSA_SIZE);
            keyPair = keyPairGenerator.generateKeyPair();            
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        return keyPair;
    }
    
    private static RSAKey generateKeys(){
        var keyPair =generateRSA();
        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    }
    
     private TokenSettings tokenSettings(){
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(1))
                .build();                
    }
    
}
