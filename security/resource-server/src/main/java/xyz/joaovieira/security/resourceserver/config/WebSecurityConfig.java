package xyz.joaovieira.security.resourceserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import xyz.joaovieira.security.resourceserver.converters.MyPrincipalJwtConverter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Configuration
public class WebSecurityConfig {

    @Value("${security.whitelisted_urls:#{null}}")
    private String[] whitelistedUrls;

    @Value("${security.jwt.password}")
    private String jwtPassword;

    @Bean
    JwtDecoder jwtDecoder() {
        byte[] secretKeyBytes = Base64.getDecoder().decode(jwtPassword);

        SecretKey secretKey = new SecretKeySpec(secretKeyBytes, JwsAlgorithms.HS512);

        return NimbusJwtDecoder
                .withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.HS512)
                .build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http.authorizeRequests()
                .requestMatchers(whitelistedUrls)
                .permitAll()
                .and()
                .csrf().ignoringRequestMatchers(whitelistedUrls)
                // register the decoder that will decrypt the JWT principal using the converter below
                .and()
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(jwtDecoder())
                                .jwtAuthenticationConverter(new MyPrincipalJwtConverter()))
                )
                .authorizeRequests()
                .anyRequest()
                .authenticated().and().build();
    }
}
