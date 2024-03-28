package xyz.joaovieira.security.resourceserver.models;


import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serial;
import java.util.Collections;
import java.util.Optional;

public class MyAuthenticationToken extends AbstractAuthenticationToken {

    @Serial
    private static final long serialVersionUID = 5459984705338594748L;

    private final transient MyPrincipal principal;

    public MyAuthenticationToken(MyPrincipal principal) {
        super(Optional.ofNullable(principal.getRoles()).orElse(Collections.emptyList())
                .stream()
                .map(SimpleGrantedAuthority::new)
                .toList());
        this.principal = principal;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
