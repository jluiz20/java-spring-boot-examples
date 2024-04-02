package xyz.joaovieira.security.resourceserver.converters;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.Jwt;
import xyz.joaovieira.security.resourceserver.models.MyAuthenticationToken;
import xyz.joaovieira.security.resourceserver.models.MyPrincipal;

import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

public class MyPrincipalJwtConverter implements Converter<Jwt, MyAuthenticationToken> {

    @Override
    public MyAuthenticationToken convert(Jwt jwt) {
        var principal = userInfo(jwt);
        return new MyAuthenticationToken(principal);
    }

    private MyPrincipal userInfo(Jwt jwt) {
        return MyPrincipal.builder()
                .authType(jwt.getClaim("authType"))
                .userId(jwt.getClaim("userId"))
                .roles(parseList(jwt.getClaim("roles")))
                .build();
    }

    private List<String> parseList(Object object) {
        if (object == null) {
            return emptyList();
        }

        if (object instanceof List list) {
            return list;
        } else if (object instanceof String string) {
            return singletonList(string);
        }

        return emptyList();
    }
}

