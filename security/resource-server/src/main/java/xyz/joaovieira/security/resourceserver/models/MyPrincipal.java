package xyz.joaovieira.security.resourceserver.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.Principal;
import java.util.Collections;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class MyPrincipal implements Principal {

    private String userId;
    private String authType;

    @Builder.Default
    private List<String> roles = Collections.emptyList();

    @Override
    public String getName() {
        return userId;
    }
}
