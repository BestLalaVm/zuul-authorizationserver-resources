package saas.keycloakopenidsecurity.configs;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.Collection;

/**
 * 支持Keycloak到应用中的Spring security的映射.
 */
public class CustomGrantedAuthoritesMapper implements GrantedAuthoritiesMapper {

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        return authorities;
    }
}
