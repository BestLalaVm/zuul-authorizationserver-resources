package saas.authorizationserver.configs;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

/**
 * https://www.cnblogs.com/hellxz/p/oauth2_oauthcode_pattern.html
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationConfig extends AuthorizationServerConfigurerAdapter {
    private final PasswordEncoder passwordEncoder;

    public AuthorizationConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        //super.configure(security);
        security.allowFormAuthenticationForClients()
                .checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //super.configure(clients);
        clients.inMemory()
                .withClient("client-a")//client端唯一标识
                .secret(passwordEncoder.encode("client-a-secret"))//客户端密码
                .authorizedGrantTypes("authorization_code")//授权模式标识
                .scopes("read_user_info")//作用域
                .resourceIds("resource1")//资源id
                .redirectUris("http://localhost:9001/callback")//回调地址
                .scopes("read_depart_info")
                .resourceIds("depart_resource")
        ;
    }
}
