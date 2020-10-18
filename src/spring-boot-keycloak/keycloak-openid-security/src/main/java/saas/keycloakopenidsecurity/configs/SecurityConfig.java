package saas.keycloakopenidsecurity.configs;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootProperties;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticatedActionsFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakSecurityContextRequestFilter;
import org.keycloak.adapters.springsecurity.management.HttpSessionManager;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.HttpSessionEventPublisher;

/**
 * @KeycloakConfiguration注解是注解的元数据信息，它包含了索要集成keuCloak所需要的注解,
 * 如我们有完整的Spring security启动的话, 我们可以检查下@Keycloak的实现, 不进行定制化Keycloak适配器
 *
 * Keycloak spring security还支持多租户模式.
 * Multi Tenancy
 *
 * 在Keycloak中基于角色的认证必须以ROLE_开头, 比如ADMIN的话,则需要定义为: ROLE_ADMIN
 *https://www.keycloak.org/docs/latest/securing_apps/index.html#client-to-client-support
 */
@KeycloakConfiguration
public class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {
    private final KeycloakClientRequestFactory keycloakClientRequestFactory;

    public SecurityConfig(KeycloakClientRequestFactory keycloakClientRequestFactory) {
        this.keycloakClientRequestFactory = keycloakClientRequestFactory;
    }

    /**
     * 为了简化客户端于keyCloak之间的交互, 我们扩展了RestTemplate并使用bearer token的方式进行交互.
     * 这边的Scope必须是propotype
     * 这样才可以不共享这个KeycloakRestTemplate
     * @return
     */
    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public KeycloakRestTemplate keycloakRestTemplate() {
        return new KeycloakRestTemplate(keycloakClientRequestFactory);
    }

    @Bean
    public ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisher() {
        return new ServletListenerRegistrationBean<>(new HttpSessionEventPublisher());
    }

    /**
     * 定义存储session的策略
     * keyCloak中sessionFixationProtectionStrategy目前是不支持的, 因为它将在用户登入之后修改session的标识,
     * 如果标识发生变化的话, 那么注销将无法工作, 因为Keycloak无法识别新的session 标识
     * @return
     */
    @Override
    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    /**
     * 注册KeycloakAuthenticationProvider with authentication manager
     * @param auth
     * @throws Exception
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(keycloakAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http.authorizeRequests().anyRequest().hasAnyRole("ADMIN");
        /*
        http.logout().logoutSuccessUrl("/")
                .and()
                .authorizeRequests()
                .antMatchers("/**").hasAuthority("user");

         */
    }

    @Bean
    public AdapterConfig adapterConfig() {
        return new KeycloakSpringBootProperties();
    }

    /**
     * 默认情况下, Spring Security适配器将查找keycloak.json配置文件.
     * 我们可以使用如下配置来采用Spring boot adapter的方式(也就是普通的application.properties的方式)
     *
     *  因为采用application.xml的方式进行配置的, 所以必须要注入一个AdapterConfig的实现.
     *  刚好KeycloakSpringBootProperties用来从application.加载配置的. 所以满足条件
     * @return
     */
    @Bean
    public KeycloakConfigResolver keycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

   //region Spring Boot总是急切地在web application的上下文中注册filter beans, 因此当在Spring Boot环境中运行Keycloak Spring security适配器的适合,
    //我们可能需要来添加FilterRegistrationBean的配置来避免Filter被注册两次.

    /**
     * 在Spring Boot 2.1中默认情况下spring.main.allow-bean-definition-overriding是禁用的.
     * 这意味着: 如果Configuration类扩展了KeycloakWebSecurityConfigurerAdapter并且被@ComponentScan检测到.
     * 那么将抛出BeanDefinitionOverrideException.
     * 这适合我们可以通过在添加@ConditionalOnMissingBean注解来避免这种错误,
     * 如下的HttpSessionManager.
     * @param filter
     * @return
     */
    @Bean
    public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(KeycloakAuthenticationProcessingFilter filter)
    {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
        registrationBean.setEnabled(false);

        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(
            KeycloakPreAuthActionsFilter filter
    ) {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
        registrationBean.setEnabled(false);

        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean keycloakAuthenticatedActionsFilterBean(KeycloakAuthenticatedActionsFilter filter) {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
        registrationBean.setEnabled(false);

        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean keycloakSecurityContextRequestFilterBean(KeycloakSecurityContextRequestFilter filter) {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
        registrationBean.setEnabled(false);

        return registrationBean;
    }

    @Bean
    @ConditionalOnMissingBean(HttpSessionManager.class)
    @Override
    protected HttpSessionManager httpSessionManager() {
        return new HttpSessionManager();
    }
    //endregion
}
