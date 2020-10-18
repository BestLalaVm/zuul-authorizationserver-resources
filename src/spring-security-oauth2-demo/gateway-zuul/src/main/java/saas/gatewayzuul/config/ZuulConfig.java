package saas.gatewayzuul.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateCustomizer;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.client.loadbalancer.LoadBalancerInterceptor;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
@EnableZuulProxy
@EnableDiscoveryClient
public class ZuulConfig {
    /**
     * 按照作者的说法:https://github.com/kakawait/uaa-behind-zuul-sample
     *  跟security.oauth2.client.userAuthorizationUri不同的是, security.oauth2.client.accessTokenUri不是采用浏览器级别进行跳转的.
     *  而是在网关中采用RestTemplate的方式进行访问的, 然而, RestTemplate在使用accessTokenUri的时候是没有使用如http://service-name/oauth/token的负载均衡的方式
     *  因此, 我们这边定义了UserInfoRestTemplateCustomizer的方式来简单实现负载均衡的功能.
     *
     *  有关具体这个问题参考: https://github.com/spring-projects/spring-security-oauth/issues/671
     * @param loadBalancerInterceptor
     * @return
     */
    @Bean
    UserInfoRestTemplateCustomizer userInfoRestTemplateCustomizer(LoadBalancerInterceptor loadBalancerInterceptor) {
        return template -> {
            List<ClientHttpRequestInterceptor> interceptors = new ArrayList<>();
            interceptors.add(loadBalancerInterceptor);

            AccessTokenProviderChain accessTokenProviderChain = Stream.of(new AuthorizationCodeAccessTokenProvider(),
                    new ImplicitAccessTokenProvider(), new ResourceOwnerPasswordAccessTokenProvider(),
                    new ClientCredentialsAccessTokenProvider())
                    .peek(tp -> tp.setInterceptors(interceptors))
                    .collect(Collectors.collectingAndThen(Collectors.toList(), AccessTokenProviderChain::new));

            template.setAccessTokenProvider(accessTokenProviderChain);
        };
    }
}
