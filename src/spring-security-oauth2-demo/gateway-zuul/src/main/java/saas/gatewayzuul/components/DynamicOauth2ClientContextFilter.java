package saas.gatewayzuul.components;

import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

public class DynamicOauth2ClientContextFilter extends OAuth2ClientContextFilter {
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * 逻辑跟默认的super.redirectUser一样.
     * 这样配置的目的是为了让security.oauth2.client.userAuthorizationUri中的配置跳转到Zuul本身.
     * @param e
     * @param request
     * @param response
     * @throws IOException
     */
    @Override
    protected void redirectUser(UserRedirectRequiredException e, HttpServletRequest request, HttpServletResponse response) throws IOException {
        //super.redirectUser(e, request, response);
        String redirectUri = e.getRedirectUri();
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri);
        Map<String, String> requestParam = e.getRequestParams();
        for (Map.Entry<String, String> param : requestParam.entrySet()) {
            builder.queryParam(param.getKey(), param.getValue());
        }

        if (e.getStateKey() != null) {
            builder.queryParam("state", e.getStateKey());
        }

        String url = getBaseUrl(request) + builder.build().encode().toUriString();

        this.redirectStrategy.sendRedirect(request, response, url);
    }

    @Override
    public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
        this.redirectStrategy = redirectStrategy;
    }

    private String getBaseUrl(HttpServletRequest request) {
        StringBuffer url = request.getRequestURL();

        /**
         * Url: http://xxxxx/contextpath/{uri}
         */
        return url.substring(0, url.length() - request.getRequestURI().length() + request.getContextPath().length());
    }
}
