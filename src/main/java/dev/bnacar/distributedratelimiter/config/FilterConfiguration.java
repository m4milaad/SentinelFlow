package dev.bnacar.distributedratelimiter.config;

import dev.bnacar.distributedratelimiter.security.SecurityFilter;
import dev.bnacar.distributedratelimiter.security.abuse.AbuseMitigationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfiguration {

    private final SecurityFilter securityFilter;

    @Autowired
    public FilterConfiguration(SecurityFilter securityFilter) {
        this.securityFilter = securityFilter;
    }

    @Bean
    public FilterRegistrationBean<SecurityFilter> securityFilterRegistration() {
        FilterRegistrationBean<SecurityFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(securityFilter);
        registration.addUrlPatterns("/api/*");
        registration.setOrder(1);
        return registration;
    }

    @Bean
    public FilterRegistrationBean<AbuseMitigationFilter> abuseMitigationFilterRegistration(
            @Autowired(required = false) AbuseMitigationFilter abuseMitigationFilter) {
        FilterRegistrationBean<AbuseMitigationFilter> registration = new FilterRegistrationBean<>();
        if (abuseMitigationFilter != null) {
            registration.setFilter(abuseMitigationFilter);
        } else {
            registration.setEnabled(false);
        }
        registration.addUrlPatterns("/api/*");
        registration.setOrder(0);
        return registration;
    }
}