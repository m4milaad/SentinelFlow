package io.sentinelflow.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("SentinelFlow API")
                        .description("SentinelFlow - High-performance sentinelflow and abuse mitigation engine with Redis support, " +
                                   "featuring configurable capacity and refill rates, thread-safe operations, " +
                                   "real-time observability, and administrative controls.")
                        .version("1.4.0")
                        .contact(new Contact()
                                .name("SentinelFlow")
                                .url("https://github.com/m4milaad/sentinel-flow"))
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT")))
                .servers(List.of(
                        new Server().url("http://localhost:8080").description("Development server"),
                        new Server().url("/").description("Current server")
                ));
    }
}