package ulcambridge.foundations.viewer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

/**
 * Configuration which needs to be duplicated in AppConfig and
 * DispatchServletConfig.
 *
 * Definitions for BeanFactoryPostProocessors which don't get inherited by child
 * contexts, so must be redefined explicitly.
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class CrossContextConfig {

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }
}
