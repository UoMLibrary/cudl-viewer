package ulcambridge.foundations.viewer.config;

import org.apache.commons.dbcp.BasicDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.scheduling.annotation.EnableScheduling;
import ulcambridge.foundations.viewer.CollectionFactory;
import ulcambridge.foundations.viewer.ItemFactory;
import ulcambridge.foundations.viewer.JSONReader;
import ulcambridge.foundations.viewer.authentication.UsersDBDao;

import javax.sql.DataSource;

@Configuration
@PropertySource("classpath:cudl-global.properties")
@ComponentScan({
    "ulcambridge.foundations.viewer.frontend",
    "ulcambridge.foundations.viewer.admin"
})
@Import(SecurityConfig.class)
@EnableScheduling
public class AppConfig {

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    @Configuration
    @ComponentScan("ulcambridge.foundations.viewer.dao")
    @Import({CollectionFactory.class, ItemFactory.class, JSONReader.class,
             UsersDBDao.class})
    public static class DatabaseConfig {
        @Bean
        public DataSource dataSource(
            @Value("${jdbc.driver}") String driverClassName,
            @Value("${jdbc.url}") String url,
            @Value("${jdbc.user}") String username,
            @Value("${jdbc.password}") String password) {

            BasicDataSource ds = new BasicDataSource();
            ds.setDriverClassName(driverClassName);
            ds.setUrl(url);
            ds.setUsername(username);
            ds.setPassword(password);
            ds.setMaxActive(8);
            ds.setMaxIdle(8);
            ds.setValidationQuery("SELECT 1");
            ds.setTestOnBorrow(true);

            return ds;
        }
    }
}
