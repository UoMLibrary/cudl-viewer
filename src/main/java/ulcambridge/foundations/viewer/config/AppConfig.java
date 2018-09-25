package ulcambridge.foundations.viewer.config;

import com.google.gson.Gson;
import org.apache.commons.dbcp2.BasicDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.util.StreamUtils;
import org.springframework.web.client.RestTemplate;
import ulcambridge.foundations.viewer.CollectionFactory;
import ulcambridge.foundations.viewer.ItemFactory;
import ulcambridge.foundations.viewer.JSONReader;
import ulcambridge.foundations.viewer.authentication.UsersDBDao;
import ulcambridge.foundations.viewer.crowdsourcing.model.GsonFactory;

import javax.sql.DataSource;

import static java.nio.charset.StandardCharsets.UTF_8;

@Configuration
@PropertySource("classpath:cudl-global.properties")
@EnableScheduling
@EnableTransactionManagement
public class AppConfig {

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
            ds.setValidationQuery("SELECT 1");
            ds.setTestOnBorrow(true);

            return ds;
        }

        @Bean
        @Autowired
        public PlatformTransactionManager transactionManager(
            DataSource dataSource) {

            return new DataSourceTransactionManager(dataSource);
        }
    }

    @Bean
    public Gson gson() {
        return GsonFactory.create();
    }

    @Bean
    @Primary
    public RestTemplate restTemplate() {
        Logger log = LoggerFactory.getLogger(RestTemplate.class);
        RestTemplate restTemplate = new RestTemplate();

        if (log.isTraceEnabled()) {
            restTemplate.setRequestFactory(new BufferingClientHttpRequestFactory(restTemplate.getRequestFactory()));
            restTemplate.getInterceptors().add((request, body, execution) -> {
                log.trace("{} {}: {}", request.getMethod(), request.getURI(), new String(body, UTF_8));
                ClientHttpResponse response = execution.execute(request, body);
                log.trace("Response: {}", StreamUtils.copyToString(response.getBody(), UTF_8));
                return response;
            });
        }

        return restTemplate;
    }
}
