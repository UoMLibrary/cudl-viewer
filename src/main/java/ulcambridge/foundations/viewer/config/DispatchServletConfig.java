package ulcambridge.foundations.viewer.config;

import com.auth0.jwt.Algorithm;
import com.auth0.jwt.JWTSigner;
import com.google.common.base.Charsets;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.ComponentScan.Filter;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.MimeType;
import org.springframework.util.StreamUtils;
import org.springframework.web.multipart.commons.CommonsMultipartResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.resource.GzipResourceResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import ulcambridge.foundations.embeddedviewer.configuration.Config;
import ulcambridge.foundations.embeddedviewer.configuration.EmbeddedViewerConfiguringResourceTransformer;
import ulcambridge.foundations.viewer.authentication.distributed.AcceptableAudiences;
import ulcambridge.foundations.viewer.authentication.distributed.DefaultJwtCreator;
import ulcambridge.foundations.viewer.authentication.distributed.JwtCreator;
import ulcambridge.foundations.viewer.embedded.Configs;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.function.Predicate;

@Configuration
@EnableWebMvc
@ComponentScan(
    basePackages = {"ulcambridge.foundations.viewer"},
    useDefaultFilters = false,
    includeFilters = {@Filter(Controller.class)})
@Import(CrossContextConfig.class)
public class DispatchServletConfig
    extends WebMvcConfigurerAdapter
    implements BeanFactoryAware {

    public static final String EMBEDDED_VIEWER_PATTERN = "/embed/**";

    private BeanFactory beanFactory;

    @Override
    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = beanFactory;
    }

    @Override
    public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
        // Register the UTF-8 message converter
        converters.add(0, this.beanFactory.getBean(
            StringHttpMessageConverter.class));

        super.extendMessageConverters(converters);
    }

    /**
     * A message converter which encodes strings using UTF-8. By default Spring
     * uses latin-1 for some reason.
     */
    @Bean
    public StringHttpMessageConverter stringHttpMessageConverter() {
        StringHttpMessageConverter converter =
            new StringHttpMessageConverter(Charsets.UTF_8);

        // Don't write a massive Accept-Charset header with every charset
        // imaginable.
        converter.setWriteAcceptCharset(false);

        return converter;
    }

    @Bean(name = "viewResolver")
    public InternalResourceViewResolver jspViewResolver() {
        InternalResourceViewResolver resolver = new InternalResourceViewResolver();

        resolver.setContentType(new MimeType("text", "html",
                                Charsets.UTF_8).toString());
        resolver.setPrefix("/WEB-INF/");
        resolver.setSuffix(".jsp");
        resolver.setExposedContextBeanNames("globalproperties");

        return resolver;
    }

    @Bean(name = "multipartResolver")
    public static CommonsMultipartResolver commonsMultipartResolver() {
        CommonsMultipartResolver c = new CommonsMultipartResolver();
        c.setDefaultEncoding("utf-8");
        c.setMaxUploadSize(1024 * 1024 * 20);
        c.setMaxInMemorySize(1024 * 1024);
        return c;
    }

    @Bean
    public Config embeddedViewerConfig(
        @Value("${cudl.viewer.analytics.embedded.gaid:}") String gaTrackingId,
        @Value("${services://services.cudl.lib.cam.ac.uk}/v1/metadata/json/")
        String metadataUrlPrefix,
        @Value("${metadataUrlSuffix:}") String metadataUrlSuffix,
        @Value("${imageServer://image01.cudl.lib.cam.ac.uk/}")
        String dziUrlPrefix,
        @Value("${rootURL://cudl.lib.cam.ac.uk}") String metadataUrlHost) {

        return Configs.createEmbeddedViewerConfig(
            gaTrackingId, metadataUrlPrefix, metadataUrlSuffix, dziUrlPrefix,
            metadataUrlHost);
    }

    @Configuration
    public static class ResourcesConfig extends WebMvcConfigurerAdapter {

        @Autowired
        private Environment env;

        @Autowired
        private Config embeddedViewerConfig;

        private String resolve(String text) {
            return env.resolveRequiredPlaceholders(text);
        }

        @Override
        public void addResourceHandlers(ResourceHandlerRegistry registry) {
            registry.addResourceHandler("/models/**")
                .addResourceLocations("/models/");

            registry.addResourceHandler(
                    resolve("${cudl-viewer-content.images.url}/**"))
                .addResourceLocations(
                    resolve("file:${cudl-viewer-content.images.path}/"));

            registry.addResourceHandler(
                    resolve("${cudl-viewer-content.html.url}/**"))
                .addResourceLocations(
                    resolve("file:${cudl-viewer-content.html.path}/"));

            registry.addResourceHandler("/img/**")
                .addResourceLocations("/img/");

            registry.addResourceHandler("/favicon.ico")
                .addResourceLocations("/favicon.ico");

            addViewerUiAssets(registry);
            addEmbeddedViewerAssets(registry);
        }

        private void addViewerUiAssets(ResourceHandlerRegistry registry) {
            registry.addResourceHandler("/ui/**")
                .addResourceLocations(
                    "classpath:ulcambridge/foundations/viewer/viewer-ui/assets/")
                .setCachePeriod(60 * 60 * 24 * 365)  // 1 year
                .resourceChain(true)
                    .addResolver(new GzipResourceResolver());
        }

        private void addEmbeddedViewerAssets(ResourceHandlerRegistry registry) {
            // Cache headers are not set here but in urlrewrite.xml. This is
            // because the viewer.html needs different cache-control values to
            // the rest of the assets.
            registry.addResourceHandler(EMBEDDED_VIEWER_PATTERN)
                .addResourceLocations(
                    "classpath:ulcambridge/foundations/embeddedviewer/assets/")
                .resourceChain(true)
                    .addResolver(new GzipResourceResolver())
                    .addTransformer(
                        new EmbeddedViewerConfiguringResourceTransformer(
                            embeddedViewerConfig));
        }
    }

    @Configuration
    public static class DistributedAuthConfig implements BeanFactoryAware {

        private BeanFactory beanFactory;

        @Override
        public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
            this.beanFactory = beanFactory;
        }

        @Bean
        public Algorithm distributedAuthJwtSigningAlgorithm(
            @Value("${cudl.distributed-auth.jwt.signing.algorithm}")
                Algorithm algorithm) {

            Assert.notNull(algorithm);

            return algorithm;
        }

        @Bean
        @Lazy
        public byte[] distributedAuthJwtSigningSecret(
            @Value("${cudl.distributed-auth.jwt.signing.secret.value}")
                String secret,
            @Value("${cudl.distributed-auth.jwt.signing.secret.encoding:UTF-8}")
                String encoding) throws UnsupportedEncodingException {

            if("base64".equals(encoding)) {
                return Base64.getDecoder().decode(secret);
            }

            return secret.getBytes(encoding);
        }

        @Bean
        @Lazy
        public PrivateKey distributedAuthJwtSigningKey(
            @Value("${cudl.distributed-auth.jwt.signing.key.path}")
                String privateKeyResourcePath,
            @Value("${cudl.distributed-auth.jwt.signing.key.algorithm:RSA}")
                String keyType,
            ResourceLoader resourceLoader) {

            byte[] keyData;
            try {
                InputStream keyStream = resourceLoader
                    .getResource(privateKeyResourcePath).getInputStream();
                keyData = StreamUtils.copyToByteArray(keyStream);
            }
            catch (IOException e) {
                throw new RuntimeException(
                    "Failed to load private key data from: "
                        + privateKeyResourcePath, e);
            }

            try {
                return KeyFactory.getInstance(keyType)
                    .generatePrivate(new PKCS8EncodedKeySpec(keyData));
            }
            catch (InvalidKeySpecException e) {
                throw new RuntimeException("Failed to generate private key", e);
            }
            catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Failed to generate private key", e);
            }
        }

        public enum AcceptableAudiencesPolicy {
            /**
             * The viewer will sign JWTs for any audience URL. Used for easy
             * local testing.
             */
            ANY,
            /**
             * The viewer will only sign JWTs for audience URLs under a
             * specified domain.
             */
            SUBDOMAIN
        }

        @Bean
        public Predicate<URI> isAcceptableAudienceURL(
            @Value("${cudl.distributed-auth.jwt.acceptable-audiences.policy:SUBDOMAIN}")
                AcceptableAudiencesPolicy policy) {

            return this.beanFactory.getBean("isAcceptableAudienceURL." + policy,
                                            Predicate.class);
        }

        @Bean(name = "isAcceptableAudienceURL.ANY")
        public Predicate<URI> anyUrlPredicate() {
            return url -> true;
        }

        @Bean(name = "isAcceptableAudienceURL.SUBDOMAIN")
        public Predicate<URI> subdomainUrlPredicate(
            @Value("${cudl.distributed-auth.jwt.acceptable-audiences.subdomain}")
                String subdomain) {

            return AcceptableAudiences.urlSubdomainMatcher(subdomain);
        }

        /**
         * Used to create JSON web tokens at the /auth/token endpoint
         */
        @Bean
        public JwtCreator jwtCreator(
            @Qualifier("distributedAuthJwtSigningAlgorithm") Algorithm algo,
            Predicate<URI> isAcceptableAudienceURL) {

            JWTSigner signer;

            switch(algo) {
                // HMAC SHA signatures using shared secret
                case HS256:
                case HS384:
                case HS512:
                    byte[] secret = (byte[])beanFactory.getBean(
                        "distributedAuthJwtSigningSecret");
                    signer = new JWTSigner(secret);
                    break;
                // RSA signatures created using private key, verified with
                // public key.
                case RS256:
                case RS384:
                case RS512:
                    PrivateKey key = beanFactory.getBean(
                        "distributedAuthJwtSigningKey", PrivateKey.class);
                    signer = new JWTSigner(key);
                    break;
                default:
                    throw new RuntimeException(
                        "Unknown JWT signing algorithm: " + algo);
            }

            return new DefaultJwtCreator(
                isAcceptableAudienceURL, signer, algo, Clock.systemUTC(),
                DefaultJwtCreator.DEFAULT_VALIDITY_PERIOD, Duration.ofDays(2));
        }
    }

    @Configuration
    public static class TaggingApiConfig {

        @Bean
        public URI taggingApiBaseUrl(
            @Value("${taggingApiBaseUrl}") URI taggingApiBaseUrl) {
            return taggingApiBaseUrl;
        }
    }
}
