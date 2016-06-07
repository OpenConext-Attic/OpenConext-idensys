package idensys.web;

import idensys.saml.*;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.binding.security.IssueInstantRule;
import org.opensaml.common.binding.security.MessageReplayRule;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.util.storage.ReplayCache;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.Filter;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import static java.util.Collections.singletonList;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private Environment environment;

  @Value("${idp.metadata_url}")
  private String identityProviderMetadataUrl;

  @Value("${proxy.base_url}")
  private String idensysBaseUrl;

  @Value("${proxy.entity_id}")
  private String idensysEntityId;

  @Value("${proxy.private_key}")
  private String idensysPrivateKey;

  @Value("${proxy.certificate}")
  private String idensysCertificate;

  @Value("${proxy.passphrase}")
  private String idensysPassphrase;

  @Value("${proxy.acs_location}")
  private String idensysACSLocation;

  @Value("${serviceproviders.feed}")
  private String serviceProvidersFeedUrl;

  @Value("${serviceproviders.allow_unknown}")
  private boolean serviceProvidersAllowUnknown;

  private DefaultResourceLoader defaultResourceLoader = new DefaultResourceLoader();

  private Map<String, ServiceProvider> serviceProviders;

  @Bean
  public SAMLAuthenticationProvider samlAuthenticationProvider() {
    SAMLAuthenticationProvider samlAuthenticationProvider = new ProxySAMLAuthenticationProvider();
    samlAuthenticationProvider.setUserDetails(new DefaultSAMLUserDetailsService());
    samlAuthenticationProvider.setForcePrincipalAsString(false);
    samlAuthenticationProvider.setExcludeCredential(true);
    return samlAuthenticationProvider;
  }

  @Bean
  public SAMLEntryPoint samlEntryPoint() {
    WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
    webSSOProfileOptions.setIncludeScoping(false);

    SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
    samlEntryPoint.setDefaultProfileOptions(webSSOProfileOptions);
    return samlEntryPoint;
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.ignoring().antMatchers("/health", "/info");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .httpBasic().authenticationEntryPoint(identityProviderAuthnFilter())
      .and()
      .csrf().disable()
      .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
      .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class)
      .authorizeRequests()
      .antMatchers("/saml/idp/**", "/sp/metadata", "/saml/SSO/**", "/idp/metadata").permitAll()
      .anyRequest().hasRole("USER");
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(samlAuthenticationProvider());
  }

  @Bean
  public MetadataDisplayFilter metadataDisplayFilter() {
    DefaultMetadataDisplayFilter displayFilter = new DefaultMetadataDisplayFilter();
    displayFilter.setFilterProcessesUrl("sp/metadata");
    return displayFilter;
  }

  @Bean
  public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
    SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
    failureHandler.setUseForward(true);
    failureHandler.setDefaultFailureUrl("/error");
    return failureHandler;
  }

  @Bean
  @Autowired
  public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
    SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
    samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
    samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(new ProxyAuthenticationSuccessHandler(samlMessageHandler()));
    samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
    return samlWebSSOProcessingFilter;
  }

  @Bean
  @Autowired
  public MetadataGeneratorFilter metadataGeneratorFilter() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, XMLStreamException {
    return new MetadataGeneratorFilter(metadataGenerator());
  }

  @Bean
  public FilterChainProxy samlFilter() throws Exception {
    List<SecurityFilterChain> chains = new ArrayList<>();
    chains.add(chain("/saml/idp/**", identityProviderAuthnFilter()));
    chains.add(chain("/saml/login/**", samlEntryPoint()));
    chains.add(chain("/sp/metadata/**", metadataDisplayFilter()));
    chains.add(chain("/saml/SSO/**", samlWebSSOProcessingFilter()));
    return new FilterChainProxy(chains);
  }

  @Bean
  public IdentityProviderAuthnFilter identityProviderAuthnFilter() throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, KeyStoreException, IOException, XMLStreamException {
    return new IdentityProviderAuthnFilter(samlMessageHandler(), serviceProviders, serviceProvidersAllowUnknown);
  }

  private DefaultSecurityFilterChain chain(String pattern, Filter entryPoint) {
    return new DefaultSecurityFilterChain(new AntPathRequestMatcher(pattern), entryPoint);
  }

  @Bean
  public ExtendedMetadata extendedMetadata() {
    ExtendedMetadata extendedMetadata = new ExtendedMetadata();
    extendedMetadata.setIdpDiscoveryEnabled(false);
    extendedMetadata.setSignMetadata(false);
    return extendedMetadata;
  }

  @Bean
  public MetadataProvider identityProvider() throws MetadataProviderException {
    Resource resource = defaultResourceLoader.getResource(identityProviderMetadataUrl);
    ResourceMetadataProvider resourceMetadataProvider = new ResourceMetadataProvider(resource);
    resourceMetadataProvider.setParserPool(parserPool());
    ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(resourceMetadataProvider, extendedMetadata());
    extendedMetadataDelegate.setMetadataTrustCheck(true);
    extendedMetadataDelegate.setMetadataRequireSignature(true);
    return extendedMetadataDelegate;
  }

  @Bean
  @Qualifier("metadata")
  public CachingMetadataManager metadata() throws MetadataProviderException {
    List<MetadataProvider> providers = new ArrayList<>();
    providers.add(identityProvider());

    return new CachingMetadataManager(providers);
  }

  @Bean
  public VelocityEngine velocityEngine() {
    return VelocityFactory.getEngine();
  }

  @Bean(initMethod = "initialize")
  public ParserPool parserPool() {
    return new StaticBasicParserPool();
  }

  @Bean(name = "parserPoolHolder")
  public ParserPoolHolder parserPoolHolder() {
    return new ParserPoolHolder();
  }

  @Bean
  public SAMLContextProviderImpl contextProvider() throws URISyntaxException {
    return new ProxiedSAMLContextProviderLB(new URI(idensysBaseUrl));
  }

  @Bean
  public MetadataGenerator metadataGenerator() throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, KeyStoreException, IOException, XMLStreamException {
    MetadataGenerator metadataGenerator = new MetadataGenerator();
    metadataGenerator.setEntityId(idensysEntityId);
    metadataGenerator.setEntityBaseURL(idensysBaseUrl);
    metadataGenerator.setExtendedMetadata(extendedMetadata());
    metadataGenerator.setIncludeDiscoveryExtension(false);
    metadataGenerator.setKeyManager(keyManager());
    if (environment.acceptsProfiles("dev")) {
      metadataGenerator.setWantAssertionSigned(false);
    }
    return metadataGenerator;
  }

  @Bean
  public KeyManager keyManager() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, XMLStreamException {
    KeyStoreLocator keyStoreLocator = new KeyStoreLocator();
    KeyStore keyStore = keyStoreLocator.createKeyStore(idensysPassphrase);

    keyStoreLocator.addPrivateKey(keyStore, idensysEntityId, idensysPrivateKey, idensysCertificate, idensysPassphrase);

    this.serviceProviders = getServiceProviders();
    serviceProviders.entrySet().forEach(sp -> {
      try {
        ServiceProvider serviceProvider = sp.getValue();
        if (serviceProvider.isSigningCertificateSigned() && !serviceProvider.getEntityId().equals(idensysEntityId)) {
          keyStoreLocator.addCertificate(keyStore, sp.getKey(), serviceProvider.getSigningCertificate());
        }
      } catch (CertificateException | KeyStoreException e) {
        throw new RuntimeException(e);
      }
    });
    return new JKSKeyManager(keyStore, Collections.singletonMap(idensysEntityId, idensysPassphrase), idensysEntityId);
  }

  private Map<String, ServiceProvider> getServiceProviders() throws IOException, XMLStreamException {
    //expensive and we don't want the serviceProviders as @Bean
    if (this.serviceProviders == null) {
      this.serviceProviders = new ServiceProviderFeedParser(defaultResourceLoader.getResource(serviceProvidersFeedUrl)).parse();
    }
    if (environment.acceptsProfiles("dev")) {
      this.serviceProviders.put(idensysEntityId, new ServiceProvider(idensysEntityId, idensysCertificate, singletonList(idensysACSLocation)));
    }
    return this.serviceProviders;
  }

  @Bean
  public SAMLMessageHandler samlMessageHandler() throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, KeyStoreException, IOException, XMLStreamException {
    return new SAMLMessageHandler(
      keyManager(),
      new HTTPRedirectDeflateDecoder(parserPool()),
      new HTTPPostSimpleSignEncoder(velocityEngine(), "/templates/saml2-post-simplesign-binding.vm", true),
      securityPolicyResolver(),
      idensysEntityId);
  }

  private SecurityPolicyResolver securityPolicyResolver() {
    IssueInstantRule instantRule = new IssueInstantRule(90, 300);
    MessageReplayRule replayRule = new MessageReplayRule(new ReplayCache(new MapBasedStorageService(), 14400000));

    BasicSecurityPolicy securityPolicy = new BasicSecurityPolicy();
    securityPolicy.getPolicyRules().addAll(Arrays.asList(instantRule, replayRule));

    return new StaticSecurityPolicyResolver(securityPolicy);
  }


}
