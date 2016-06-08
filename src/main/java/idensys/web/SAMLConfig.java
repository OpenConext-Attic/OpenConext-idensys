package idensys.web;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.binding.artifact.BasicSAMLArtifactMap;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.saml2.binding.decoding.HTTPArtifactDecoderImpl;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.encoding.HTTPArtifactEncoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.websso.*;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Typically this should all be done by default convention in the Spring SAML library,
 * but as Spring SAML is not build with conventions over configuration we do all the
 * plumbing ourselves.
 */
@Configuration
public class SAMLConfig {

  @Bean
  public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
    return new MultiThreadedHttpConnectionManager();
  }

  @Bean
  public HttpClient httpClient() {
    return new HttpClient(multiThreadedHttpConnectionManager());
  }

  @Bean
  @Autowired
  public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
    BasicSAMLArtifactMap map = new BasicSAMLArtifactMap(new MapBasedStorageService<>(), 1000 * 60 * 5);
    HTTPArtifactDecoderImpl decoder = new HTTPArtifactDecoderImpl(artifactResolutionProfile(parserPool), parserPool);
    HTTPArtifactEncoder encoder = new HTTPArtifactEncoder(velocityEngine, "/templates/saml2-post-artifact-binding.vm", map);
    //return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile(parserPool));
    return new HTTPArtifactBinding(decoder, encoder);
  }

  @Bean
  @Autowired
  public HTTPSOAP11Binding soapBinding(ParserPool parserPool) {
    return new HTTPSOAP11Binding(parserPool);
  }

  @Bean
  @Autowired
  public HTTPPostBinding httpPostBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
    HTTPPostEncoder encoder = new HTTPPostEncoder(velocityEngine, "/templates/saml2-post-binding.vm");
    return new HTTPPostBinding(parserPool, new HTTPPostDecoder(parserPool), encoder);
  }

  @Bean
  @Autowired
  public HTTPRedirectDeflateBinding httpRedirectDeflateBinding(ParserPool parserPool) {
    return new HTTPRedirectDeflateBinding(parserPool);
  }

  @Bean
  @Autowired
  public HTTPSOAP11Binding httpSOAP11Binding(ParserPool parserPool) {
    return new HTTPSOAP11Binding(parserPool);
  }

  @Bean
  @Autowired
  public HTTPPAOS11Binding httpPAOS11Binding(ParserPool parserPool) {
    return new HTTPPAOS11Binding(parserPool);
  }

  @Autowired
  @Bean
  public SAMLProcessorImpl processor(VelocityEngine velocityEngine, ParserPool parserPool) {
    Collection<SAMLBinding> bindings = new ArrayList<>();
    bindings.add(httpRedirectDeflateBinding(parserPool));
    bindings.add(httpPostBinding(parserPool, velocityEngine));
    bindings.add(artifactBinding(parserPool, velocityEngine));
    bindings.add(httpSOAP11Binding(parserPool));
    bindings.add(httpPAOS11Binding(parserPool));
    return new SAMLProcessorImpl(bindings);
  }

  @Bean
  public static SAMLBootstrap sAMLBootstrap() {
    return new SAMLBootstrap();
  }

  @Bean
  public SAMLDefaultLogger samlLogger() {
    return new SAMLDefaultLogger();
  }

  @Bean
  public WebSSOProfileConsumer webSSOprofileConsumer() {
    return new WebSSOProfileConsumerImpl();
  }

  @Bean
  public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
    return new WebSSOProfileConsumerHoKImpl();
  }

  @Bean
  public WebSSOProfile webSSOprofile() {
    return new WebSSOProfileImpl();
  }

  @Bean
  public WebSSOProfileECPImpl ecpprofile() {
    return new WebSSOProfileECPImpl();
  }

  private ArtifactResolutionProfile artifactResolutionProfile(ParserPool parserPool) {
    final ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient());
    artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding(parserPool)));
    return artifactResolutionProfile;
  }


}
