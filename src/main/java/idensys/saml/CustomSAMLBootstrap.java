package idensys.saml;

import org.opensaml.Configuration;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.saml.SAMLConstants;

public class CustomSAMLBootstrap extends org.springframework.security.saml.SAMLBootstrap {

  public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {

    super.postProcessBeanFactory(beanFactory);

    BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
    config.registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
    config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
  }

  /**
   * Method registers extension specific KeyInfoGenerator which emits .
   *
   * @see SAMLConstants#SAML_METADATA_KEY_INFO_GENERATOR
   */
  @Override
  protected void setMetadataKeyInfoGenerator() {
    NamedKeyInfoGeneratorManager manager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
    X509KeyInfoGeneratorFactory generator = new X509KeyInfoGeneratorFactory();
    generator.setEmitEntityCertificate(true);
    generator.setEmitEntityCertificateChain(true);
    generator.setEmitSubjectAltNamesAsKeyNames(true);
    generator.setEmitKeyNames(true);
    manager.registerFactory(SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR, generator);
  }

}
