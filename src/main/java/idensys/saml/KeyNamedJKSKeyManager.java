package idensys.saml;

import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.springframework.security.saml.key.JKSKeyManager;

import java.security.KeyStore;
import java.util.Map;

public class KeyNamedJKSKeyManager extends JKSKeyManager {

  private final String configuredKeyName;

  public KeyNamedJKSKeyManager(KeyStore keyStore, Map<String, String> passwords, String defaultKey, String configuredKeyName) {
    super(keyStore, passwords, defaultKey);
    this.configuredKeyName = configuredKeyName;
  }

  public Credential getCredential(String keyName) {
    Credential credential = super.getCredential(keyName);
    if (credential instanceof BasicX509Credential) {
      BasicX509Credential basicX509Credential =  (BasicX509Credential) credential;
      basicX509Credential.getKeyNames().add(configuredKeyName);
    }
    return credential;
  }
}
