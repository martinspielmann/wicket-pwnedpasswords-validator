package de.martinspielmann.wicket.pwnedpasswordsvalidator;

import org.apache.wicket.util.tester.FormTester;
import org.apache.wicket.util.tester.WicketTester;
import org.apache.wicket.validation.Validatable;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class PwnedPasswordsValidatorTest {


  private String apiKey = "foo123";

  @Test
  public void constructorsShouldSetDefaultValues() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey);
    Assert.assertEquals(true, v.shouldFailOnError());
    Assert.assertNull(v.getProxy());
  }

  @Test
  public void constructorsShouldSetParameterValues() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey, false);
    Assert.assertEquals(false, v.shouldFailOnError());
    Assert.assertNull(v.getProxy());
  }

  @Test
  public void constructorsShouldSetAllParameterValuesValues() {
    Proxy proxy = Proxy.NO_PROXY;
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey, false, proxy);
    Assert.assertEquals(false, v.shouldFailOnError());
    Assert.assertEquals(Proxy.NO_PROXY, v.getProxy());
  }

  @Test
  public void testSha1() throws NoSuchAlgorithmException {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey);
    String sha1 = v.sha1("foo");
    Assert.assertEquals("0BEEC7B5EA3F0FDBC95D0DD47F3C5BC275DA8A33", sha1);
  }

  @Test
  public void validateUnknownError() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey) {
      @Override
      protected Status getResponseStatus(String pw) {
        return Status.UNKNOWN_API_ERROR;
      }
    };
    Validatable<String> validatable = new Validatable<>();
    v.validate(validatable);
    Assert.assertEquals(1, validatable.getErrors().size());
  }

  @Test
  public void validateUnknownErrorIgnore() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey, false) {
      @Override
      protected Status getResponseStatus(String pw) {
        return Status.UNKNOWN_API_ERROR;
      }
    };
    Validatable<String> validatable = new Validatable<>();
    v.validate(validatable);
    Assert.assertEquals(0, validatable.getErrors().size());
  }

  @Test
  public void validatePwned() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey) {
      @Override
      protected Status getResponseStatus(String pw) {
        return Status.PASSWORD_PWNED;
      }
    };
    Validatable<String> validatable = new Validatable<>();
    v.validate(validatable);
    Assert.assertEquals(1, validatable.getErrors().size());
  }

  @Test
  public void validatePwOK() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey) {
      @Override
      protected Status getResponseStatus(String pw) {
        return Status.PASSWORD_OK;
      }
    };
    Validatable<String> validatable = new Validatable<>();
    v.validate(validatable);
    Assert.assertEquals(0, validatable.getErrors().size());
  }

  @Test
  public void validatePwTooManyRequestsIgnore() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey, true) {
      @Override
      protected Status getResponseStatus(String pw) {
        return Status.TOO_MANY_REQUESTS;
      }
    };
    Validatable<String> validatable = new Validatable<>();
    v.validate(validatable);
    Assert.assertEquals(0, validatable.getErrors().size());
  }

  @Test
  public void validatePwTooManyRequestsFail() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey, true) {
      @Override
      protected Status getResponseStatus(String pw) {
        return Status.TOO_MANY_REQUESTS;
      }
    };
    Validatable<String> validatable = new Validatable<>();
    v.validate(validatable);
    Assert.assertEquals(1, validatable.getErrors().size());
  }


  @Test
  public void getResponseStatusPwned() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey);
    Status s = v.getResponseStatus("secret123");
    Assert.assertEquals(Status.PASSWORD_PWNED, s);
  }

  @Test
  public void getResponseStatusForRandomPassword() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey);
    Status s = v.getResponseStatus(UUID.randomUUID().toString() + UUID.randomUUID().toString());
    Assert.assertEquals(Status.PASSWORD_OK, s);
  }

  @Test
  public void getProxy() {
    SocketAddress sa = new InetSocketAddress(80);
    Proxy p = new Proxy(Proxy.Type.HTTP, sa);
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey, false, p);
    Assert.assertEquals(p, v.getProxy());
  }

  @Test
  public void shouldFailOnError() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey, false);
    Assert.assertFalse(v.shouldFailOnError());
  }

  @Test
  public void getApiUrl() throws MalformedURLException, NoSuchAlgorithmException {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey);
    URL u = new URL("https://api.pwnedpasswords.com/range/F2B14");
    Assert.assertEquals(u, v.getApiUrl("secret123"));
  }

  @Test
  public void homepageRendersSuccessfully() {
    WicketTester tester = new WicketTester(new WicketApplication());
    tester.startPage(HomePage.class);
    tester.assertRenderedPage(HomePage.class);
  }

  @Test
  public void feedbackPwnedPassword() {
    WicketTester tester = new WicketTester(new WicketApplication());
    tester.startPage(HomePage.class);
    FormTester ft = tester.newFormTester("form");
    ft.setValue("pw", "secret123");
    ft.submit();
    String feedback = ft.getForm().getLocalizer().getString("PwnedPasswordsValidator.pwned",
        ft.getForm().get("pw"));
    tester.assertErrorMessages(feedback);
  }
}
