package de.martinspielmann.wicket.pwnedpasswordsvalidator;

import org.apache.wicket.util.tester.FormTester;
import org.apache.wicket.util.tester.WicketTester;
import org.apache.wicket.validation.Validatable;
import org.junit.Assert;
import org.junit.Test;

import de.martinspielmann.haveibeenpwned4j.HaveIBeenPwnedApiClient;
import de.martinspielmann.haveibeenpwned4j.HaveIBeenPwnedException;
import de.martinspielmann.haveibeenpwned4j.Status;

public class PwnedPasswordsValidatorTest {

  private String apiKey = "foo123";

  @Test
  public void constructorsShouldSetDefaultValues() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey);
    Assert.assertEquals(true, v.shouldFailOnError());
  }

  @Test
  public void constructorsShouldSetParameterValues() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey, false);
    Assert.assertEquals(false, v.shouldFailOnError());
  }

  @Test
  public void validateUnknownError() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey) {
      private static final long serialVersionUID = 1L;

      @Override
      protected HaveIBeenPwnedApiClient getClient() {
        return new HaveIBeenPwnedApiClient() {
          @Override
          public boolean isPasswordPwned(String password) {
            throw new HaveIBeenPwnedException("Foo!", Status.of(503));
          }
        };
      }
    };
    Validatable<String> validatable = new Validatable<>();
    v.validate(validatable);
    Assert.assertEquals(1, validatable.getErrors().size());
  }

  @Test
  public void validateUnknownErrorIgnore() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey, false) {
      private static final long serialVersionUID = 1L;

      @Override
      protected HaveIBeenPwnedApiClient getClient() {
        return new HaveIBeenPwnedApiClient() {
          @Override
          public boolean isPasswordPwned(String password) {
            throw new HaveIBeenPwnedException("Foo!", Status.of(503));
          }
        };
      }
    };
    Validatable<String> validatable = new Validatable<>();
    v.validate(validatable);
    Assert.assertEquals(0, validatable.getErrors().size());
  }

  @Test
  public void validatePwned() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey) {
      private static final long serialVersionUID = 1L;

      @Override
      protected HaveIBeenPwnedApiClient getClient() {
        return new HaveIBeenPwnedApiClient() {
          @Override
          public boolean isPasswordPwned(String password) {
            return true;
          }
        };
      }
    };
    Validatable<String> validatable = new Validatable<>();
    v.validate(validatable);
    Assert.assertEquals(1, validatable.getErrors().size());
  }

  @Test
  public void validatePwOK() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey) {
      private static final long serialVersionUID = 1L;

      @Override
      protected HaveIBeenPwnedApiClient getClient() {
        return new HaveIBeenPwnedApiClient() {
          @Override
          public boolean isPasswordPwned(String password) {
            return false;
          }
        };
      }
    };
    Validatable<String> validatable = new Validatable<>();
    v.validate(validatable);
    Assert.assertEquals(0, validatable.getErrors().size());
  }

  @Test
  public void shouldFailOnError() {
    PwnedPasswordsValidator v = new PwnedPasswordsValidator(apiKey, false);
    Assert.assertFalse(v.shouldFailOnError());
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
    String feedback = ft.getForm().getLocalizer().getString("PwnedPasswordsValidator.pwned", ft.getForm().get("pw"));
    tester.assertErrorMessages(feedback);
  }
}
