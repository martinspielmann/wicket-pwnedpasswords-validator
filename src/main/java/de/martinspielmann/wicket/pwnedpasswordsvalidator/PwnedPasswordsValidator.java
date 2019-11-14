package de.martinspielmann.wicket.pwnedpasswordsvalidator;

import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidationError;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.martinspielmann.haveibeenpwned4j.HaveIBeenPwnedApiClient;
import de.martinspielmann.haveibeenpwned4j.HaveIBeenPwnedException;
import java.net.InetSocketAddress;
import java.net.Proxy;

/**
 * Checks if a given password has been disclosed in a data breach using API of
 * <a href="https://haveibeenpwned.com/">https://haveibeenpwned.com/</a> More
 * details at <a href=
 * "https://haveibeenpwned.com/API/v3#PwnedPasswords">https://haveibeenpwned.com/API/v2#PwnedPasswords</a>
 *
 * @author Martin Spielmann
 */
public class PwnedPasswordsValidator implements IValidator<String> {

  private static final long serialVersionUID = 1L;

  private static final Logger LOG = LoggerFactory.getLogger(PwnedPasswordsValidator.class);

  private final boolean failOnError;

  private final HaveIBeenPwnedApiClient client;

  /**
   * Creates a new PwnedPasswordsValidator with default configuration without an
   * API key. If an error occurs during validation, the validated password will be
   * treated as invalid.
   */
  public PwnedPasswordsValidator() {
    this(null, true, null);
  }

  /**
   * Creates a new PwnedPasswordsValidator with default configuration. If an error
   * occurs during validation, the validated password will be treated as invalid.
   * 
   * @param apiKey the hibp-api-key
   */
  public PwnedPasswordsValidator(String apiKey) {
    this(apiKey, true, null);
  }

  /**
   * Creates a new PwnedPasswordsValidator
   *
   * @param apiKey      the hibp-api-key
   * @param failOnError If {@code true}, if an error occurs during validation, the
   *                    validated password will be treated as invalid. Else errors
   *                    will be ignored and the password will be treated as valid.
   */
  public PwnedPasswordsValidator(String apiKey, boolean failOnError) {
    this(apiKey, failOnError, null);
  }

  /**
   * Creates a new PwnedPasswordsValidator.
   *
   * @param apiKey      the hibp-api-key
   * @param failOnError If {@code true}, if an error occurs during validation, the
   *                    validated password will be treated as invalid. Else errors
   *                    will be ignored and the password will be treated as valid.
   * @param proxy       the proxy server
   */
  public PwnedPasswordsValidator(String apiKey, boolean failOnError, Proxy proxy) {
    this.failOnError = failOnError;
    InetSocketAddress proxyAddress = proxy != null ? (InetSocketAddress) proxy.address() : null;
    client = new HaveIBeenPwnedApiClient(apiKey, proxyAddress, "pingunaut/wicket-pwnedpasswords-validator");
  }

  protected HaveIBeenPwnedApiClient getClient() {
    return client;
  }

  @Override
  public void validate(IValidatable<String> validatable) {
    String pw = validatable.getValue();
    try {
      boolean isPwned = getClient().isPasswordPwned(pw);
      if (isPwned) {
        validatable.error(decorate(new ValidationError(this, "pwned"), validatable));
      }
    } catch (HaveIBeenPwnedException e) {
      if (shouldFailOnError()) {
        validatable
            .error(decorate(new ValidationError(this, "error").setVariable("code", e.getMessage()), validatable));
      }
    }
  }

  /**
   * Allows subclasses to decorate reported errors
   *
   * @param error       the error
   * @param validatable the validatable
   * @return decorated error
   */
  protected IValidationError decorate(IValidationError error, IValidatable<String> validatable) {
    return error;
  }

  boolean shouldFailOnError() {
    return failOnError;
  }
}
