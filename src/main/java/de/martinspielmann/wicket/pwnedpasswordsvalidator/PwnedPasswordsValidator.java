package de.martinspielmann.wicket.pwnedpasswordsvalidator;

import org.apache.commons.io.IOUtils;
import org.apache.wicket.util.string.Strings;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidationError;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URL;
import java.net.Proxy.Type;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Checks if a given password has been disclosed in a data breach using API of
 * <a href="https://haveibeenpwned.com/">https://haveibeenpwned.com/</a> More details at <a href=
 * "https://haveibeenpwned.com/API/v3#PwnedPasswords">https://haveibeenpwned.com/API/v2#PwnedPasswords</a>
 *
 * @author Martin Spielmann
 */
public class PwnedPasswordsValidator implements IValidator<String> {

  private static final long serialVersionUID = -2295946752223344261L;

  private static final Logger LOG = LoggerFactory.getLogger(PwnedPasswordsValidator.class);

  private static final String API_URL = "https://api.pwnedpasswords.com/range/%s";

  private final String apiKey;
  private final boolean failOnError;
  private final SerializableProxy proxy;

  /**
   * Creates a new PwnedPasswordsValidator with default configuration. If an error occurs during
   * validation, the validated password will be treated as invalid.
   * 
   * @param apiKey the hibp-api-key
   */
  public PwnedPasswordsValidator(String apiKey) {
    this(apiKey, true, null);
  }

  /**
   * Creates a new PwnedPasswordsValidator
   *
   * @param apiKey the hibp-api-key
   * @param failOnError If {@code true}, if an error occurs during validation, the validated password
   *        will be treated as invalid. Else errors will be ignored and the password will be treated
   *        as valid.
   */
  public PwnedPasswordsValidator(String apiKey, boolean failOnError) {
    this(apiKey, failOnError, null);
  }

  /**
   * Creates a new PwnedPasswordsValidator.
   *
   * @param apiKey the hibp-api-key
   * @param failOnError If {@code true}, if an error occurs during validation, the validated password
   *        will be treated as invalid. Else errors will be ignored and the password will be treated
   *        as valid.
   * @param proxy the proxy server
   */
  public PwnedPasswordsValidator(String apiKey, boolean failOnError, Proxy proxy) {
    if (apiKey == null) {
      throw new NullPointerException(
          "Before the first usage of PwnedPasswordsValidator, make sure you set the hibp-api-key using PwnedPasswordsValidator.configureApiKey()");
    }
    this.apiKey = apiKey;
    this.failOnError = failOnError;
    if (proxy != null) {
      this.proxy = new SerializableProxy(proxy);
    } else {
      this.proxy = null;
    }
  }

  @Override
  public void validate(IValidatable<String> validatable) {
    String pw = validatable.getValue();
    Status status = getResponseStatus(pw);
    switch (status) {
      case UNKNOWN_API_ERROR:
      case TOO_MANY_REQUESTS:
      case UNAUTHORIZED:
        if (shouldFailOnError()) {
          validatable
              .error(decorate(new ValidationError(this, "error").setVariable("code", status.getCode()), validatable));
        }
        break;
      case PASSWORD_PWNED:
        validatable.error(decorate(new ValidationError(this, "pwned"), validatable));
        break;
      case PASSWORD_OK:
        // great. password not pwned.
        break;
      default:
        break;
    }
  }

  protected Status getResponseStatus(String pw) {
    try {

      HttpURLConnection c;
      if (getProxy() != null) {
        c = (HttpURLConnection) getApiUrl(pw).openConnection(getProxy());
      } else {
        c = (HttpURLConnection) getApiUrl(pw).openConnection();
      }
      c.setRequestMethod("GET");
      c.setRequestProperty("User-Agent", "pingunaut/wicket-pwnedpasswords-validator");
      c.setRequestProperty("hibp-api-key", apiKey);
      c.connect();

      Status status = Status.of(c.getResponseCode());
      // if nothing is found or there was an API error, return
      if (!status.equals(Status.PASSWORD_PWNED)) {
        return status;
      }
      // if there were results, check if your pw hash was pwned
      String result = IOUtils.toString(c.getInputStream(), StandardCharsets.UTF_8);
      String[] lines = result.split("\\r?\\n");
      String hashSuffix = getHashSuffix(pw);
      for (String line : lines) {
        if (line.split(":")[0].equals(hashSuffix)) {
          return Status.PASSWORD_PWNED;
        }
      }
      return Status.PASSWORD_OK;
    } catch (IOException | NoSuchAlgorithmException e) {
      LOG.error("Error checking password for pwnage", e);
      return Status.UNKNOWN_API_ERROR;
    }
  }

  protected Proxy getProxy() {
    if (proxy == null) {
      return null;
    }
    return proxy.get();
  }

  String getHashPrefix(String pw) throws NoSuchAlgorithmException {
    return sha1(pw).substring(0, 5);
  }

  String getHashSuffix(String pw) throws NoSuchAlgorithmException {
    return sha1(pw).substring(5);
  }

  URL getApiUrl(String pw) throws MalformedURLException, NoSuchAlgorithmException {
    return new URL(String.format(API_URL, getHashPrefix(pw)));
  }

  /**
   * The API allows to check passwords directly. To avoid url encoding issues with complicated
   * passwords, we use the possibility to check sha1 hashes
   *
   * @param pw the password
   * @return sha1 hash of the given password
   * @throws NoSuchAlgorithmException if SHA-1 digest not available
   */
  protected String sha1(String pw) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-1");
    byte[] encodedhash = digest.digest(pw.getBytes(StandardCharsets.UTF_8));
    return Strings.toHexString(encodedhash);
  }

  /**
   * Allows subclasses to decorate reported errors
   *
   * @param error the error
   * @param validatable the validatable
   * @return decorated error
   */
  protected IValidationError decorate(IValidationError error, IValidatable<String> validatable) {
    return error;
  }

  boolean shouldFailOnError() {
    return failOnError;
  }


  private static class SerializableProxy implements Serializable {
    private static final long serialVersionUID = 6611963348855847317L;

    private Type type;
    private SocketAddress sa;

    public SerializableProxy(Proxy proxy) {
      this.type = proxy.type();
      this.sa = proxy.address();
    }

    public Proxy get() {
      if (type == Type.DIRECT) {
        return Proxy.NO_PROXY;
      }
      return new Proxy(type, sa);
    }

  }

}
