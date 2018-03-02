# wicket-pwnedpasswords-validator

A validator for Apache Wicket that checks if a given password has been pwned.
The validator uses the free API of https://haveibeenpwned.com/ by [@troyhunt](https://github.com/troyhunt) to 
validate that the password has not been previously exposed in data breaches.

## Usage

1. Include maven dependency in your pom.xml

```xml
ADD MVN DEPENDENCY SNIPPED HERE AS SOON AS IT IS AVAILABLE IN CENTRAL
```

2. Add PwnedPasswordsValidator to your PasswordTextField 

```java
// just your every day registration form...
Form form = new Form("form");
add(form);
f.add(new FeedbackPanel("feedback"));
PasswordTextField password = new PasswordTextField("password", new Model<>(""));
form.add(password);

// and here it is:
password.add(new PwnedPasswordsValidator());

```

## Prerequisites

* Maven (or download jar from [Releases](https://github.com/pingunaut/wicket-pwnedpasswords-validator/releases))
* Wicket 6, 7, 8

## Development 

```
git clone https://github.com/pingunaut/wicket-pwnedpasswords-validator.git
cd wicket-pwnedpasswords-validator
mvn test
```

## Built With

* [Maven](https://maven.apache.org/) - Dependency Management
* [Jenkins](https://jenkins.io/) - CI Server

## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **Martin Spielmann** - *Initial work* - [pingunaut](https://github.com/pingunaut)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project is licensed under the Apache License Version 2.0 - see the [LICENSE.md](LICENSE.md) file for details
