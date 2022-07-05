# Bech32

Bech32 implementation in Java.

## Build Process

Install Maven 3.2 or higher.

### Build:

mvn clean

mvn package

Two .jar files will be created in the directory ./target :

Bech32.jar : Can be included in any Java project 'as is' but requires inclusion of dependencies. Main.java harness not included.

Bech32-jar-with-dependencies.jar : includes all dependencies and can be run from the command line using the Main.java harness.

### Run using Main.java harness:

java -jar -ea target/Bech32-jar-with-dependencies.jar

### Dev contact:

[PGP](http://pgp.mit.edu/pks/lookup?op=get&search=0x72B5BACDFEDF39D7)
