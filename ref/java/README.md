# Bech32 Java

## Usage

This [Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) implementation is 
designed to be a standalone drop-in library for your Java and Android projects. <br/>

Based entirely on the Java Standard library, it allows either to validate a **Bech32 String** or a **Bech32 Segwit Address**. <br/>
In the latter case it's possible to decode, with the **SegwitAddress** class, an address in a way that throws an exception with 
the releated issue if it's an invalid one. Otherwise it's possible to get back a *null* object if the
address is invalid. 


```java
Bech32 bech32 = new Bech32();

// Returns a valid Bech32Decoded object
mBech32.decode("A12UEL5L");

// Throws a Bech32ValidationException
mBech32.decode("x1b4n0q5v"); 
```
```java
SegwitAddress segwitAddress = new SegwitAddress();

// Returns a valid SegwitAddress object
segwitAddress.decode("bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "bc");

// Returns a null object
segwitAddress.decode("bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", "bc");

// Throws a Bech32ValidationException
segwitAddress.decodeThrowing("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "bc");
```

## Running tests

The project is integrated with Gradle, but thanks to its design can be built using your favourite build system. </br>
It depends on JUnit's `org.junit.Assert` class in order to assert the test results. <br/> 
In order to run the tests launch via the command line these two gradle tasks. <br/> 
Note that a **gradlew** binary is already included when cloning this repository.

```
$ ./gradlew --refresh-dependencies
$ ./gradlew test

BUILD SUCCESSFUL in 0s
3 actionable tasks: 3 up-to-date
```

