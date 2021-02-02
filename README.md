---

# Java implementation of [Diffie-Hellman key exchange][1]

This project implements a Diffie-Hellman key exchange cryptographic algorithm, which is used to derive a common secret key from publicly exchanged values.

---

# Table of contents
* [Java implementation of Diffie-Hellman key exchange](#java-implementation-of-diffie-hellman-key-exchange)
* [Table of contents](#table-of-contents)
* [Description](#description)
* [Code examples](#code-examples)
   * [1. Session creation](#1-session-creation)
   * [2. Session output](#2-session-output)
   * [3. Common key calculation](#3-common-key-calculation)
* [Meta](#meta)
* [Credits](#credits)

---

# Description

This project is a single-file simple composition of classes that allows three things: create a session object, output information from a session, and calculate a secret key.

There are two types of session creation (both having two subtypes):
* with public key **g**:
   * with value generation (fields **p** and **g** will be generated according to provided parameters if it's possible)
   * with value input (arguments provided to the constructor will fill the fields **p** and **g**)
* without public key **g** (field **g** will have a value of 2):
   * with value generation (field **p** will be generated according to provided parameters if it's possible)
   * with value input (argument provided to the constructor will fill the field **p**)

---

# Code examples

## 1. Session creation:

Session creation after inserting a **secret key** and generate public keys **p** and **g**:
```java
DHKeyExchangeSession aliceSession = new DHKeyExchangeSession(
        new BigInteger(500, SecureRandom.getInstance("SHA1PRNG")), //secret key (example)
        2048, SecureRandom.getInstance("SHA1PRNG"),                //p size 2048 bits, randomness source
        30, SecureRandom.getInstance("SHA1PRNG")                   //g size 30 bits, randomness source
);
                                                                   //[extract and send p and g to Bob]
```

Session creation after inserting a **secret key** and public keys **p** and **g** reception:
```java
                                                                   //[get public keys p and g from Alice]
DHKeyExchangeSession bobSession = new DHKeyExchangeSession(
       new BigInteger(500, SecureRandom.getInstance("SHA1PRNG")),  //secret key (example)
       p,                                                          //BigInteger p was received from Alice
       g                                                           //BigInteger g was received from Alice
);
```

Session creation after inserting a **secret key** and generate public key **p** (public key **g** will be equal to 2, which is [equally secure][2]):
```java
DHKeyExchangeSession aliceSession = new DHKeyExchangeSession(
       new BigInteger(500, SecureRandom.getInstance("SHA1PRNG")),  //secret key (example)
       2048, SecureRandom.getInstance("SHA1PRNG")                  //p size 2048 bits, randomness source
);
                                                                   //[extract and send p to Bob]
```

Session creation after inserting a **secret key** and public key **p** reception (**g** will be equal to 2):
```java
                                                                   //[get public key p from Alice]
DHKeyExchangeSession bobSession = new DHKeyExchangeSession(
       new BigInteger(500, SecureRandom.getInstance("SHA1PRNG")),  //secret key (example)
       p                                                           //BigInteger p was received from Alice
);
```

## 2. Session output:

These methods are used to retrieve data from a session object to send them to a partner:
```java
BigInteger p = aliceSession.getPublicPrimeKey();                   //extract p from Alice session
BigInteger g = aliceSession.getPublicGeneratorKey();               //extract g from Alice session
BigInteger m = aliceSession.getUserModuloKey()                     //extract modulo key from Alice session
                                                                   //[send extracted data to Bob]
```

## 3. Common key calculation:

```java
                                                                   //[get Alice modulo key]
BigInteger commonSecretKey = bobSession.getCommonSecretKey(aliceModKey, bobSecret);
```

```java
                                                                   //[get Bob modulo key]
BigInteger commonSecretKey = aliceSession.getCommonSecretKey(bobModKey, aliceSecret);
```

---

# Meta

For this project has been used **Composition over Inheritance** principle.

Only SecureRandom class may serve as a source of randomness for the **p** and **g** generation.

Liberal use of modifier `final` has been implemented to prevent any possibility of attack through inheritance or overwriting, as well as to provide more thread safety and optimization.

**Double-Speed Safe Prime Generation** has been used to perform **public key p** generation, which can lead to generating Safe Primes one bit larger than intended. 

JDK version used: 11.

---

# Credits

[David Naccache - Double-Speed Safe Prime Generation](https://eprint.iacr.org/2003/175.pdf)


---


[1]: https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange "Wikipedia: Diffie-Hellman Key Exchange"
[2]: https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange#Security "Wikipedia: g is often a small integer such as 2. Because of the random self-reducibility of the discrete logarithm problem a small g is equally secure as any other generator of the same group."
