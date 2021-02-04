/*
Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.
THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

import java.math.BigInteger;

public final class DHKeyExchangeSession {
  // [1]v-------------------VARIABLES--------------------v//
  // All secret variables must be provided and none are stored for security reasons.
  // Variables are made final to prevent attacks by overwriting.

  private final PublicPrimeKey publicPrimeKey; // also known as p.
  private final PublicGeneratorKey publicGeneratorKey; // also known as g.
  private final UserModuloKey userModuloKey; // is equal to g^secret mod p.

  // [1]^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^//

  // [2]v------------------CONSTRUCTORS------------------v//
  // Constructors below are used to initialize variables, no setters provided for maximum
  // reliability.
  // By default publicGeneratorKey.value is set to 2 when it's not provided.

  public DHKeyExchangeSession(BigInteger secretKey, BigInteger prime, BigInteger generator) {
    publicPrimeKey = new PublicPrimeKey(prime);
    publicGeneratorKey = new PublicGeneratorKey(generator, publicPrimeKey);
    userModuloKey =
        new UserModuloKey(publicGeneratorKey, new UserSecretKey(secretKey), publicPrimeKey);
  }

  public DHKeyExchangeSession(BigInteger secretKey, BigInteger prime) {
    publicPrimeKey = new PublicPrimeKey(prime);
    publicGeneratorKey = new PublicGeneratorKey();
    userModuloKey =
        new UserModuloKey(publicGeneratorKey, new UserSecretKey(secretKey), publicPrimeKey);
  }

  public DHKeyExchangeSession(
      BigInteger secretKey,
      int primeBitLength,
      java.security.SecureRandom primeRandom,
      int generatorBitLength,
      java.security.SecureRandom generatorRandom) {
    publicPrimeKey = new PublicPrimeKey(new VariableSetting(primeBitLength, primeRandom));
    publicGeneratorKey =
        new PublicGeneratorKey(
            new VariableSetting(generatorBitLength, generatorRandom), publicPrimeKey);
    userModuloKey =
        new UserModuloKey(publicGeneratorKey, new UserSecretKey(secretKey), publicPrimeKey);
  }

  public DHKeyExchangeSession(
      BigInteger secretKey, int primeBitLength, java.security.SecureRandom primeRandom) {
    publicPrimeKey = new PublicPrimeKey(new VariableSetting(primeBitLength, primeRandom));
    publicGeneratorKey = new PublicGeneratorKey();
    userModuloKey =
        new UserModuloKey(publicGeneratorKey, new UserSecretKey(secretKey), publicPrimeKey);
  }

  // [2]^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^//

  // [3]v--------------------OUTPUT----------------------v//
  // The methods below are used to extract data from the session object after its creation.

  public BigInteger getPublicPrimeKey() {
    return publicPrimeKey.getValue(); // Return generated p.
  }

  public BigInteger getPublicGeneratorKey() {
    return publicGeneratorKey.getValue(); // Return generated g.
  }

  public BigInteger getUserModuloKey() {
    return userModuloKey.getValue(); // Return calculated modulo key.
  }

  public BigInteger getCommonSecretKey(BigInteger partnerModKey, BigInteger secretKey) {
    return new CommonSecretKey(
            new PartnerModuloKey(partnerModKey), new UserSecretKey(secretKey), publicPrimeKey)
        .getValue(); // Return calculated common secret key after receiving the partner modulo key
                     // and inserting the user secret key.
  }

  // [3]^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^//

  // [4]v-------------------CLASSES----------------------v//
  // Classes are made final liberally to prevent attacks by inheritance.
  // Certainty fields use Integer.MAX_VALUE by default to ensure the quality of generated prime
  // numbers.

  private static final class VariableSetting {
    // This class is a wrapper for BigInteger generation settings, used to check input data.
    private final int bitLength;
    private final java.security.SecureRandom random;

    public VariableSetting(int inputBitLength, java.security.SecureRandom inputRandom) {
      if (inputBitLength < 2) throw new ArithmeticException("Bit length is less than two.");
      if (inputRandom == null) throw new NullPointerException("Random source is null.");
      bitLength = inputBitLength;
      random = inputRandom;
    }

    private int getBitLength() {
      return bitLength;
    }

    private java.security.SecureRandom getRandom() {
      return random;
    }
  }

  private static final class UserSecretKey {
    // This class is a wrapper for user secret key, used to check input data
    private final BigInteger value;

    public UserSecretKey(BigInteger input) {
      if (input == null) throw new NullPointerException("Secret key is null.");
      if (input.compareTo(BigInteger.TWO) < 0)
        throw new IllegalArgumentException("Secret key is be less than two.");
      value = input;
    }

    public BigInteger getValue() {
      return value;
    }
  }

  private static final class PublicPrimeKey {
    // This class is a wrapper for public key p, used to check input data and generate a Safe prime
    private final BigInteger value;

    public PublicPrimeKey(BigInteger input) {
      if (input == null) throw new NullPointerException("Public key Prime is null.");
      if (input.compareTo(BigInteger.TWO) < 0)
        throw new IllegalArgumentException("Public key Prime is less than two.");
      if (!input.subtract(BigInteger.ONE).divide(BigInteger.TWO).isProbablePrime(Integer.MAX_VALUE))
        throw new IllegalArgumentException("Public key Prime is not a Safe prime.");
      value = input;
    }

    public PublicPrimeKey(VariableSetting var) {
      value = generateSafePrime(var.getBitLength(), var.getRandom());
    }

    private BigInteger generateSafePrime(int bitLength, java.util.Random inputRandom) {
      BigInteger returnValue;
      do {
        returnValue =
            new BigInteger(
                bitLength,
                Integer.MAX_VALUE,
                inputRandom); // Generate a potential Safe or Sophie Germain prime.
        if (returnValue
            .subtract(BigInteger.ONE)
            .divide(BigInteger.TWO)
            .isProbablePrime(Integer.MAX_VALUE))
          return returnValue; // If (p - 1) / 2 is prime then return p.
        returnValue =
            returnValue.multiply(BigInteger.TWO).add(BigInteger.ONE); // Calculate q * 2 + 1.
      } while (!returnValue.isProbablePrime(Integer.MAX_VALUE));
      return returnValue; // If q * 2 + 1 is prime then return it (will cause a return value to be
                          // one bit larger than bitLength).
    } // Note that this method may produce BitIntegers one bit larger than provided bitLength as
      // described here:  https://eprint.iacr.org/2003/175.pdf.

    public BigInteger getValue() {
      return value;
    }
  }

  private static final class PublicGeneratorKey {
    // This class is a wrapper for public key g, used to check input data or set default value.
    private final BigInteger value;

    public PublicGeneratorKey() {
      value = BigInteger.TWO;
    }

    public PublicGeneratorKey(BigInteger input, PublicPrimeKey prime) {
      if (input == null) throw new NullPointerException("Public key Generator is null.");
      if (prime == null) throw new NullPointerException("Public key Prime is null.");
      if (input.compareTo(BigInteger.TWO) < 0)
        throw new IllegalArgumentException("Public key Generator is less than two.");
      if (!input.equals(BigInteger.TWO) && isNotPrimitiveRootOfP(input, prime.getValue()))
        throw new IllegalArgumentException("Public key Generator is not a primitive root of P.");
      value = input;
    }

    public PublicGeneratorKey(VariableSetting var, PublicPrimeKey prime) {
      if (prime == null) throw new NullPointerException("Public key Prime input object is null.");
      value = generatePrimitiveRoot(var.getBitLength(), var.getRandom(), prime.getValue());
    }

    private BigInteger generatePrimitiveRoot(
        int bitLength, java.util.Random inputRandom, BigInteger p) {
      BigInteger returnValue;
      byte defaultAttempts =
          100; // To prevent an infinite cycle we set a number of default attempts.
      do { // If bitLength is small enough and p is one of some specific groups of primes this
           // method will be unable to generate a proper Generator.
        returnValue = new BigInteger(bitLength, Integer.MAX_VALUE, inputRandom);
        defaultAttempts--;
      } while (isNotPrimitiveRootOfP(returnValue, p) && defaultAttempts > 0);
      if (defaultAttempts > 0) return returnValue;
      throw new ArithmeticException(
          "Can't create Generator with provided parameters, change the parameters or use default Generator value.");
    }

    private boolean isNotPrimitiveRootOfP(BigInteger g, BigInteger p) {
      BigInteger n = p.subtract(BigInteger.ONE);
      if (g.compareTo(n) >= 0) // If g > (p - 1) then g is not a primitive root of p.
      return true;
      java.util.Set<BigInteger> factors = getPrimeFactors(n);
      for (BigInteger factor : factors)
        if (modularExponentiation(g, n.divide(factor), p, BigInteger.ONE).equals(BigInteger.ONE))
          return true;
      return false;
    }

    private java.util.Set<BigInteger> getPrimeFactors(BigInteger n) {
      java.util.Set<BigInteger> factors = new java.util.HashSet<>();
      for (BigInteger i = BigInteger.TWO; i.compareTo(n) <= 0; i = i.add(BigInteger.ONE))
        while (n.mod(i).equals(BigInteger.ZERO)) {
          factors.add(i);
          n = n.divide(i);
          if (n.isProbablePrime(Integer.MAX_VALUE)) return factors;
        }
      return factors;
    }

    private BigInteger modularExponentiation(
        BigInteger base, BigInteger exponent, BigInteger modulus, BigInteger input) {
      if (exponent.equals(BigInteger.ZERO)) return input;
      if (exponent.mod(BigInteger.TWO).equals(BigInteger.ONE))
        return modularExponentiation(
            base, exponent.subtract(BigInteger.ONE), modulus, base.multiply(input).mod(modulus));
      return modularExponentiation(
          base.multiply(base).mod(modulus), exponent.divide(BigInteger.TWO), modulus, input);
    }

    public BigInteger getValue() {
      return value;
    }
  }

  private static final class UserModuloKey {
    // This class is a wrapper for user modulo key, used to calculate g^secret mod p.
    private final BigInteger value;

    public UserModuloKey(
        PublicGeneratorKey publicGeneratorKey,
        UserSecretKey secretKey,
        PublicPrimeKey publicPrimeKey) {
      value =
          calculateModuloKey(
              publicGeneratorKey.getValue(), secretKey.getValue(), publicPrimeKey.getValue());
    }

    private BigInteger calculateModuloKey(BigInteger g, BigInteger s, BigInteger p) {
      return g.modPow(s, p);
    }

    public BigInteger getValue() {
      return value;
    }
  }

  private static final class PartnerModuloKey {
    // This class is a wrapper for partner modulo key, used to check input data.
    private final BigInteger value;

    public PartnerModuloKey(BigInteger input) {
      if (input == null) throw new NullPointerException("Partner modulo key is null.");
      value = input;
    }

    public BigInteger getValue() {
      return value;
    }
  }

  private static final class CommonSecretKey {
    // This class is a wrapper for common secret key, used to calculate partner_modulo_key^secret
    // mod p.
    private final BigInteger value;

    public CommonSecretKey(
        PartnerModuloKey moduloKeyPartner, UserSecretKey secretKey, PublicPrimeKey publicPrimeKey) {
      value =
          calculateSecretKey(
              moduloKeyPartner.getValue(), secretKey.getValue(), publicPrimeKey.getValue());
    }

    private BigInteger calculateSecretKey(BigInteger m, BigInteger s, BigInteger p) {
      return m.modPow(s, p);
    }

    public BigInteger getValue() {
      return value;
    }
  }

  // [4]^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^//
}
