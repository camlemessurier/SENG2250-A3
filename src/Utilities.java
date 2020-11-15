// Utilities.java
// Author: Cam Le Messurier 3301398
// Provides basic utils for simplified SSL handshake 

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class Utilities {

    // Generates a random prime
    public static BigInteger primeGen(int bitEncryption) {
        Random rand = new SecureRandom();
        return BigInteger.probablePrime(bitEncryption / 2, rand);
    }

    // Calculates a SHA256 hash
    public static BigInteger SHA256(String input) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return new BigInteger(hash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;

    }

    // Creates multiples of strings for ipad and opad
    public static String strRepeat(String input, int numRepeats) {
        String result = "";
        for (int i = 0; i < numRepeats; i++) {
            result += input;
        }
        return result;
    }

    // Fast mod exponentiation
    public static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus) {

        BigInteger modPow = BigInteger.ONE;

        // Trivial case
        if (modulus.equals(BigInteger.ONE)) {
            return BigInteger.ZERO;
        }

        // While sign of exponent is positive
        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            // If exponent is odd
            if (exponent.testBit(0)) {
                modPow = (modPow.multiply(base)).mod(modulus);
            }
            exponent = exponent.shiftRight(1);
            base = (base.multiply(base)).mod(modulus);
        }
        return modPow.mod(modulus);
    }

}
