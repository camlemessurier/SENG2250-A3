// SSL.java
// Author: Cam Le Messurier 3301398
// Implementation of SSL services.
// For using simplified SSL_DHE_RSA_WITH_AES_256_CBC_SHA

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SSL {

    // General setup
    private static int bitEncryption = 2048;
    private static SecureRandom random = new SecureRandom();

    // RSA values
    private static BigInteger e = new BigInteger("65537"); // public key given by assignemnt specs

    // DH values - given by assignemnt specs
    private static BigInteger DHp = new BigInteger(
            "178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239");
    private static BigInteger DHg = new BigInteger(
            "174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730");

    // AES values
    private static BigInteger opad = new BigInteger(Utilities.strRepeat("5c", 32), 16);
    private static BigInteger ipad = new BigInteger(Utilities.strRepeat("36", 32), 16);
    private static String initVector = "encryptionIntVec";

    // ------------------------------------------------------------------------------
    //
    // RSA Methods
    //
    // ------------------------------------------------------------------------------

    // Calculates a set of RSA keys.
    // rsaKeys[0][0] = modulus
    // rsaKeys[0][1] = private key
    // rsaKeys[1][0] = modulus
    // rsaKeys[1][1] = public key

    public static BigInteger[][] rsaKeyGen() {

        BigInteger rsaKeys[][] = new BigInteger[2][2];
        BigInteger p = Utilities.primeGen(bitEncryption);
        BigInteger q = Utilities.primeGen(bitEncryption);
        BigInteger n; // Modulus
        BigInteger d; // Private Key

        n = p.multiply(q);

        d = e.modInverse(p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)));

        rsaKeys[0][0] = n; // modulus
        rsaKeys[0][1] = d; // private key

        rsaKeys[1][0] = n; // modulus
        rsaKeys[1][1] = e; // public key

        return rsaKeys;
    }

    // Signs a biginteger input, using rsa keys
    public static BigInteger rsaSigGen(BigInteger dhePublicKey, BigInteger[][] rsaKeys) {
        BigInteger hash = (Utilities.SHA256(dhePublicKey.toString())).abs(); // hashes input
        BigInteger rsaSig = rsaEncrypt(hash, rsaKeys); // encrypts hash
        return rsaSig;
    }

    // Checks whether a given rsa signature is valuid
    public static boolean rsaVerifySig(BigInteger dhePubKey, BigInteger rsaSig, BigInteger[][] rsaKeys) {
        BigInteger hash = Utilities.SHA256(dhePubKey.toString()).abs(); // hashed supposed message
        BigInteger rsaSigDecrypted = rsaDecrypt(rsaSig, rsaKeys); // decrypted actual signature
        return rsaSigDecrypted.equals(hash); // Checks if they match each other
    }

    // Encypted message using RSA keys
    public static BigInteger rsaEncrypt(BigInteger messageBI, BigInteger[][] rsaKeys) {

        BigInteger rsaEncrypted = Utilities.modPow(messageBI, rsaKeys[0][1], rsaKeys[0][0]);
        return rsaEncrypted;

    }

    // Decrypts message using RSA keys
    public static BigInteger rsaDecrypt(BigInteger encrypted, BigInteger[][] rsaKeys) {
        BigInteger decrypted = Utilities.modPow(encrypted, rsaKeys[1][1], rsaKeys[1][0]);
        return decrypted;
    }

    // ------------------------------------------------------------------------------
    //
    // DHE Methods
    //
    // ------------------------------------------------------------------------------

    // Creates dhe keys
    // dheKeys[0][0] private key
    // dheKeys[0][1] is session key
    // dheKeys[1][0] public key,
    // dheKeys[1][1] is other public key

    public static BigInteger[][] dheKeyGen() {
        BigInteger[][] dheKeys = new BigInteger[2][2];
        dheKeys[0][0] = dheRandom();
        dheKeys[1][0] = Utilities.modPow(DHg, dheKeys[0][0], DHp);
        return dheKeys;
    }

    // Generatues random DHE value that is less than dhe prime
    public static BigInteger dheRandom() {
        BigInteger DHrandom;
        do {
            DHrandom = new BigInteger(DHp.bitLength(), random);

        } while (DHrandom.compareTo(DHp) >= 0); // repeates until random is less than dhe prime as per dhe
        return DHrandom;
    }

    // calculates session key given dheKeys
    public static BigInteger[][] dheCalculateSessionKey(BigInteger[][] dheKeys) {
        dheKeys[0][1] = Utilities.modPow(dheKeys[1][1], dheKeys[0][0], DHp);
        return dheKeys;
    }

    // ------------------------------------------------------------------------------
    //
    // AES Methods
    //
    // ------------------------------------------------------------------------------

    // Encrypts using AES symmetric encryption
    public static String[] aesEncrypt(String message, BigInteger sessionKey) {

        try {
            String[] messageWithHmac = new String[2];
            SecretKeySpec skeySpec = new SecretKeySpec(sessionKey.toByteArray(), "AES");
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            messageWithHmac[0] = Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes("UTF-8"))); // encrypts
                                                                                                                // message
            messageWithHmac[1] = HMAC(sessionKey, message).toString(); // attaches HMAC to message
            return messageWithHmac;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    // Decrypts using AES symmetric decryption
    public static String aesDecrypt(String encryptedMessage, BigInteger sessionKey) {
        try {

            SecretKeySpec skeySpec = new SecretKeySpec(sessionKey.toByteArray(), "AES");
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedMessage)));
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    // Verifies a HMAC
    public static boolean verifyHMAC(String hmac, String messageIn, BigInteger sessionKey)
            throws NoSuchAlgorithmException {
        return hmac.equals(HMAC(sessionKey, messageIn).toString());
    }

    // Creates a HMAC given a message
    public static BigInteger HMAC(BigInteger sessionKey, String message) {
        return Utilities
                .SHA256(sessionKey.xor(opad).toString() + Utilities.SHA256(sessionKey.xor(ipad).toString() + message));
    }

}
