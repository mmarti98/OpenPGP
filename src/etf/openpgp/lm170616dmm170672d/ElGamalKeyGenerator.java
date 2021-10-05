package etf.openpgp.lm170616dmm170672d;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.spec.DHParameterSpec;

/**
 * Klasa koja sluzi za cuvanje para kljuceva dobijenog pomocu ElGamal algoritma
 *
 */
public class ElGamalKeyGenerator {
	/**
	 * Par kljuceva
	 */
	private KeyPair ElGamalKeyPair;

	/**
	 * Metoda koja na osnovu broja bitova generise par kljuceva pomocu ElGamal
	 * algoritma
	 * 
	 * @param size
	 * @return KeyPair
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public KeyPair generate_slow(int size) throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ElGamal", "BC");
		kpg.initialize(size, new SecureRandom()); // size: 1024 ili 2048
		KeyPair elgamalKeyPair = kpg.generateKeyPair();
		this.ElGamalKeyPair = elgamalKeyPair;
		return elgamalKeyPair;
	}

	/**
	 * Metoda koja generise par kljuceva pomocu ElGamal algoritma
	 * 
	 * @return KeyPair
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public KeyPair generate_fast()
			throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
		BigInteger g = new BigInteger(
				"153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc",
				16);
		BigInteger p = new BigInteger(
				"9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b",
				16);

		DHParameterSpec elParams = new DHParameterSpec(p, g);
		elgKpg.initialize(elParams);
		KeyPair elgKp = elgKpg.generateKeyPair();
		return elgKp;
	}

	/**
	 * Metoda koja dohvata objekat tipa KeyPair
	 * 
	 * @return KeyPair
	 */
	public KeyPair get_key_pair() {
		return ElGamalKeyPair;
	}

	/**
	 * Metoda koja vraca tajni kljuc
	 * 
	 * @return PrivateKey
	 */
	public PrivateKey get_private_key() {
		if (ElGamalKeyPair != null) {
			return ElGamalKeyPair.getPrivate();
		} else
			return null;
	}

	/**
	 * Metoda koja vraca javni kljuc
	 * 
	 * @return PublicKey
	 */
	public PublicKey get_public_key() {
		if (ElGamalKeyPair != null) {
			return ElGamalKeyPair.getPublic();
		} else
			return null;
	}

}
