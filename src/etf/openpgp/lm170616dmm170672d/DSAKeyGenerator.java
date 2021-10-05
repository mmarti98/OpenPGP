package etf.openpgp.lm170616dmm170672d;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Klasa koja sluzi za cuvanje para kljuceva dobijenog pomocu DSA algoritma
 *
 */
public class DSAKeyGenerator {
	/**
	 * Par kljuceva
	 */
	private KeyPair dsaKeyPair;

	/**
	 * Metoda koja na osnovu broja bitova generise par kljuceva pomocu DSA algoritma
	 * 
	 * @param size
	 * @return KeyPair
	 * @throws NoSuchAlgorithmException
	 */
	public KeyPair generate(int size) throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
		kpg.initialize(size, new SecureRandom()); // size: 1024 ili 2048
		KeyPair dsaKeyPair = kpg.generateKeyPair();
		this.dsaKeyPair = dsaKeyPair;
		return dsaKeyPair;
	}

	/**
	 * Metoda koja dohvata objekat tipa KeyPair
	 * 
	 * @return KeyPair
	 */
	public KeyPair get_key_pair() {
		return dsaKeyPair;
	}

	/**
	 * Metoda koja vraca tajni kljuc
	 * 
	 * @return PrivateKey
	 */
	public PrivateKey get_private_key() {
		if (dsaKeyPair != null) {
			return dsaKeyPair.getPrivate();
		} else
			return null;
	}

	/**
	 * Metoda koja vraca javni kljuc
	 * 
	 * @return PublicKey
	 */
	public PublicKey get_public_key() {
		if (dsaKeyPair != null) {
			return dsaKeyPair.getPublic();
		} else
			return null;
	}

}
