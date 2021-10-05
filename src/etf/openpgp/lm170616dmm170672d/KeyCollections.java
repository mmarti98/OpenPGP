package etf.openpgp.lm170616dmm170672d;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.Security;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * 
 * Klasa koja implementira metode koje vrše potrebnu obradu kolekcije kljuceva.
 *
 */
public class KeyCollections {

	private static String userHome = "user.home";
	static String path = System.getProperty(userHome) + "\\Desktop\\files\\'";

	private static final String PRIVATE_KEYRING_FILE = path + "privatniKljucevi.bpg";
	private static final String PUBLIC_KEYRING_FILE = path + "javniKljucevi.bpg";

	private static PGPPublicKeyRingCollection public_ring_collection;
	private static PGPSecretKeyRingCollection secret_ring_collection;

	private static File public_rings_file = new File(PUBLIC_KEYRING_FILE);
	private static File secret_rings_file = new File(PRIVATE_KEYRING_FILE);

	/**
	 * Metoda koja ucitava kljuceve iz fajlova koji predstavljaju prsten javnih i
	 * tajnih kljuceva
	 * 
	 * @throws PGPException
	 * @throws IOException
	 */
	static void ucitaj() throws IOException, PGPException {
		Security.addProvider(new BouncyCastleProvider());

		secret_ring_collection = new PGPSecretKeyRingCollection(Collections.EMPTY_LIST);
		public_ring_collection = new PGPPublicKeyRingCollection(Collections.EMPTY_LIST);

		public_rings_file = new File(PUBLIC_KEYRING_FILE);
		secret_rings_file = new File(PRIVATE_KEYRING_FILE);

		if (public_rings_file.exists()) {
			InputStream input = new FileInputStream(public_rings_file);
			public_ring_collection = new PGPPublicKeyRingCollection(input, new JcaKeyFingerprintCalculator());
			System.out.println("ima public ring file:" + public_ring_collection.size());

			input.close();
		}
		if (secret_rings_file.exists()) {

			InputStream input = new FileInputStream(secret_rings_file);
			secret_ring_collection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input),
					new JcaKeyFingerprintCalculator());
			System.out.println("ima secret ring file: " + secret_ring_collection.size());

			input.close();
		}
	}

	/**
	 * Metoda koja obavlja generisanje kljuceva na osnovu zadatih vrijednosti
	 * 
	 * @param dsa_size
	 * @param elgamal_size
	 * @param identity
	 * @param passphrase
	 * @throws Exception
	 */
	public static void generate_key_pair(int dsa_size, int elgamal_size, String identity, char[] passphrase)
			throws Exception {


		DSAKeyGenerator dsa = new DSAKeyGenerator();
		KeyPair dsa_key = dsa.generate(dsa_size);

		ElGamalKeyGenerator elgamal = new ElGamalKeyGenerator();
//		KeyPair elgamal_key = elgamal.generate_slow(elgamal_size);
		KeyPair elgamal_key = elgamal.generate_fast();

		PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsa_key, new Date());
		PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgamal_key, new Date());
		PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
		PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
				identity, sha1Calc, null, null,
				new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
				new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC")
						.build(passphrase));
		keyRingGenerator.addSubKey(elgKeyPair);

		String out_public_string = path + "PUBLIC-" + identity + dsaKeyPair.getPublicKey().getKeyID() + ".asc";
		String out_private_string = path + "PRIVATE-" + identity + dsaKeyPair.getPrivateKey().getKeyID() + ".asc";
		FileOutputStream out1 = new FileOutputStream(out_public_string);
		FileOutputStream out2 = new FileOutputStream(out_private_string);
		OutputStream secretKeyFile = new ArmoredOutputStream(out2);
		OutputStream publicKeyFile = new ArmoredOutputStream(out1);

		PGPSecretKeyRing secretKeyRing = keyRingGenerator.generateSecretKeyRing();
		PGPPublicKeyRing publicKeyRing = keyRingGenerator.generatePublicKeyRing();

		secretKeyRing.encode(secretKeyFile);
		secretKeyFile.close();

		publicKeyRing.encode(publicKeyFile);
		publicKeyFile.close();

		OutputStream public_collection_file = new FileOutputStream(public_rings_file);
		OutputStream secret_collection_file = new FileOutputStream(secret_rings_file);

		public_ring_collection = PGPPublicKeyRingCollection.addPublicKeyRing(public_ring_collection, publicKeyRing);
		public_ring_collection.encode(public_collection_file);
		public_collection_file.close();

		secret_ring_collection = PGPSecretKeyRingCollection.addSecretKeyRing(secret_ring_collection, secretKeyRing);
		secret_ring_collection.encode(secret_collection_file);
		secret_collection_file.close();

	}

	/**
	 * Metoda koja provjerava da li postoji privatni kljuc sa datim KEY_ID
	 * 
	 * @param KEY_ID
	 * @return
	 * @throws PGPException
	 */
	public static boolean check_private_key(long KEY_ID) throws PGPException {
		return secret_ring_collection.getSecretKey(KEY_ID) != null ? true : false;
	}

	/**
	 * Metoda koja dohvata sve javne kljuceve
	 * 
	 * @return List<PGPPublicKeyRing>
	 */
	public static List<PGPPublicKeyRing> get_public_keys() {
		List<PGPPublicKeyRing> lista_javnih_kljuceva = new LinkedList<PGPPublicKeyRing>();
		if (public_ring_collection != null) {
			Iterator it = public_ring_collection.getKeyRings();
			while (it.hasNext()) {
				PGPPublicKeyRing key_ring = (PGPPublicKeyRing) it.next();
				lista_javnih_kljuceva.add(key_ring);
			}
		}
		System.out.println("lista javnih kljuceva:" + lista_javnih_kljuceva.size());

		return lista_javnih_kljuceva;
	}

	/**
	 * Metoda koja dohvata sve tajne kljuceve
	 * 
	 * @return List<PGPSecretKeyRing>
	 */
	public static List<PGPSecretKeyRing> get_secret_keys() {
		List<PGPSecretKeyRing> lista_tajnih_kljuceva = new LinkedList<PGPSecretKeyRing>();
		if (secret_ring_collection != null) {
			Iterator it = secret_ring_collection.getKeyRings();
			while (it.hasNext()) {
				PGPSecretKeyRing key_ring = (PGPSecretKeyRing) it.next();
				lista_tajnih_kljuceva.add(key_ring);
			}
		}

		System.out.println("lista tajnih kljuceva:" + lista_tajnih_kljuceva.size());
		return lista_tajnih_kljuceva;
	}

	/**
	 * Metoda koja dohvata javni kljuc na osnovu KEY_ID
	 * 
	 * @param KEY_ID
	 * @return PGPPublicKey
	 * @throws PGPException
	 */
	public static PGPPublicKey get_public_key(long KEY_ID) throws PGPException {
		return public_ring_collection.getPublicKey(KEY_ID);
	}

	/**
	 * Metoda koja dohvata privatni kljuc na osnovu KEY_ID
	 * 
	 * @param KEY_ID
	 * @return PGPSecretKey
	 * @throws PGPException
	 */
	public static PGPSecretKey get_private_key(long KEY_ID) throws PGPException {
		return secret_ring_collection.getSecretKey(KEY_ID);
	}

	private static PGPPublicKeyEncryptedData public_key_encrypted = null;

	public static PGPPublicKeyEncryptedData get_public_key_encrypted() {
		return public_key_encrypted;
	}

	/**
	 * Metoda koja nalazi privatni kljuc koji je u paru sa javnim kljucem
	 * 
	 * @param lista_javnih_kljuceva
	 * @return PGPSecretKey
	 * @throws PGPException
	 */

	public static PGPPrivateKey privatni_kljuc_pronadjen = null;

	public static PGPPrivateKey find_private_key(List<PGPPublicKeyEncryptedData> lista_javnih_kljuceva,
			String passphrase, int i) throws PGPException {
		PGPSecretKey secret_key = null;
		PGPPrivateKey privateKey = null;
		secret_key = KeyCollections.get_private_key(lista_javnih_kljuceva.get(i).getKeyID());
		if (secret_key != null) {
			public_key_encrypted = lista_javnih_kljuceva.get(i);
			System.out.println(public_key_encrypted.getKeyID());

			try {
				privateKey = secret_key.extractPrivateKey(
						new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray()));
				if (privateKey != null) {
					privatni_kljuc_pronadjen = privateKey;
					System.out.println("BINGO" + privateKey);
					return privateKey;
				}

			} catch (PGPException e) {
				System.out.println("nope");
				find_private_key(lista_javnih_kljuceva, passphrase, i + 1);
			}

		}
		return privateKey;

	}

	/**
	 * Metoda za brisanje javnog kljuca
	 * 
	 * @param key
	 * @throws Exception
	 */
	public static void delete_public_key(PGPPublicKeyRing key) throws Exception {
		public_ring_collection = PGPPublicKeyRingCollection.removePublicKeyRing(public_ring_collection, key);
		OutputStream public_ring_file = new FileOutputStream(public_rings_file);
		public_ring_collection.encode(public_ring_file);
		public_ring_file.close();
	}

	/**
	 * Metoda za brisanje privatnog kljuca
	 * 
	 * @param key
	 * @throws Exception
	 */
	public static void delete_private_key(PGPSecretKeyRing key) throws Exception {
		secret_ring_collection = PGPSecretKeyRingCollection.removeSecretKeyRing(secret_ring_collection, key);
		OutputStream secret_ring_file = new FileOutputStream(secret_rings_file);
		secret_ring_collection.encode(secret_ring_file);
		secret_ring_file.close();
	}

	/**
	 * Metoda za izvoz privatnog kljuca
	 * 
	 * @param user_id
	 * @param secretKeyRing
	 * @throws IOException
	 */
	public static void export_secret_key(String user_id, PGPSecretKeyRing secretKeyRing) throws IOException {
		String out_private_string = path + "PRIVATE-" + user_id + ".asc";
		FileOutputStream out2 = new FileOutputStream(out_private_string);
		OutputStream secretKeyFile = new ArmoredOutputStream(out2);
		secretKeyRing.encode(secretKeyFile);
		secretKeyFile.close();
	}

	/**
	 * Metoda za izvoz javnog kljuca
	 * 
	 * @param user_id
	 * @param publicKeyRing
	 * @throws IOException
	 */
	public static void export_public_key(String user_id, PGPPublicKeyRing publicKeyRing) throws IOException {
		String out_public_string = path + "PUBLIC-" + user_id + ".asc";
		FileOutputStream out2 = new FileOutputStream(out_public_string);
		OutputStream publicKeyFile = new ArmoredOutputStream(out2);
		publicKeyRing.encode(publicKeyFile);
		publicKeyFile.close();

	}

	/**
	 * Metoda za uvoz javnog kljuca
	 * 
	 * @param file_input_stream
	 * @throws IOException
	 * @throws PGPException
	 */
	public static void import_public_key(FileInputStream file_input_stream) throws IOException, PGPException {
		ArmoredInputStream armored = new ArmoredInputStream(file_input_stream);
		PGPPublicKeyRingCollection publicKeyRing = new PGPPublicKeyRingCollection(armored,
				new BcKeyFingerprintCalculator());

		Iterator<PGPPublicKeyRing> iter = publicKeyRing.getKeyRings();
		while (iter.hasNext()) {
			PGPPublicKeyRing ring = iter.next();
			public_ring_collection = PGPPublicKeyRingCollection.addPublicKeyRing(public_ring_collection, ring);
		}
	}

	/**
	 * Metoda za uvoz privatnog kljuca
	 * 
	 * @param file_input_stream
	 * @throws IOException
	 * @throws PGPException
	 */
	public static void import_secret_key(FileInputStream file_input_stream) throws IOException, PGPException {
		ArmoredInputStream armored = new ArmoredInputStream(file_input_stream);
		PGPSecretKeyRingCollection secretKeyRing = new PGPSecretKeyRingCollection(armored,
				new BcKeyFingerprintCalculator());
		Iterator<PGPSecretKeyRing> iter = secretKeyRing.getKeyRings();
		while (iter.hasNext()) {
			PGPSecretKeyRing ring = iter.next();
			secret_ring_collection = PGPSecretKeyRingCollection.addSecretKeyRing(secret_ring_collection, ring);
		}
	}
}
