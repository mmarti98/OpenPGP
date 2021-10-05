package etf.openpgp.lm170616dmm170672d;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.swing.JOptionPane;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

/**
 * Klasa koja implementira metod za enkripciju poruke.
 */
public class Encryption {
	private static int BUFFER_SIZE = 65536;

	/**
	 * Metoda koja sifruje zadati fajl
	 * 
	 * @param ime_izlaznog_fajla_ciphertext
	 * @param ime_ulaznog_fajla_plaintext
	 * @param lista_javnih_kljuceva_za_enkripciju
	 * @param tajni_kljuc_za_potpis
	 * @param passphrase
	 * @param is_radix_conversion_chosen
	 * @param is_zip_chosen
	 * @param tip_simetricnog_algoritma
	 * @throws IOException
	 * @throws PGPException
	 * @throws SignatureException
	 */
	public static void sifrujFajl(String ime_izlaznog_fajla_ciphertext, String ime_ulaznog_fajla_plaintext,
			List<PGPPublicKey> lista_javnih_kljuceva_za_enkripciju, PGPSecretKey tajni_kljuc_za_potpis,
			String passphrase, boolean is_radix_conversion_chosen, boolean is_zip_chosen, int tip_simetricnog_algoritma)
			throws IOException, SignatureException, PGPException {

		Provider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		boolean is_potpisivanje_chosen = tajni_kljuc_za_potpis != null ? true : false;

		PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(tip_simetricnog_algoritma).setWithIntegrityPacket(true)
						.setSecureRandom(new SecureRandom()).setProvider("BC"));

		Iterator<PGPPublicKey> javni_kljucevi = lista_javnih_kljuceva_za_enkripciju.iterator();
		while (javni_kljucevi.hasNext()) {
			encryptedDataGenerator
					.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(javni_kljucevi.next()).setProvider("BC"));
		}

		OutputStream izlazni_fajl_sifrovan = new FileOutputStream(ime_izlaznog_fajla_ciphertext);
		if (is_radix_conversion_chosen) {
			izlazni_fajl_sifrovan = new ArmoredOutputStream(izlazni_fajl_sifrovan);
		}

		OutputStream sifrovano = encryptedDataGenerator.open(izlazni_fajl_sifrovan, new byte[BUFFER_SIZE]);

		PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
		if (is_zip_chosen) {
			sifrovano = compressedDataGenerator.open(sifrovano, new byte[BUFFER_SIZE]);
		}

		PGPSignatureGenerator signatureGenerator = null;
		if (is_potpisivanje_chosen) {
			signatureGenerator = new PGPSignatureGenerator(
					new JcaPGPContentSignerBuilder(tajni_kljuc_za_potpis.getPublicKey().getAlgorithm(), PGPUtil.SHA1)
							.setProvider("BC"));

			PGPPrivateKey privatni_kljuc_za_potpis = null;
			try {
				privatni_kljuc_za_potpis = tajni_kljuc_za_potpis.extractPrivateKey(
						new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray()));
			} catch (PGPException e) {
				JOptionPane.showMessageDialog(null, "Nije dobar passphrase!");
				e.printStackTrace();
			}

			signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privatni_kljuc_za_potpis);

			Iterator<String> user_ids = tajni_kljuc_za_potpis.getPublicKey().getUserIDs();
			String user_id = (String) user_ids.next(); // moze javiti gresku ako nema id ali imace vazda
			PGPSignatureSubpacketGenerator subpacket_generator = new PGPSignatureSubpacketGenerator();
			subpacket_generator.setSignerUserID(false, user_id);
			signatureGenerator.setHashedSubpackets(subpacket_generator.generate());
			signatureGenerator.generateOnePassVersion(false).encode(sifrovano);
		}


		PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
		OutputStream sifrovan_fajl = literalDataGenerator.open(sifrovano, PGPLiteralData.BINARY,
				ime_ulaznog_fajla_plaintext, new Date(), new byte[BUFFER_SIZE]);

		int procitano = 0;
		byte[] buffer = new byte[BUFFER_SIZE];
		FileInputStream input = new FileInputStream(ime_ulaznog_fajla_plaintext);
		while ((procitano = input.read(buffer)) > 0) {
			sifrovan_fajl.write(buffer, 0, procitano);
			if (signatureGenerator != null)
				signatureGenerator.update(buffer, 0, procitano);
		}

		sifrovan_fajl.close();
		if (is_potpisivanje_chosen)
			signatureGenerator.generate().encode(sifrovano);
		sifrovano.close();

		literalDataGenerator.close();
		compressedDataGenerator.close();
		encryptedDataGenerator.close();
		input.close();
		izlazni_fajl_sifrovan.close();
	}

	public static void convert_message_zip(String ime_izlaznog_fajla_ciphertext, String ime_ulaznog_fajla_plaintext)
			throws IOException, PGPException {
		OutputStream izlazni_fajl = new FileOutputStream(ime_izlaznog_fajla_ciphertext);
		PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
		izlazni_fajl = compressedDataGenerator.open(izlazni_fajl, new byte[BUFFER_SIZE]);

		int procitano = 0;
		byte[] buffer = new byte[BUFFER_SIZE];
		FileInputStream input = new FileInputStream(ime_ulaznog_fajla_plaintext);
		while ((procitano = input.read(buffer)) > 0) {
			izlazni_fajl.write(buffer, 0, procitano);
		}
		compressedDataGenerator.close();
		izlazni_fajl.close();
	}

	public static void convert_message_radix64(String ime_izlaznog_fajla_ciphertext, String ime_ulaznog_fajla_plaintext)
			throws IOException {
		OutputStream izlazni_fajl = new FileOutputStream(ime_izlaznog_fajla_ciphertext);
		izlazni_fajl = new ArmoredOutputStream(izlazni_fajl);

		int procitano = 0;
		byte[] buffer = new byte[BUFFER_SIZE];
		FileInputStream input = new FileInputStream(ime_ulaznog_fajla_plaintext);
		while ((procitano = input.read(buffer)) > 0) {
			izlazni_fajl.write(buffer, 0, procitano);
		}

		izlazni_fajl.close();
	}

	public static void convert_message_radix64_and_zip(String ime_izlaznog_fajla_ciphertext,
			String ime_ulaznog_fajla_plaintext) throws IOException, PGPException {
		// prvo ide zip pa onda radix
		OutputStream izlazni_fajl_zipovan = new FileOutputStream("zip" + ime_izlaznog_fajla_ciphertext);
		PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
		izlazni_fajl_zipovan = compressedDataGenerator.open(izlazni_fajl_zipovan, new byte[BUFFER_SIZE]);
		int procitano = 0;
		byte[] buffer = new byte[BUFFER_SIZE];
		FileInputStream input = new FileInputStream(ime_ulaznog_fajla_plaintext);
		while ((procitano = input.read(buffer)) > 0) {
			izlazni_fajl_zipovan.write(buffer, 0, procitano);
		}
		compressedDataGenerator.close();
		izlazni_fajl_zipovan.close();

		// radix
		OutputStream izlazni_fajl = new FileOutputStream("zip" + ime_izlaznog_fajla_ciphertext);
		izlazni_fajl = new ArmoredOutputStream(izlazni_fajl);
		procitano = 0;
		input = new FileInputStream(ime_izlaznog_fajla_ciphertext + "zip");
		while ((procitano = input.read(buffer)) > 0) {
			izlazni_fajl.write(buffer, 0, procitano);
		}

		izlazni_fajl.close();

	}
}
