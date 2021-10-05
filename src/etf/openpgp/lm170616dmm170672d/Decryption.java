package etf.openpgp.lm170616dmm170672d;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.InflaterInputStream;

import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

/**
 * Klasa koja implementira metod za dekripciju poruke.
 */
public class Decryption {

	public boolean is_verifikacija_potpisa_successful = false;
	public boolean is_poruka_potpisana = false;
	public String id_potpisnika = "";

	/**
	 * Metoda koja desifruje zadati fajl
	 * 
	 * @param ime_sifrovan_fajl
	 * @param passphrase
	 * @throws Exception
	 */
	public ByteArrayOutputStream desifruj(String ime_sifrovan_fajl, String passphrase) throws Exception {
		InputStream ulazni_sifrovan_fajl = new FileInputStream(ime_sifrovan_fajl);
		ByteArrayOutputStream izlazni_byte_fajl = new ByteArrayOutputStream();

		PGPOnePassSignatureList onePassSignatureList = null;
		PGPSignatureList signatureList = null;
		PGPPublicKey pubKey = null;

		ulazni_sifrovan_fajl = PGPUtil.getDecoderStream(ulazni_sifrovan_fajl);
		PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(ulazni_sifrovan_fajl,
				new JcaKeyFingerprintCalculator());
		PGPEncryptedDataList encryptedDataList = null;
		Object o = null;

		try {
			o = pgpObjectFactory.nextObject();
		} catch (IOException e) {

		}

		if (o instanceof PGPEncryptedDataList) {
			encryptedDataList = (PGPEncryptedDataList) o;
		} else {

			try {
				o = pgpObjectFactory.nextObject();
			} catch (IOException e) {
				// radi se samo o potpisu
				InputStream izlazni_desifrovan_fajl = new FileInputStream(KeyCollections.path + "signed.txt");

				String textt2 = Signing.verifySign(izlazni_desifrovan_fajl);
				System.out.println(textt2);
				JOptionPane.showMessageDialog(null, textt2);
				ByteArrayOutputStream izlaz = new ByteArrayOutputStream();
				izlaz.write(textt2.getBytes());
				return null;
			}

			if (o != null && o instanceof PGPEncryptedDataList) {
				encryptedDataList = (PGPEncryptedDataList) o;
			}
		}

		Iterator encryptedObjects = encryptedDataList.getEncryptedDataObjects();
		PGPPublicKeyEncryptedData javni_kljuc_za_enkripciju = null;

		List<PGPPublicKeyEncryptedData> lista_javnih_kljuceva = new LinkedList();
		while (encryptedObjects.hasNext()) {
			Object obj = encryptedObjects.next();
			if (obj instanceof PGPPublicKeyEncryptedData) {
				lista_javnih_kljuceva.add((PGPPublicKeyEncryptedData) obj);
			}
		}

		KeyCollections.find_private_key(lista_javnih_kljuceva, passphrase, 0);
		PGPPrivateKey privateKey = KeyCollections.privatni_kljuc_pronadjen;
		if (privateKey != null) {
			// pronadjen privatni kljuc za enkripciju
			javni_kljuc_za_enkripciju = KeyCollections.get_public_key_encrypted();
		} else {
			System.out.println("Kljuc nije nadjen" + privateKey);

			JOptionPane.showMessageDialog(null, "Kljuc nije nadjen!");
			// return null;
		}

		InputStream clear = javni_kljuc_za_enkripciju
				.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));
		PGPObjectFactory objFactory = new JcaPGPObjectFactory(clear);
		Object message = objFactory.nextObject();

		while (message != null) {
			if (message instanceof PGPCompressedData) {
				System.out.println("Dekripcija: Poruka je zipovana");
				PGPCompressedData compressedData = (PGPCompressedData) message;
				objFactory = new PGPObjectFactory(compressedData.getDataStream(), new JcaKeyFingerprintCalculator());
				message = objFactory.nextObject();
			}

			if (message instanceof PGPLiteralData) {
				System.out.println("Dekripcija: Poruka je ekriptovana");
				InputStream input = ((PGPLiteralData) message).getInputStream();
				Streams.pipeAll(input, izlazni_byte_fajl);
			} else if (message instanceof PGPOnePassSignatureList) {
				is_poruka_potpisana = true;
				System.out.println("Dekripcija: Poruka je potpisana");
				PGPOnePassSignature passSignature = ((PGPOnePassSignatureList) message).get(0);
				pubKey = KeyCollections.get_public_key(passSignature.getKeyID());

				if (pubKey == null) {
					System.out.println("Dekripcija: Nije pronadjen javni kljuc za provjeru potpisa");
					return null;
				}
				onePassSignatureList = (PGPOnePassSignatureList) message;
			} else if (message instanceof PGPSignatureList) {
				// System.out.println("Dekripcija: Poruka je signaturelist");
				signatureList = (PGPSignatureList) message;
			} else {
				System.out.println("*******Ovaj tip poruke se ne moze desifrovati*********");
				return null;
			}

			message = objFactory.nextObject();
		}

		byte[] output = izlazni_byte_fajl.toByteArray();

		if (is_poruka_potpisana) {
			PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);
			onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKey);
			onePassSignature.update(output);
			int i = 0;
			while (i != onePassSignatureList.size()) {

				PGPSignature signature = signatureList.get(i);
				if (onePassSignature.verify(signature)) {
					is_verifikacija_potpisa_successful = true;
					id_potpisnika = (String) pubKey.getUserIDs().next();
					System.out.println("Dekripcija: Poruka je potpisao/la: " + id_potpisnika);
					JOptionPane.showMessageDialog(null, "Dekripcija: Poruku je potpisao/la: " + id_potpisnika);

				} else {
					System.out.println("********Verifikacija nije uspjela****");
					return null;
				}
				i++;
			}

		}
		return izlazni_byte_fajl;
	}

	public static void convert_message(String ime_sifrovan_fajl) throws IOException {
		InputStream ulazni_sifrovan_fajl = new FileInputStream(ime_sifrovan_fajl);
		Base64.Decoder decoder = Base64.getDecoder();
		String dStr = new String(decoder.decode(ulazni_sifrovan_fajl.toString()));
		ByteArrayOutputStream izlazni_byte_fajl = new ByteArrayOutputStream();
		izlazni_byte_fajl.write(dStr.getBytes());
	}

	public static void decompress_file(String ime_fajla) throws IOException {
		FileInputStream fis = new FileInputStream(ime_fajla);
		FileOutputStream fos = new FileOutputStream("dekompresovan.txt");
		InflaterInputStream iis = new InflaterInputStream(fis);
		int data;
		while ((data = iis.read()) != -1) {
			fos.write(data);
		}

		fos.close();
		iis.close();
	}

}
