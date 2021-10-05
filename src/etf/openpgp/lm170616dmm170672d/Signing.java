package etf.openpgp.lm170616dmm170672d;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.StringWriter;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JOptionPane;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class Signing {
	/**
	 * Metod koji potpisuje poruku
	 * 
	 * @param inputStream
	 * @param tajni_kljuc_za_potpis
	 * @param passphrase
	 * @param zip
	 * @param radix
	 * @return OutputStream
	 * @throws Exception
	 */
	public static OutputStream sign_message(InputStream inputStream, PGPSecretKey tajni_kljuc_za_potpis,
			String passphrase, boolean zip, boolean radix) throws Exception {

		StringWriter writer = new StringWriter();
		IOUtils.copy(inputStream, writer, "UTF8");
		String plaintext = writer.toString();
		System.out.println(plaintext);

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		ArmoredOutputStream armOut = new ArmoredOutputStream(bOut);
		ByteArrayInputStream bIn = new ByteArrayInputStream(plaintext.getBytes("UTF8"));

		armOut.beginClearText(PGPUtil.SHA1);
		armOut.write(plaintext.getBytes("UTF8"));
		armOut.write('\r');
		armOut.write('\n');
		armOut.endClearText();

		PGPPrivateKey privatni_kljuc_za_potpis = null;
		try {
			privatni_kljuc_za_potpis = tajni_kljuc_za_potpis.extractPrivateKey(
					new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray()));
		} catch (PGPException e) {
			JOptionPane.showMessageDialog(null, "Nije dobar passphrase!");
			e.printStackTrace();
			return null;
		}

		PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
				new JcaPGPContentSignerBuilder(tajni_kljuc_za_potpis.getPublicKey().getAlgorithm(), PGPUtil.SHA1)
						.setProvider("BC"));
		signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privatni_kljuc_za_potpis);

		Iterator it = tajni_kljuc_za_potpis.getPublicKey().getUserIDs();
		if (it.hasNext()) {
			PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
			spGen.setSignerUserID(false, (String) it.next());
			signatureGenerator.setHashedSubpackets(spGen.generate());
		}

		BCPGOutputStream bbOut = new BCPGOutputStream(armOut);

		int SIZE = 65536;
		byte[] buf = new byte[SIZE];
		int read_size = 0;

		while ((read_size = bIn.read(buf)) >= 0) {
			signatureGenerator.update(buf, 0, read_size);
		}
		PGPSignature sig = signatureGenerator.generate();
		sig.encode(bbOut);

		armOut.close();

		final OutputStream os = new FileOutputStream(KeyCollections.path + "signed.txt");
		final PrintStream printStream = new PrintStream(os);
		printStream.print(new String(bOut.toByteArray(), "UTF8"));
		printStream.close();

		return os;
	}

	/**
	 * Metod koji provjerava potpisanu poruku
	 * 
	 * @param inputStream
	 * @return String
	 * @throws Exception
	 */
	public static String verifySign(InputStream inputStream) throws Exception {
		StringWriter writer = new StringWriter();
		IOUtils.copy(inputStream, writer, "UTF8");
		String plaintext = writer.toString();
		System.out.println(plaintext);
		String rex = "-----BEGIN PGP SIGNED MESSAGE-----\\r?\\n.*?\\r?\\n\\r?\\n(.*)\\r?\\n(-----BEGIN PGP SIGNATURE-----\\r?\\n.*-----END PGP SIGNATURE-----)";
		Pattern sablon = Pattern.compile(rex, Pattern.CANON_EQ | Pattern.DOTALL);
		Matcher matcher = sablon.matcher(plaintext);
		if (matcher.find()) {
			String datainfo = matcher.group(1);
			String signinfo = matcher.group(2);
			ByteArrayInputStream dataIn = new ByteArrayInputStream(datainfo.getBytes("UTF8"));
			ByteArrayInputStream signIn = new ByteArrayInputStream(signinfo.getBytes("UTF8"));
			InputStream key_input = (InputStream) signIn;
			InputStream key_private = PGPUtil.getDecoderStream(key_input);
			PGPObjectFactory pgpFact = new PGPObjectFactory(key_private, new KeyFingerPrintCalculator() {

				@Override
				public byte[] calculateFingerprint(PublicKeyPacket arg0) throws PGPException {
					return null;
				}
			});

			PGPSignatureList signatureList = (PGPSignatureList) pgpFact.nextObject();
			PGPSignature signature = signatureList.get(0);

			PGPPublicKey key = KeyCollections.get_public_key(signature.getKeyID());
			signature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

			for (int i = 0; datainfo.charAt(i) != '\r'; i++) {
				signature.update((byte) datainfo.charAt(i));
			}

			if (signature.verify()) {
				String user_potpisao = "Poruku potpisao/la " + (String) key.getUserIDs().next();
				return user_potpisao;
			} else {
				String poruka = "Nije moguce odrediti ko je potpisao poruku!";
				return poruka;
			}

		}
		return null;
	}

}
