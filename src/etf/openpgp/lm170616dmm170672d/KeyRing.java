package etf.openpgp.lm170616dmm170672d;

import java.awt.GridLayout;
import java.util.Iterator;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class KeyRing extends JPanel {

	/**
	 * Povrsina na kojoj ce se prikazati prsten javnih i privatnih kljuceva
	 */
	private JScrollPane publicKeyRingScrollPane;
	private JScrollPane privateKeyRingScrollPane;

	/**
	 * Naslovi za ScrollPane
	 */
	private static final String privateKeyRingTitle = "PRSTEN PRIVATNIH KLJUCEVA";
	private static final String publicKeyRingTitle = "PRSTEN JAVNIH KLJUCEVA";

	public static List<PGPPublicKeyRing> publicKeys;
	public static List<PGPSecretKeyRing> secretKeys;

	/**
	 * 
	 * 
	 */
	public static JTextArea publicRingTextArea = new JTextArea();
	public static JTextArea privateRingTextArea = new JTextArea();

	/**
	 * Azuriranje prostora za prikaz prstenova
	 * 
	 */
	public static void refreshTextAreas() {
		publicKeys = KeyCollections.get_public_keys();
		secretKeys = KeyCollections.get_secret_keys();
		publicRingTextArea.setText(""); 

		publicRingTextArea.append("User ID:			Public Key:		\n");

		Iterator<PGPPublicKeyRing> iter = publicKeys.iterator();
		while (iter.hasNext()) {
	
			PGPPublicKeyRing ring = iter.next();
			String user_id = (String) ring.getPublicKey().getUserIDs().next();
			publicRingTextArea.append("\n");

			publicRingTextArea.append(
					user_id + "		" + Integer.toHexString((int) ring.getPublicKey().getKeyID()).toUpperCase() + "\n");

		}

		privateRingTextArea.setText(""); 

		privateRingTextArea.append("User ID:			Private Key:		\n");

		Iterator<PGPSecretKeyRing> iter2 = secretKeys.iterator();

		while (iter2.hasNext()) {
		
			PGPSecretKeyRing ring = iter2.next();
			String user_id = (String) ring.getSecretKey().getUserIDs().next();
			privateRingTextArea.append("\n");
			privateRingTextArea.append(
					user_id + "		" + Integer.toHexString((int) ring.getSecretKey().getKeyID()).toUpperCase() + "\n");

		}

	}

	/**
	 * GUI za tab na kom se prikazuju prsten privatnih i javnih kljuceva
	 */
	public KeyRing() {
		super();
		this.setLayout(new GridLayout(1, 2, 30, 30));

		publicRingTextArea.setEditable(false);
		privateRingTextArea.setEditable(false);

		publicKeyRingScrollPane = new JScrollPane(publicRingTextArea);
		publicKeyRingScrollPane.setColumnHeaderView(new JLabel(publicKeyRingTitle));

		privateKeyRingScrollPane = new JScrollPane(privateRingTextArea);
		privateKeyRingScrollPane.setColumnHeaderView(new JLabel(privateKeyRingTitle));

//		refreshTextAreas();

		this.add(privateKeyRingScrollPane);
		this.add(publicKeyRingScrollPane);
	}

}
