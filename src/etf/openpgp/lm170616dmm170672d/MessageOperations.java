package etf.openpgp.lm170616dmm170672d;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;

import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class MessageOperations extends JPanel {

	/**
	 * Tekstovi za labele
	 */
	private static final String sendMessagePanelTitle = "SLANJE PORUKE";
	private static final String receiveMessagePanelTitle = "PRIJEM PORUKE";
	private static final String messageLabelText = "Poruka:";
	private static final String encryptionCheckBoxText = "Enkripcija";
	private static final String signatureCheckBoxText = "Potpisivanje";
	private static final String zipCheckBoxText = "ZIP kompresija";
	private static final String radixCheckBoxText = "Radix-64 konverzija";
	private static final String sendMessageButtonText = "Posalji poruku";
	private static final String passwordText = "Lozinka:";
	private static final String privateKeyText = "Privatni kljuc:";
	private static final String algorithmText = "Algoritam:";
	private static final String publicKeysText = "Javni kljuc:";
	private static final String fileText = "Datoteka:";
	private static final String importButtonText = "Ucitaj";
	private static final String decryptText = "Dekriptuj";
	private static final String userHome = "user.home";
	private static final String path = System.getProperty(userHome) + "\\Desktop\\files\\";

	/**
	 * Algoritmi za simetricne kljuceve koje aplikacija podrzava
	 */
	private static String[] algorithmNames = { "3DES", "AES" };

	/**
	 * Izbor algoritma
	 */
	private JComboBox algorithmOptions = new JComboBox(algorithmNames);
	/**
	 * Izbor privatnog kljuca za potpisivanje
	 */
	private static JComboBox privateKeyOptions = new JComboBox();
	/**
	 * Polje za unos lozinke za privatni kljuc
	 */
	private JPasswordField passwordTextField = new JPasswordField();
	/**
	 * Polje za unos lozinke kod dekriptovanja
	 */
	private JPasswordField passwordDecryptTextField = new JPasswordField();

	/**
	 * Opcija da se enkriptuje poruka
	 */
	private JCheckBox encryptionCheckBox = new JCheckBox(encryptionCheckBoxText);

	/**
	 * Lista javnih kljuceva za enkripciju
	 */
	private static JList publicKeysList;
	/**
	 * Opcija za potpis poruke
	 */
	private JCheckBox signatureCheckBox = new JCheckBox(signatureCheckBoxText);
	/**
	 * Opcija za ZIP kompresiju poruke
	 */
	private JCheckBox zipCheckBox = new JCheckBox(zipCheckBoxText);
	/**
	 * Opcija za Radix-64 konverziju poruke
	 */
	private JCheckBox radixCheckBox = new JCheckBox(radixCheckBoxText);

	/**
	 * Poruka za enkripciju i dekripciju
	 */
	private File messageFile;
	private File messageToDecryptFile;

	/**
	 * Postavljanje kljuceva u padajuce liste
	 */
	public static void refreshKeyLists() {
		List<PGPPublicKeyRing> publicKeys = KeyCollections.get_public_keys();
		List<PGPSecretKeyRing> secretKeys = KeyCollections.get_secret_keys();
		DefaultComboBoxModel<String> secretKeysModel = new DefaultComboBoxModel();

		for (Iterator iterator = secretKeys.iterator(); iterator.hasNext();) {

			PGPSecretKeyRing pgpSecretKeyRing = (PGPSecretKeyRing) iterator.next();
			secretKeysModel.addElement((String) pgpSecretKeyRing.getPublicKey().getUserIDs().next());

		}

		privateKeyOptions.setModel(secretKeysModel);

		DefaultComboBoxModel<String> publicKeysModel = new DefaultComboBoxModel();

		for (Iterator iterator = publicKeys.iterator(); iterator.hasNext();) {

			PGPPublicKeyRing pgpPublicKeyRing = (PGPPublicKeyRing) iterator.next();
			publicKeysModel.addElement((String) pgpPublicKeyRing.getPublicKey().getUserIDs().next());
		}

		publicKeysList.setModel(publicKeysModel);
	}

	/**
	 * GUI za tab na kom je prijem i slanje poruke
	 */
	public MessageOperations() {
		super();
		this.setLayout(new GridLayout(2, 1));

		JPanel sendMessagePanel = new JPanel(new GridLayout(6, 5, 15, 15));

		// GUI za slanje poruke
		sendMessagePanel.add(new JLabel(sendMessagePanelTitle));
		sendMessagePanel.add(new JLabel());
		sendMessagePanel.add(new JLabel());
		sendMessagePanel.add(new JLabel());
		sendMessagePanel.add(new JLabel());

		sendMessagePanel.add(new JLabel(messageLabelText));

		JButton messageButton = new JButton(importButtonText);
		sendMessagePanel.add(messageButton);
		messageButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser();

				int returnVal = fileChooser.showOpenDialog(null);

				if (returnVal == JFileChooser.APPROVE_OPTION) {
					messageFile = fileChooser.getSelectedFile();
					System.out.println(messageFile.getName() + " " + messageFile.getAbsolutePath());
				}
			}
		});
		sendMessagePanel.add(new JLabel());
		sendMessagePanel.add(new JLabel());
		sendMessagePanel.add(new JLabel());

		sendMessagePanel.add(encryptionCheckBox);
		encryptionCheckBox.setSelected(true);
		encryptionCheckBox.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				zipCheckBox.setEnabled(true);
				radixCheckBox.setEnabled(true);
				if (encryptionCheckBox.isSelected()) {
					algorithmOptions.setEnabled(true);
					publicKeysList.setEnabled(true);

				} else {
					algorithmOptions.setEnabled(false);
					publicKeysList.setEnabled(false);
				}
				if (!encryptionCheckBox.isSelected() && signatureCheckBox.isSelected()) {
					zipCheckBox.setEnabled(false);
					radixCheckBox.setEnabled(false);

				}

			}
		});
		sendMessagePanel.add(new JLabel(algorithmText));
		sendMessagePanel.add(algorithmOptions);
		sendMessagePanel.add(new JLabel(publicKeysText));
		// mogucnost biranja vise od jednog kljuca
		publicKeysList = new JList();
		publicKeysList.setVisibleRowCount(3);
		publicKeysList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		sendMessagePanel.add(new JScrollPane(publicKeysList));

		sendMessagePanel.add(signatureCheckBox);
		signatureCheckBox.setSelected(true);
		signatureCheckBox.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				zipCheckBox.setEnabled(true);
				radixCheckBox.setEnabled(true);
				if (signatureCheckBox.isSelected()) {
					privateKeyOptions.setEnabled(true);
					passwordTextField.setEnabled(true);

				} else {
					privateKeyOptions.setEnabled(false);
					passwordTextField.setEnabled(false);
				}
				if (!encryptionCheckBox.isSelected() && signatureCheckBox.isSelected()) {
					zipCheckBox.setEnabled(false);
					radixCheckBox.setEnabled(false);

				}

			}
		});
		sendMessagePanel.add(new JLabel(privateKeyText));
		sendMessagePanel.add(privateKeyOptions);
		sendMessagePanel.add(new JLabel(passwordText));
		sendMessagePanel.add(passwordTextField);

		sendMessagePanel.add(zipCheckBox);
		sendMessagePanel.add(radixCheckBox);
		JButton sendMessageButton = new JButton(sendMessageButtonText);
		sendMessageButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				boolean encryption = false;
				String encryption_algorithm;
				String[] passwords;
				int encryption_alg = PGPEncryptedData.NULL;
				List<String> selectedPublicKeys_list = null;

				if (encryptionCheckBox.isSelected()) {
					System.out.println("Enkripcija izabrana");
					encryption = true;
					encryption_algorithm = String.valueOf(algorithmOptions.getSelectedItem());
					System.out.println(encryption_algorithm);
					if (encryption_algorithm.equals("AES")) {
						encryption_alg = PGPEncryptedData.AES_128;
					} else {
						encryption_alg = PGPEncryptedData.TRIPLE_DES;
					}

					selectedPublicKeys_list = publicKeysList.getSelectedValuesList();
					for (String elem : selectedPublicKeys_list) {
						System.out.println(elem);
					}
				}
				boolean signature = false;
				String password = new String("");
				if (signatureCheckBox.isSelected()) {
					System.out.println("Potpisivanje izabrano");
					signature = true;
					String selectedPrivateKey = String.valueOf(privateKeyOptions.getSelectedItem());
					System.out.println(selectedPrivateKey);

					password = new String(passwordTextField.getPassword());
					System.out.println(password);

				}
				boolean radix64 = radixCheckBox.isSelected();
				boolean zip = zipCheckBox.isSelected();

				if (encryptionCheckBox.isSelected() && publicKeysList.getSelectedValuesList().isEmpty()) {
					JOptionPane.showMessageDialog(null, "Izaberite javni kljuc! ");
				} else if (signatureCheckBox.isSelected() && privateKeyOptions.getSelectedItem() == null) {

					JOptionPane.showMessageDialog(null, "Izaberite privatni kljuc! ");

				} else if (password.equals("") && signatureCheckBox.isSelected()) {

					JOptionPane.showMessageDialog(null, "Unesite lozinku! ");

				} else {

					List<PGPPublicKeyRing> publicKeys = KeyCollections.get_public_keys();
					List<PGPPublicKey> javni_kljucevi_lista = new LinkedList<PGPPublicKey>();

					if (encryptionCheckBox.isSelected()) {
						for (Iterator iterator = selectedPublicKeys_list.iterator(); iterator.hasNext();) { 
							String selectedPublicKey = (String) iterator.next();
							// System.out.println(selectedPublicKey + "selected");
							Iterator<PGPPublicKeyRing> iter = publicKeys.iterator();

							while (iter.hasNext()) {
								PGPPublicKeyRing ring = iter.next();
								String user_id = (String) ring.getPublicKey().getUserIDs().next();
								// za jedan ring trazimo kljuc za enkripciju
								Iterator it = ring.getPublicKeys();
								while (user_id.equals(selectedPublicKey) && it.hasNext()) 
								{
									PGPPublicKey k = (PGPPublicKey) it.next();
									if (k.isEncryptionKey()) {
									
										javni_kljucevi_lista.add((PGPPublicKey) k); 
									}
								}
							}
						}
					} 
					String plaintext = messageFile.getAbsolutePath();
					String ciphertext = path + "cipher.txt";

					Encryption sifrovanje = new Encryption();
					PGPSecretKey kljuc_za_potpis = null;
					if (signature) {
						List<PGPSecretKeyRing> secretKeys = KeyCollections.get_secret_keys();
						Iterator<PGPSecretKeyRing> iter2 = secretKeys.iterator();

						PGPSecretKeyRing ring = iter2.next();
						String user_id = (String) ring.getSecretKey().getUserIDs().next();
						System.out.println(user_id + "userid");
						String chosenUserID = String.valueOf(privateKeyOptions.getSelectedItem());
						System.out.println(chosenUserID + "chosenuserId");
						kljuc_za_potpis = ring.getSecretKey();
						while (iter2.hasNext() && !user_id.equals(chosenUserID)) {
							ring = iter2.next();
							user_id = (String) ring.getSecretKey().getUserIDs().next();
							System.out.println(user_id + "userid");
							kljuc_za_potpis = ring.getSecretKey();

						}
					} // ako je potpis trazen

					try {
						if (encryption) {
							Encryption.sifrujFajl(ciphertext, plaintext, javni_kljucevi_lista, kljuc_za_potpis,
									password, radix64, zip, encryption_alg);

							JOptionPane.showMessageDialog(null, "Poruka je poslata! ");
							passwordTextField.setText("");
						} // sad gledamo ako nije enkripcija
						else if (radix64 && !zip && !signature) {
							Encryption.convert_message_radix64(ciphertext, plaintext);
							JOptionPane.showMessageDialog(null, "Poruka je poslata! ");

						} else if (zip && !signature && !radix64) {
							Encryption.convert_message_zip(ciphertext, plaintext);
							JOptionPane.showMessageDialog(null, "Poruka je poslata! ");

						} else if (zip && radix64 && !signature) {
							Encryption.convert_message_radix64_and_zip(ciphertext, plaintext);
							JOptionPane.showMessageDialog(null, "Poruka je poslata! ");

						} else if (signature) {

							InputStream ulazni_fajl = new FileInputStream(plaintext);

							try {
								Signing.sign_message(ulazni_fajl, kljuc_za_potpis, password, true, true);
								JOptionPane.showMessageDialog(null, "Poruka je poslata! ");

							} catch (Exception e1) {
								JOptionPane.showMessageDialog(null, "Poruka nije poslata! ");

								e1.printStackTrace();
							}

						}
					} catch (SignatureException e1) {
						e1.printStackTrace();
						JOptionPane.showMessageDialog(null, "Poruka nije poslata! ");
						passwordTextField.setText("");

					} catch (IOException e1) {
						e1.printStackTrace();
						JOptionPane.showMessageDialog(null, "Poruka nije poslata! ");
						passwordTextField.setText("");

					} catch (PGPException e1) {
						e1.printStackTrace();
						JOptionPane.showMessageDialog(null, "Poruka nije poslata! ");
						passwordTextField.setText("");
					}

				}
			}
		});
		sendMessagePanel.add(sendMessageButton);

		sendMessagePanel.add(new JLabel());
		sendMessagePanel.add(new JLabel());
		sendMessagePanel.add(new JLabel());
		sendMessagePanel.add(new JLabel());
		sendMessagePanel.add(new JLabel());

		// GUI za prijem poruke
		JPanel receiveMessagePanel = new JPanel(new GridLayout(6, 3, 15, 15));

		receiveMessagePanel.add(new JSeparator());
		receiveMessagePanel.add(new JSeparator());
		receiveMessagePanel.add(new JSeparator());

		receiveMessagePanel.add(new JLabel(receiveMessagePanelTitle));
		receiveMessagePanel.add(new JLabel());
		receiveMessagePanel.add(new JLabel());

		receiveMessagePanel.add(new JLabel(fileText));
		JButton receiveMessageButton = new JButton(importButtonText);
		receiveMessageButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser();

				int returnVal = fileChooser.showOpenDialog(null);

				if (returnVal == JFileChooser.APPROVE_OPTION) {
					messageToDecryptFile = fileChooser.getSelectedFile();
					System.out.println(messageToDecryptFile.getName() + " " + messageToDecryptFile.getAbsolutePath());
				}

			}
		});
		receiveMessagePanel.add(receiveMessageButton);
		receiveMessagePanel.add(new JLabel());

		receiveMessagePanel.add(new JLabel(passwordText));
		receiveMessagePanel.add(passwordDecryptTextField);
		JButton decryptButton = new JButton(decryptText);
		decryptButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				String password = new String(passwordDecryptTextField.getPassword());
				System.out.println(password);
				if (password.isEmpty()) {
					JOptionPane.showMessageDialog(null, "Unesite lozinku! ");
				} else {
					// putanja do datoteke
					String ciphertext = messageToDecryptFile.getAbsolutePath();

					Decryption desifrovanje = new Decryption();
					try {

						ByteArrayOutputStream izlazni_byte_fajl = desifrovanje.desifruj(ciphertext, password);
						passwordDecryptTextField.setText("");
						if (izlazni_byte_fajl != null)
						// izbor zeljene lokacije
						{
							JFileChooser chooser = new JFileChooser();
							if (chooser.showSaveDialog(MessageOperations.this) == JFileChooser.APPROVE_OPTION) {
								System.out.println(chooser.getSelectedFile());
								OutputStream izlazni_desifrovan_fajl = new FileOutputStream(chooser.getSelectedFile());
								izlazni_byte_fajl.writeTo(izlazni_desifrovan_fajl);
							}
						}

					} catch (Exception e1) {
						e1.printStackTrace();
						JOptionPane.showMessageDialog(null, "Poruka nije desifrovana! ");
						passwordDecryptTextField.setText("");
					}
				}
			}
		});
		receiveMessagePanel.add(decryptButton);

		receiveMessagePanel.add(new JLabel());
		receiveMessagePanel.add(new JLabel());
		receiveMessagePanel.add(new JLabel());

		receiveMessagePanel.add(new JLabel());
		receiveMessagePanel.add(new JLabel());
		receiveMessagePanel.add(new JLabel());

		//
		this.add(sendMessagePanel);
		this.add(receiveMessagePanel);

	}
}
