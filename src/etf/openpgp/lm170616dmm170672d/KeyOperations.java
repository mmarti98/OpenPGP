package etf.openpgp.lm170616dmm170672d;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import javax.swing.ButtonGroup;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class KeyOperations extends JPanel {

	/**
	 * Nazivi polja
	 */
	private static final String importKeysPanelTitleText = "UVOZ KLJUCA";
	private static final String exportPrivateKeysPanelTitleText = "IZVOZ PRIVATNOG KLJUCA";
	private static final String exportPublicKeysPanelTitleText = "IZVOZ JAVNOG KLJUCA";
	private static final String publicKeyRadioButtonText = "Javni kljuc";
	private static final String privateKeyRadioButtonText = "Privatni kljuc";
	private static final String importButtonText = "Uvezi";
	private static final String exportPublicKeyButtonText = "Izvezi javni kljuc";
	private static final String exportPrivateKeyButtonText = "Izvezi privatni kljuc";
	private static final String generateKeysPanelTitleText = "GENERISANJE NOVOG PARA KLJUCEVA";
	private static final String nameLabelText = "Ime:";
	private static final String emailLabelText = "Email:";
	private static final String DSA_optionsLabelText = "DSA za potpisivanje (bitovi):";
	private static final String ElGamal_optionsLabelText = "ElGamal za enkripciju (bitovi):";
	private static final String passwordLabelText = "Lozinka:";
	private static final String generateKeysButtonLabel = "Generisi kljuceve";
	private static final String deletePublicKeyLabel = "BRISANJE JAVNOG KLJUCA";
	private static final String deletePublicKeyButtonLabel = "Obrisi javni kljuc";
	private static final String deletePrivateKeyLabel = "BRISANJE PRIVATNOG KLJUCA";
	private static final String deletePrivateKeyButtonLabel = "Obrisi privatni kljuc";

	/**
	 * Broj bita kljuceva sa kojima rade algoritmi za potpisivanje i enkripciju
	 */
	private static String[] DSA_bit_options = { "1024", "2048" };
	private static String[] ElGamal_bit_options = { "1024", "2048", "4096" };

	/**
	 * Polje za ime, email i lozinku korisnika za kog se kreira novi par kljuceva
	 */
	private JTextField nameTextField = new JTextField();
	private JTextField emailTextField = new JTextField();
	private JPasswordField passwordField = new JPasswordField();
	/**
	 * Izbor broja bita kljuceva sa kojima rade algoritmi za potpisivanje i
	 * enkripciju
	 */
	private JComboBox DSA_algorithm = new JComboBox(DSA_bit_options);
	private JComboBox ElGamal_algorithm = new JComboBox(ElGamal_bit_options);

	/**
	 * Izbor kljuceva za brisanje
	 */
	private static JComboBox deletePublicKeyOptions = new JComboBox();
	private static JComboBox deletePrivateKeyOptions = new JComboBox();

	/**
	 * Polje za unos lozinke prilikom brisanja privatnog kljuca
	 */
	private JPasswordField deletePasswordField = new JPasswordField();

	/**
	 * Izbor kljuceva za izvoz
	 */
	private static JComboBox exportPublicKeyOptions = new JComboBox();
	private static JComboBox exportPrivateKeyOptions = new JComboBox();

	/**
	 * Radio button za uvoz javnog ili privatnog kljuca
	 */
	private JRadioButton importPublicKeyRadioButton = new JRadioButton(publicKeyRadioButtonText);
	private JRadioButton importPrivateKeyRadioButton = new JRadioButton(privateKeyRadioButtonText);

	/**
	 * Azuriranje svake liste kljuceva koja se ispisuje
	 */
	public static void refreshKeyLists() {
		List<PGPPublicKeyRing> publicKeys = KeyCollections.get_public_keys();
		List<PGPSecretKeyRing> secretKeys = KeyCollections.get_secret_keys();

		DefaultComboBoxModel<String> model = new DefaultComboBoxModel();
		DefaultComboBoxModel<String> modell = new DefaultComboBoxModel();

		for (Iterator iterator = publicKeys.iterator(); iterator.hasNext();) {

			PGPPublicKeyRing pgpPublicKeyRing = (PGPPublicKeyRing) iterator.next();
			model.addElement((String) pgpPublicKeyRing.getPublicKey().getUserIDs().next());
			modell.addElement((String) pgpPublicKeyRing.getPublicKey().getUserIDs().next());
		}

		DefaultComboBoxModel<String> model2 = new DefaultComboBoxModel();
		DefaultComboBoxModel<String> modell2 = new DefaultComboBoxModel();

		for (Iterator iterator = secretKeys.iterator(); iterator.hasNext();) {

			PGPSecretKeyRing pgpSecretKeyRing = (PGPSecretKeyRing) iterator.next();
			model2.addElement((String) pgpSecretKeyRing.getPublicKey().getUserIDs().next());
			modell2.addElement((String) pgpSecretKeyRing.getPublicKey().getUserIDs().next());

		}

		deletePublicKeyOptions.setModel(model);
		exportPublicKeyOptions.setModel(modell);
		deletePrivateKeyOptions.setModel(model2);
		exportPrivateKeyOptions.setModel(modell2);
	}

	/**
	 * GUI za tab sa operacijama nad kljucevima
	 */
	public KeyOperations() {
		super();
		this.setLayout(new GridLayout(2, 2, 50, 50));

		JPanel generateKeysPanel = new JPanel();
		JPanel deleteKeysPanel = new JPanel();
		JPanel importPanel = new JPanel();
		JPanel exportPanel = new JPanel();

		// GUI za generisanje novog para kljuceva
		generateKeysPanel.setLayout(new GridLayout(7, 2, 10, 10));
		JLabel generateKeysPanelTitle = new JLabel(generateKeysPanelTitleText);
		JLabel nameLabel = new JLabel(nameLabelText);

		JLabel emailLabel = new JLabel(emailLabelText);

		JLabel DSA_optionsLabel = new JLabel(DSA_optionsLabelText);

		JLabel ElGamal_optionsLabel = new JLabel(ElGamal_optionsLabelText);

		JLabel passwordLabel = new JLabel(passwordLabelText);

		JButton generateKeysButton = new JButton(generateKeysButtonLabel);
		generateKeysButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				String name = nameTextField.getText();
				System.out.println(name);
				String email = emailTextField.getText();
				System.out.println(email);
				String DSA_SelectedItem = String.valueOf(DSA_algorithm.getSelectedItem());
				int DSA_bits = Integer.parseInt(DSA_SelectedItem);
				System.out.println(DSA_bits);
				String ElGamal_SelectedItem = String.valueOf(ElGamal_algorithm.getSelectedItem());
				int ElGamal_bits = Integer.parseInt(ElGamal_SelectedItem);
				System.out.println(ElGamal_bits);
				String password = new String(passwordField.getPassword());
				System.out.println(password);

				if (!name.isEmpty() && !email.isEmpty() && !password.isEmpty()) {
					String identity = name + "_" + email;

					try {
						KeyCollections.generate_key_pair(DSA_bits, ElGamal_bits, identity, password.toCharArray());

						KeyRing.refreshTextAreas();
						refreshKeyLists();
						MessageOperations.refreshKeyLists();
						JOptionPane.showMessageDialog(null, "Kljuc je generisan za korisnika " + name);
						nameTextField.setText("");
						emailTextField.setText("");
						passwordField.setText("");
					} catch (Exception e1) {
						JOptionPane.showMessageDialog(null,
								"Kljuc nije generisan za korisnika " + name + ". Pokusajte ponovo!");

					}
				} else {
					JOptionPane.showMessageDialog(null, "Unesite sve podatke! ");
				}
			}
		});
		generateKeysPanel.add(generateKeysPanelTitle);
		generateKeysPanel.add(new JLabel());
		generateKeysPanel.add(nameLabel);
		generateKeysPanel.add(nameTextField);
		generateKeysPanel.add(emailLabel);
		generateKeysPanel.add(emailTextField);
		generateKeysPanel.add(DSA_optionsLabel);
		generateKeysPanel.add(DSA_algorithm);
		generateKeysPanel.add(ElGamal_optionsLabel);
		generateKeysPanel.add(ElGamal_algorithm);
		generateKeysPanel.add(passwordLabel);
		generateKeysPanel.add(passwordField);
		generateKeysPanel.add(new JLabel());
		generateKeysPanel.add(generateKeysButton);

		// GUI za brisanje kljuceva
		deleteKeysPanel.setLayout(new GridLayout(7, 2, 10, 10));

		deleteKeysPanel.add(new JLabel(deletePublicKeyLabel));
		deleteKeysPanel.add(new JLabel());
		deleteKeysPanel.add(deletePublicKeyOptions);
		JButton deletePublicKeyButton = new JButton(deletePublicKeyButtonLabel);
		deletePublicKeyButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				String selectedPublicKey = String.valueOf(deletePublicKeyOptions.getSelectedItem());
				System.out.println(selectedPublicKey);

				List<PGPPublicKeyRing> publicKeys = KeyCollections.get_public_keys();
				Iterator<PGPPublicKeyRing> iter = publicKeys.iterator();
				PGPPublicKeyRing ring = iter.next();
				String user_id = (String) ring.getPublicKey().getUserIDs().next();
				while (iter.hasNext() && !user_id.equals(selectedPublicKey)) {
					ring = iter.next();
					user_id = (String) ring.getPublicKey().getUserIDs().next();
				}
				try {
					KeyCollections.delete_public_key(ring);
			
					KeyRing.refreshTextAreas();
					KeyOperations.refreshKeyLists();
					MessageOperations.refreshKeyLists();
					JOptionPane.showMessageDialog(null, "Kljuc je izbrisan! ");

				} catch (Exception e1) {
					e1.printStackTrace();
					JOptionPane.showMessageDialog(null, "Kljuc nije izbrisan! ");

				}

			}
		});
		deleteKeysPanel.add(deletePublicKeyButton);
		deleteKeysPanel.add(new JLabel());
		deleteKeysPanel.add(new JLabel());

		deleteKeysPanel.add(new JSeparator());
		deleteKeysPanel.add(new JSeparator());

		deleteKeysPanel.add(new JLabel(deletePrivateKeyLabel));
		deleteKeysPanel.add(deletePrivateKeyOptions);

		deleteKeysPanel.add(new JLabel(passwordLabelText));
		deleteKeysPanel.add(deletePasswordField);
		deleteKeysPanel.add(new JLabel());

		JButton deletePrivateKeyButton = new JButton(deletePrivateKeyButtonLabel);
		deletePrivateKeyButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				String enteredPassword = new String(deletePasswordField.getPassword());

				if (enteredPassword.isEmpty()) {
					JOptionPane.showMessageDialog(null, "Unesite lozinku! ");
				} else {
					String selectedPrivateKey = String.valueOf(deletePrivateKeyOptions.getSelectedItem());
					System.out.println(selectedPrivateKey);
					System.out.println(enteredPassword);

					List<PGPSecretKeyRing> secretKeys = KeyCollections.get_secret_keys();
					Iterator<PGPSecretKeyRing> iter2 = secretKeys.iterator();
					PGPSecretKeyRing ring = iter2.next();
					String user_id = (String) ring.getSecretKey().getUserIDs().next();
					while (iter2.hasNext() && !user_id.equals(selectedPrivateKey)) {
						ring = iter2.next();
						user_id = (String) ring.getPublicKey().getUserIDs().next();
					}

					PGPPrivateKey privateKey = null;
				
					try {
						privateKey = ring.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
								.setProvider("BC").build(enteredPassword.toCharArray()));
					} catch (PGPException e1) {
						JOptionPane.showMessageDialog(null, "Pogresan passphrase! ");
						e1.printStackTrace();
					}
					if (privateKey != null) {
						try {
							KeyCollections.delete_private_key(ring);
						} catch (Exception e1) {
							e1.printStackTrace();
							JOptionPane.showMessageDialog(null, "Kljuc nije izbrisan! ");
							deletePasswordField.setText("");
						}
					
						KeyRing.refreshTextAreas();
						KeyOperations.refreshKeyLists();
						MessageOperations.refreshKeyLists();

						JOptionPane.showMessageDialog(null, "Kljuc je izbrisan! ");
						deletePasswordField.setText("");
					}
				}
			}
		});
		deleteKeysPanel.add(deletePrivateKeyButton);

		// GUI za uvoz kljuca
		importPanel.setLayout(new GridLayout(7, 2, 10, 10));
		importPanel.add(new JSeparator());
		importPanel.add(new JSeparator());

		importPanel.add(new JLabel(importKeysPanelTitleText));
		importPanel.add(new JLabel());

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(importPrivateKeyRadioButton);
		buttonGroup.add(importPublicKeyRadioButton);
		importPanel.add(importPrivateKeyRadioButton);
		importPanel.add(importPublicKeyRadioButton);

		JButton importKeyButton = new JButton(importButtonText);
		importKeyButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (!importPrivateKeyRadioButton.isSelected() && !importPublicKeyRadioButton.isSelected()) {
					JOptionPane.showMessageDialog(null, "Oznacite da li se radi o javnom ili privatnom kljucu! ");
				} else {
					JFileChooser fileChooser = new JFileChooser();

					int returnVal = fileChooser.showOpenDialog(null);

					if (returnVal == JFileChooser.APPROVE_OPTION) {

						if (importPrivateKeyRadioButton.isSelected()) {

							System.out.println("uvozi se privatni kljuc");
							File importFile = fileChooser.getSelectedFile();
							System.out.println(importFile.getName() + " " + importFile.getAbsolutePath());
							try {
								KeyCollections.import_secret_key(new FileInputStream(importFile));
								JOptionPane.showMessageDialog(null, "Kljuc je uvezen! ");
							} catch (FileNotFoundException e1) {
								e1.printStackTrace();

								JOptionPane.showMessageDialog(null, "Kljuc nije uvezen! ");
							} catch (IOException e1) {
								JOptionPane.showMessageDialog(null, "Kljuc nije uvezen! ");
								e1.printStackTrace();
							} catch (PGPException e1) {
								JOptionPane.showMessageDialog(null, "Kljuc nije uvezen! ");
								e1.printStackTrace();
							}

						} else if (importPublicKeyRadioButton.isSelected()) {
							System.out.println("uvozi se javni kljuc");
							File importFile = fileChooser.getSelectedFile();
							System.out.println(importFile.getName() + " " + importFile.getAbsolutePath());
							try {
								KeyCollections.import_public_key(new FileInputStream(importFile));

								JOptionPane.showMessageDialog(null, "Kljuc je uvezen! ");
							} catch (FileNotFoundException e1) {
								JOptionPane.showMessageDialog(null, "Kljuc nije uvezen! ");
								e1.printStackTrace();
							} catch (IOException e1) {
								JOptionPane.showMessageDialog(null, "Kljuc nije uvezen! ");
								e1.printStackTrace();
							} catch (PGPException e1) {
								JOptionPane.showMessageDialog(null, "Kljuc nije uvezen! ");
								e1.printStackTrace();
							}

						}
						KeyRing.refreshTextAreas();
						KeyOperations.refreshKeyLists();
						MessageOperations.refreshKeyLists();

					} else {
						return;
					}
				}
			}
		});
		importPanel.add(new JLabel());

		importPanel.add(importKeyButton);

		// GUI za izvoz kljuca
		exportPanel.setLayout(new GridLayout(7, 2, 10, 10));
		exportPanel.add(new JSeparator());
		exportPanel.add(new JSeparator());
		exportPanel.add(new JLabel(exportPublicKeysPanelTitleText));
		exportPanel.add(new JLabel());
		exportPanel.add(exportPublicKeyOptions);
		JButton exportPublicKeyButton = new JButton(exportPublicKeyButtonText);
		exportPublicKeyButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				String selectedPublicKey = String.valueOf(exportPublicKeyOptions.getSelectedItem());
				System.out.println(selectedPublicKey);

				List<PGPPublicKeyRing> publicKeys = KeyCollections.get_public_keys();
				Iterator<PGPPublicKeyRing> iter = publicKeys.iterator();
				PGPPublicKeyRing ring = iter.next();
				String user_id = (String) ring.getPublicKey().getUserIDs().next();
				while (iter.hasNext() && !user_id.equals(selectedPublicKey)) {
					ring = iter.next();
					user_id = (String) ring.getPublicKey().getUserIDs().next();
				}

				try {
					KeyCollections.export_public_key(user_id, ring);

					JOptionPane.showMessageDialog(null, "Kljuc je izvezen! ");
				} catch (IOException e1) {
					e1.printStackTrace();

					JOptionPane.showMessageDialog(null, "Kljuc nije izvezen! ");
				}

			}
		});
		exportPanel.add(exportPublicKeyButton);
		exportPanel.add(new JLabel());
		exportPanel.add(new JLabel());

		exportPanel.add(new JLabel(exportPrivateKeysPanelTitleText));
		exportPanel.add(new JLabel());
		exportPanel.add(exportPrivateKeyOptions);
		JButton exportPrivateKeyButton = new JButton(exportPrivateKeyButtonText);
		exportPrivateKeyButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				String selectedPrivateKey = String.valueOf(exportPrivateKeyOptions.getSelectedItem());
				System.out.println(selectedPrivateKey);

				List<PGPSecretKeyRing> secretKeys = KeyCollections.get_secret_keys();
				Iterator<PGPSecretKeyRing> iter2 = secretKeys.iterator();
				PGPSecretKeyRing ring = iter2.next();
				String user_id = (String) ring.getSecretKey().getUserIDs().next();
				while (iter2.hasNext() && !user_id.equals(selectedPrivateKey)) {
					ring = iter2.next();
					user_id = (String) ring.getPublicKey().getUserIDs().next();
				}

				try {
					KeyCollections.export_secret_key(user_id, ring);

					JOptionPane.showMessageDialog(null, "Kljuc je izvezen! ");
				} catch (IOException e1) {
					e1.printStackTrace();

					JOptionPane.showMessageDialog(null, "Kljuc nije izvezen! ");
				}

			}
		});
		exportPanel.add(exportPrivateKeyButton);

		//
		this.add(generateKeysPanel);
		this.add(deleteKeysPanel);
		this.add(importPanel);
		this.add(exportPanel);
	}

}
