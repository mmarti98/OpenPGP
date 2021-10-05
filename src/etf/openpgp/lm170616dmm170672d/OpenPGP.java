package etf.openpgp.lm170616dmm170672d;

import java.io.IOException;

import javax.swing.*;

import org.bouncycastle.openpgp.PGPException;

/**
 * Klasa sa funkcijom glavnog programa main koja pokrece aplikaciju
 * 
 */
public class OpenPGP {

	/**
	 * Definisani naslovi tabova
	 */
	private static final String keyOperationsTabTitle = "Operacije sa kljucevima";
	private static final String keyRingViewTabTitle = "Prsten javnih i privatnih kljuceva";
	private static final String messageTabTitle = "Slanje i prijem poruke";
	private static final String applicationName = "OpenPGP";
	/**
	 * Tabovi za funkcionalnosti
	 */
	public static KeyOperations keyOperationsTab = new KeyOperations();
	public static KeyRing keyRingViewTab = new KeyRing();
	public static MessageOperations messageTab = new MessageOperations();

	/**
	 * Funkcija koja pokrece aplikaciju
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		JFrame frame = new JFrame(applicationName);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setSize(1500, 700);
		frame.setLocationRelativeTo(null);

		JTabbedPane tabbedPane = new JTabbedPane();
		tabbedPane.addTab(keyOperationsTabTitle, keyOperationsTab);
		tabbedPane.addTab(keyRingViewTabTitle, keyRingViewTab);
		tabbedPane.addTab(messageTabTitle, messageTab);

		frame.add(tabbedPane);
		frame.setVisible(true);

		try {
			KeyCollections.ucitaj();
			KeyRing.refreshTextAreas();
			KeyOperations.refreshKeyLists();
			MessageOperations.refreshKeyLists();
		} catch (IOException | PGPException e) {
			e.printStackTrace();
		}
	}

}
