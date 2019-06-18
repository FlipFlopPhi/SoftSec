/**
 * 
 */
package terminal.exception;

/**
 * @author pspaendonck
 *
 */
public class IncorrectSequenceNumberException extends Exception {

	public IncorrectSequenceNumberException(int encounteredSeqNr, int expectedSeqNr) {
		super("Incorrect Sequence number encountered: "+encounteredSeqNr+" while "+expectedSeqNr+" was expected.");
	}
}
