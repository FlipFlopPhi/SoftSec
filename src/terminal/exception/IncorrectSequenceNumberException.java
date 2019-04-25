/**
 * 
 */
package terminal.exception;

/**
 * @author pspaendonck
 *
 */
public class IncorrectSequenceNumberException extends Exception {

	public IncorrectSequenceNumberException() {
		super("SequenceNumberJammed ABORT IMMEDIATELY! CALL THE SECRET SERVICE!"
					+ "EXECUTE ORDER 420!");
	}
}
