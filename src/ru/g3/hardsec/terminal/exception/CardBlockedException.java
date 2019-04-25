/**
 * 
 */
package ru.g3.hardsec.terminal.exception;

/**
 * @author pspaendonck
 *
 */
public class CardBlockedException extends Exception {

	public CardBlockedException() {
		super("Card was blocked because the PIN was entered incorrectly too many times.");
	}
}
