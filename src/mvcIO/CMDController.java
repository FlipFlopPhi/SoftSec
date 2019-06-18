/**
 * 
 */
package mvcIO;

import java.util.Scanner;

/**
 * MVC pattern controller, using the command prompt
 * @author Flip van Spaendonck, Thijs Werrij, Toon Lenaerts
 */
public class CMDController implements Controller {

	private Scanner scanner;
	
	public CMDController() {
		scanner = new Scanner(System.in);
	}
	@Override
	public int nextInt() {
		return scanner.nextInt();
	}

}
