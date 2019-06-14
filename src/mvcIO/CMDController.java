/**
 * 
 */
package mvcIO;

import java.util.Scanner;

/**
 * @author Vizu
 *
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
