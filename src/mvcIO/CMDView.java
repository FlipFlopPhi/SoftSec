package mvcIO;

/**
 * MVC pattern view using the command prompt.
 * @author Flip van Spaendonck, Thijs Werrij, Toon Lenaerts
 */
public class CMDView implements View {

	@Override
	public void println(String output) {
		System.out.println(output);
	}

}
