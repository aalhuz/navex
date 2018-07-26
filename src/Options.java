/**
 * @author Abeer Alhuzali
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */
package navex;

import java.util.ArrayList;


public class Options {
      static ArrayList<String> loginFile = new ArrayList<String>();
      public static ArrayList<String> getLoginFile() {
		return loginFile;
	}
	public static void setLoginFile(ArrayList<String> loginF) {
		loginFile = loginF;
		
	}
	ArrayList<String> loginpass = new ArrayList<String>();
      ArrayList<String> loginuser = new ArrayList<String>();
      
      
      
}
