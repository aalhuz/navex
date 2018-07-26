/*
 * @author : NoTamper and WAPTIC 
 * 
 * */



package navex.formula;

import java.util.ArrayList;
import java.util.SortedSet;
import java.util.TreeSet;




public class InferType {

	// TODO: find better ways to cover all cases
	// kludge algo :
	// 1. if value is "" : default inference of STRING.
	// 2. try to parse hex/oct/dec numbers
	// - if a number format exception is thrown it is likely a string
	// - otherwise a string
	// 3. If string, test for the presence of char, digit, @, ., to select
	// appropriate type
	// sValue is the value of a control
	// return value is a regular expression capturing type of the
	// value in PERL regular expressions e.g.,
	// STRING: /[a-zA-Z]*/
	// STRING email context: /[a-zA-Z\@\.]*/
	// STRING alphanumeric : /[a-zA-Z0-9]*/
	// Number: /[0-9]*/
	public static final String TNUM_DEC = "/[\\-0-9]*/";
	public final static String TNUM_HEX = "/[\\-xX0-9a-f]*/";
	public final static String TNUM_OCT = "/[\\-0-7]*/";
	public static final int TEXT_TYPE = 1;
	
	public final static String TSTR_ASCII_SPACE = "/[a-zA-Z\\\\n\\\\r\\\\t ]*/";
	public final static String TSTR_ASCII = "/[a-zA-Z]*/";
	public final static String TSTR_TYPE= TSTR_ASCII;

	public static String inferType(String sValue) {
		if (sValue == null || sValue == "" || sValue == " " || sValue.trim() == "")
			return TSTR_TYPE;

		// ideally we should check the most constrained numeric system first :
		// not a perfect sol
		// but then value=00 is causing days of a date to have octal number
		// system.
		// reversed it : with more inputs perhaps we can catch problems
		try {
			Integer.parseInt(sValue, 16);
			return TNUM_HEX;
		} catch (Exception e) {
		}
		try {
			Integer.parseInt(sValue, 10);
			return TNUM_DEC;
		} catch (Exception e) {
		}
		try {
			Integer.parseInt(sValue, 8);
			return TNUM_OCT;
		} catch (Exception e) {
		}

		String sReg = "";
		// if(sValue.indexOf("@") != -1) sReg += "\\@";
		// if(sValue.indexOf(".") != -1) sReg += "\\.";
		// if(sValue.matches("0-9")) sReg += "0-9";
		SortedSet<Character> ss = new TreeSet<Character>();
		for (char c : sValue.toCharArray()) {
			// if(!Character.isLetter(c))
			ss.add(c);
		}

		String csUniq = "";
		for (Character ch : ss)
			csUniq += ch.charValue();

		// now escape the PERL special chars
		csUniq = perlEscape(csUniq);
		if (csUniq == ""){
			//csUniq = "a-zA-Z\\\\t\\\\r\\\\n ";
			sValue = TSTR_TYPE;
		} else {

			sValue = "/[" + sReg + csUniq + "]*/";
		}
		
		return sValue;
	}

	public static String inferType(ArrayList<String> alValues) {
		String sValue = "";
		if (alValues == null || alValues.size() == 0)
			return TSTR_TYPE;
			//return "/[a-zA-Z\\\\t\\\\r\\\\n ]*/";

		String csUniq = "";
		if(alValues.size() == 1){
			SortedSet<Character> ss = new TreeSet<Character>();
			for (String sv : alValues) {
				if (sv == null)
					continue;
				for (char c : sv.toCharArray()) {
					// if(!Character.isLetter(c))
					ss.add(c);
				}
			}
	
			for (Character ch : ss)
				csUniq += ch.charValue();

			// now escape the PERL special chars
			csUniq = perlEscape(csUniq);
			if (csUniq == ""){
				//csUniq = "a-zA-Z\\\\n\\\\r\\\\t ";
				sValue = TSTR_TYPE;
			} else {
				sValue = "/[" + csUniq + "]*/";
			}
		} else { 
			int iLast = alValues.size(); 
			int iC = 1; 
			for(String sv : alValues){
				String s = sv.trim(); 
				if(sv.equals("")){
					// solver workaround: 
					// it doesnt like empty spaces in 
					// IN constraints 
					// e.g., IN x "/(1|2|)/"
					System.out.println("Ignoring empty option value \n");
					++iC; continue; 
				}

				csUniq +=  perlEscape(sv); 
				
				if(iC < iLast){
					csUniq += "|";
				}
				iC++;
			}
			
			sValue = "/(" + csUniq + ")/"; 
		}
		
		return sValue;
	}

	public static String perlEscape(String csUniq) {
		String[] sPerl = {"\\\\", "@", "\\.", "\\^", "\\$", ":", "\\/", "\\=", "\\?",
			
		};

		for (String se : sPerl)
			csUniq = csUniq.replaceAll(se, "\\\\\\\\" + se);

		return csUniq;
	}

	public static String inferType(String value, int textType) {
		// TODO Auto-generated method stub
		switch(textType){
			
		case InferType.TEXT_TYPE:
			//return "/[a-zA-Z\\\\n\\\\t\\\\r ]*/";
			return TSTR_TYPE;

		default: 
			return inferType(value);
		}
	}

	public static String findCharsUsed(ArrayList<String> domain){

		String csUniq = ""; 
		String sValue = ""; 

		SortedSet<Character> ss = new TreeSet<Character>();
		for (String sv : domain) {
			if (sv == null || sv.trim().equals(""))
				continue;
			for (char c : sv.toCharArray()) {
				ss.add(c);
			}
		}
	
		for (Character ch : ss)
			csUniq += ch.charValue();

		// now escape the PERL special chars
		csUniq = perlEscape(csUniq);
		if (csUniq == ""){
			//csUniq = "a-zA-Z\\\\r\\\\t\\\\n ";
			sValue = TSTR_TYPE;
		} else {
			sValue = "/[" + csUniq + "]*/";
		}

		return sValue; 
	}

	public static String inferTypeOr(ArrayList<String> alValues, String var){
		String sValue = "";
	
		if (alValues == null || alValues.size() == 0){
			//return "/[a-zA-Z\\\\n\\\\r\\\\t ]*/";
			return TSTR_TYPE;
		}

		String csUniq = "";
		if(alValues.size() == 1){
			String sv = alValues.get(0); 
			if(sv != null && !sv.trim().equals("")){

			}
		} else { 
			
			int orConsts = 0; 
			for(String sv : alValues){
				
				if(sv != null && !sv.trim().equals("")){
					orConsts ++; 

				}
			}
			
			if(orConsts > 1){
				sValue = "\t (OR " + sValue + ")\n";
			}
		}
		
		return sValue;
	}

}
