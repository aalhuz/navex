/**
 * @author Abeer Alhuzali
 *This class analyzes TAC formulas and transform them to Z3 specifications
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */

package navex.solver;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;


import navex.formula.Formula;

public class Solver {

	private static boolean negate = false;
	public static void setNegate(boolean negate) {
		Solver.negate = negate;
	}


	public static int c=0;
	String z3Formula; // this holds the specifications as one string
	HashSet<Formula> z3FormulaList;

	String type ; // formula type is either FORM or TRACE
	private String sinkType;

	public String getZ3Formula() {
		return z3Formula;
	}


	public void setZ3Formula(String z3Formula) {
		this.z3Formula = z3Formula;
	}


	public Solver() {
		this.count=0;
		this.z3FormulaList = new HashSet<Formula>();
		if(negate)
			this.assertion = new HashSet<String>();


	}

	public HashSet<String> getAssertion() {
		return assertion;
	}


	public Solver(HashSet<Formula> z3Formulas){
		this.z3FormulaList = z3Formulas;
		this.count=0;
		if(negate)
			this.assertion = new HashSet<String>();
	}


	public Solver(HashSet<Formula> formula, String sinkType) {
		this.z3FormulaList = formula;
		this.sinkType = sinkType;
		this.count=0;
		if(negate)
			this.assertion = new HashSet<String>();
	}


	int count=0;
	private HashSet<String> assertion;
	
	public String prepareSolver() {

		String Spec ="";

		HashSet<String> DeclaredVars = genDeclarations();

		for(String vars: DeclaredVars){
			Spec+=vars;
		}


		String temp  = FormulaTranslation(this.z3FormulaList);

		temp+= assignAttackStrings(this.z3FormulaList, this.sinkType);

		for  (int varc=1; varc <= count ; varc++){
			Spec+="(declare-variable p1b"+varc +" Bool)\n";
             }
		Spec += temp;

		if (negate)
		{  if (this.getAssertion() != null){
			if (this.getAssertion().size() == 1 )
				Spec += this.getAssertion();
			else if (this.getAssertion().size() > 1 ){
				Spec += "\n(assert (and \n";
				for(String as : this.getAssertion()){
					as = as.replace("(", "").replaceAll(")", "").
							replace("assert", "").replace("\n","").trim();
					Spec +=" "+as+" ";
				}
				Spec += " ))\n";
			}
		}
		}

		Spec+="\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";

		Spec+="(check-sat)\n(get-model)"
			+ "\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";

		return Spec;

	}


	/**
	 * @return the set of variable declarations
	 */
	private HashSet<String> genDeclarations (){

		HashSet<String> ret=new HashSet<String>();

		for (Formula f1 : this.z3FormulaList){
			if(f1.getSource() == "FORM"){
				if ( f1.getOperator().equalsIgnoreCase("=") || 
						f1.getOperator().equalsIgnoreCase("maxlen")	
						|| f1.getOperator().equalsIgnoreCase("minlen")	){
					ret.addAll(handleAssignFormula(f1));
				}
				else if (f1.getOperator().equalsIgnoreCase("or")){
					ret.addAll(handleOptionFormula(f1));
				}

			}
			else if (f1.getSource() == "TRACE" || f1.getSource() == "STATIC"){
				ret.addAll(this.getDeclarationTrace(f1));
			}
         }

		return ret;		
	}



	private HashSet<String> getDeclarationTrace(Formula f1) {
             HashSet<String> ret=new HashSet<String>();


		String left="XXX";
		if (f1.getLeftOp().size()>=1 ){
			left=f1.getLeftOp().get(0);
			if( left.length()==1 && (Character.isLetter(left.charAt(0)))){

			}
			if (left.contains("[") || left.contains("]") || left.contains("{") || left.contains("}") ){
				left=left.replace("[", "_").replace("]", "").replace("{", "").replace("}", "");
				left=left.trim();
			}
		}

		if (f1.getRightOp() != null && f1.getOperator().trim().startsWith("AST_DIM")){

			String right = f1.getRightOp().replace("[", "_").replace("]", "").trim();
			ret.add("(declare-variable "+ right +" String)\n");

		}
		
		if(f1.getOperator().equals("!")){
			if(f1.getLeftOp().size() == 1 && !f1.getLeftOp().get(0).isEmpty())
				ret.add("(declare-variable "+ left +" String)\n");	

		}
		switch(f1.getOperator()){

		case "is_int": case "is_integer":
			ret.add("(define-fun containsNumbers ((input String)) Bool\n"
					+ "(ite (Contains input \"0\") true\n"
					+ "(ite (Contains input \"1\") true\n"
					+ "(ite (Contains input \"2\") true\n"
					+ "(ite (Contains input \"3\") true\n"
					+ "(ite (Contains input \"4\") true\n"
					+ "(ite (Contains input \"5\") true\n"
					+ "(ite (Contains input \"6\") true\n"
					+ "(ite (Contains input \"7\") true\n"
					+ "(ite (Contains input \"8\") true\n"
					+ "(ite (Contains input \"9\") true false \n"
					+ ")))))))))))\n");

			ret.add("(define-fun containsLetters((input String)) Bool\n (ite (Contains input \"a\") true "
					+ "\n (ite (Contains input \"b\") true "
					+ "\n (ite (Contains input \"c\") true "
					+ "\n (ite (Contains input \"d\") true "
					+ "\n (ite (Contains input \"f\") true "
					+ "\n (ite (Contains input \"e\") true "
					+ "\n (ite (Contains input \"E\") true "
					+ "\n (ite (Contains input \"x\") true "
					+ "\n (ite (Contains input \"X\") true "
					+ "\n (ite (Contains input \"A\") true "
					+ "\n (ite (Contains input \"B\") true "
					+ "\n (ite (Contains input \"C\") true "
					+ "\n (ite (Contains input \"D\") true "
					+ "\n (ite (Contains input \"F\") true "
					+ "\n (ite (Contains input \"g\") true "
					+ "\n (ite (Contains input \"h\") true "
					+ "\n (ite (Contains input \"i\") true "
					+ "\n (ite (Contains input \"j\") true "
					+ "\n (ite (Contains input \"k\") true "
					+ "\n (ite (Contains input \"l\") true "
					+ "\n (ite (Contains input \"m\") true "
					+ "\n (ite (Contains input \"n\") true "
					+ "\n (ite (Contains input \"o\") true "
					+ "\n (ite (Contains input \"p\") true "
					+ "\n (ite (Contains input \"q\") true "
					+ "\n (ite (Contains input \"r\") true "
					+ "\n (ite (Contains input \"s\") true "
					+ "\n (ite (Contains input \"t\") true "
					+ "\n (ite (Contains input \"u\") true "
					+ "\n (ite (Contains input \"v\") true "
					+ "\n (ite (Contains input \"w\") true "
					+ "\n (ite (Contains input \"y\") true "
					+ "\n (ite (Contains input \"z\") true "
					+ "\n (ite (Contains input \"G\") true "
					+ "\n (ite (Contains input \"H\") true "
					+ "\n (ite (Contains input \"I\") true "
					+ "\n (ite (Contains input \"J\") true "
					+ "\n (ite (Contains input \"K\") true "
					+ "\n (ite (Contains input \"L\") true "
					+ "\n (ite (Contains input \"M\") true "
					+ "\n (ite (Contains input \"N\") true "
					+ "\n (ite (Contains input \"O\") true "
					+ "\n (ite (Contains input \"P\") true "
					+ "\n (ite (Contains input \"Q\") true "
					+ "\n (ite (Contains input \"R\") true "
					+ "\n (ite (Contains input \"S\") true "
					+ "\n (ite (Contains input \"T\") true "
					+ "\n (ite (Contains input \"U\") true "
					+ "\n (ite (Contains input \"V\") true "
					+ "\n (ite (Contains input \"W\") true "
					+ "\n (ite (Contains input \"Y\") true "
					+ "\n (ite (Contains input \"Z\") true false)))))))))))))))))))))))))))))))))))))))))))))))))))))\n");

			ret.add("(define-fun containsCharacters ((input String)) Bool "
					+ "(ite (Contains input \";\") true " 
					+ "(ite (Contains input \",\") true " 
					+ "(ite (Contains input \"/\") true " 
					+ "(ite (Contains input \".\") true " 
					+ "(ite (Contains input \"$\") true " 
					+ "(ite (Contains input \"%\") true " 
					+ "(ite (Contains input \"^\") true " 
					+ "(ite (Contains input \"?\") true " 
					+ "(ite (Contains input \"<\") true " 
					+ "(ite (Contains input \">\") true " 
					+ "(ite (Contains input \"\'\") true " 
					+ "(ite (Contains input \"=\") true " 
					+ "(ite (Contains input \"!\") true false ))))))))))))))\n");
			ret.addAll(declareTraceHelper(f1));
			break;

		case "is_numeric":
			ret.add("(define-fun ContainsDoubles ((input String)) Bool\n"
					+ "(ite (Contains input \"xx\") true\n"
					+ "(ite (Contains input \"XX\") true\n"
					+ "(ite (Contains input \"Xx\") true\n"
					+ "(ite (Contains input \"xX\") true\n"
					+ "(ite (Contains input \"bb\") true\n"
					+ "(ite (Contains input \"BB\") true\n"
					+ "(ite (Contains input \"bB\") true\n"
					+ "(ite (Contains input \"Bb\") true false)))))))))\n");

			ret.add("(define-fun containsHexLetters ((input String)) Bool\n"
					+ "(ite (Contains input \"a\") true \n"
					+ "(ite (Contains input \"b\") true \n"
					+ "(ite (Contains input \"c\") true \n"
					+ "(ite (Contains input \"d\") true \n"
					+ "(ite (Contains input \"f\") true \n"
					+ "(ite (Contains input \"A\") true \n"
					+ "(ite (Contains input \"B\") true \n"
					+ "(ite (Contains input \"C\") true \n"
					+ "(ite (Contains input \"D\") true \n"
					+ "(ite (Contains input \"F\") true false)))))))))))\n");

			ret.add("(define-fun BeyondBinary ((input String)) Bool"
					+ "(ite (Contains input \"a\") true\n"
					+ "(ite (Contains input \"c\") true \n"
					+ "(ite (Contains input \"d\") true \n"
					+ "(ite (Contains input \"f\") true \n"
					+ "(ite (Contains input \"A\") true \n"
					+ "(ite (Contains input \"C\") true \n"
					+ "(ite (Contains input \"D\") true \n"
					+ "(ite (Contains input \"F\") true false)))))))))\n");

			ret.add("(define-fun ContainsOnlyOctals ((input String)) Bool\n"
					+ "(ite (Contains input \"8\") false \n "
					+ "(ite (Contains input \"9\") false true)))\n");

			ret.add("(define-fun ContainsOnlyBinary ((input String)) Bool\n"
					+ "(ite (Contains input \"2\") true\n"
					+ "(ite (Contains input \"3\") true\n"
					+ "(ite (Contains input \"4\") true\n"
					+ "(ite (Contains input \"5\") true\n"
					+ "(ite (Contains input \"6\") true\n"
					+ "(ite (Contains input \"7\") true\n"
					+ "(ite (Contains input \"8\") true\n"
					+ "(ite (Contains input \"9\") true false \n"
					+ ")))))))))\n");

			ret.add("(define-fun containsLetters2((input String)) Bool\n (ite (Contains input \"a\") true "
					+ "\n (ite (Contains input \"b\") true "
					+ "\n (ite (Contains input \"c\") true "
					+ "\n (ite (Contains input \"d\") true "
					+ "\n (ite (Contains input \"f\") true "
					+ "\n (ite (Contains input \"e\") true "
					+ "\n (ite (Contains input \"E\") true "
					+ "\n (ite (Contains input \"x\") true "
					+ "\n (ite (Contains input \"X\") true "
					+ "\n (ite (Contains input \"A\") true "
					+ "\n (ite (Contains input \"B\") true "
					+ "\n (ite (Contains input \"C\") true "
					+ "\n (ite (Contains input \"D\") true "
					+ "\n (ite (Contains input \"F\") true "
					+ "\n (ite (Contains input \"g\") true "
					+ "\n (ite (Contains input \"h\") true "
					+ "\n (ite (Contains input \"i\") true "
					+ "\n (ite (Contains input \"j\") true "
					+ "\n (ite (Contains input \"k\") true "
					+ "\n (ite (Contains input \"l\") true "
					+ "\n (ite (Contains input \"m\") true "
					+ "\n (ite (Contains input \"n\") true "
					+ "\n (ite (Contains input \"o\") true "
					+ "\n (ite (Contains input \"p\") true "
					+ "\n (ite (Contains input \"q\") true "
					+ "\n (ite (Contains input \"r\") true "
					+ "\n (ite (Contains input \"s\") true "
					+ "\n (ite (Contains input \"t\") true "
					+ "\n (ite (Contains input \"u\") true "
					+ "\n (ite (Contains input \"v\") true "
					+ "\n (ite (Contains input \"w\") true "
					+ "\n (ite (Contains input \"y\") true "
					+ "\n (ite (Contains input \"z\") true "
					+ "\n (ite (Contains input \"G\") true "
					+ "\n (ite (Contains input \"H\") true "
					+ "\n (ite (Contains input \"I\") true "
					+ "\n (ite (Contains input \"J\") true "
					+ "\n (ite (Contains input \"K\") true "
					+ "\n (ite (Contains input \"L\") true "
					+ "\n (ite (Contains input \"M\") true "
					+ "\n (ite (Contains input \"N\") true "
					+ "\n (ite (Contains input \"O\") true "
					+ "\n (ite (Contains input \"P\") true "
					+ "\n (ite (Contains input \"Q\") true "
					+ "\n (ite (Contains input \"R\") true "
					+ "\n (ite (Contains input \"S\") true "
					+ "\n (ite (Contains input \"T\") true "
					+ "\n (ite (Contains input \"U\") true "
					+ "\n (ite (Contains input \"V\") true "
					+ "\n (ite (Contains input \"W\") true "
					+ "\n (ite (Contains input \"Y\") true "
					+ "\n (ite (Contains input \"Z\") true false)))))))))))))))))))))))))))))))))))))))))))))))))))))\n");

			ret.add("(define-fun containsCharacters2 ((input String)) Bool "
					+ "(ite (Contains input \";\") true " 
					+ "(ite (Contains input \",\") true " 
					+ "(ite (Contains input \"/\") true " 
					+ "(ite (Contains input \".\") true " 
					+ "(ite (Contains input \"$\") true " 
					+ "(ite (Contains input \"%\") true " 
					+ "(ite (Contains input \"^\") true " 
					+ "(ite (Contains input \"?\") true " 
					+ "(ite (Contains input \"<\") true " 
					+ "(ite (Contains input \">\") true " 
					+ "(ite (Contains input \"\'\") true " 
					+ "(ite (Contains input \"=\") true " 
					+ "(ite (Contains input \"!\") true false ))))))))))))))\n");

			ret.addAll(declareTraceHelper(f1));
			break;		 




		case "substr":
			ret.add("(define-fun substr ((str String) (start Int) (len Int)) String\n"
					+ "\t (Substring str start len) )\n");

			if (f1.getSource() == "STATIC" ){
				if(f1.getLeftOp().size()>=2){
					String str1=(f1.getLeftOp().get(0));
					if(!(str1.startsWith("$"))) {
					}
					else {
						String str=filterString(str1);
						ret.add("(declare-variable "+(str) +" String)\n");
					}

					if(f1.getRightOp() != null){
						String strstr=filterString(f1.getRightOp());
						ret.add("(declare-variable "+strstr +" String)\n");
					}
					String var = f1.getLeftOp().get(1);
					if(var.startsWith("$")) {
						String str=filterString(f1.getLeftOp().get(1));
						ret.add("(declare-const "+str +" Int)\n");
					}

					if(f1.getLeftOp().size()==3){
						if(f1.getLeftOp().get(2).startsWith("$")) {
							String str=filterString(f1.getLeftOp().get(2));
							ret.add("(declare-const "+filterString(str) +" Int)\n");
						}

					}	
				}
			}
			else {
				if(f1.getLeftOp().size()>=2){
					String str1=filterString(f1.getLeftOp().get(0));
					ret.add("(declare-variable "+str1 +" String)\n");

					if(f1.getRightOp() != null){
						String strstr=filterString(f1.getRightOp());
						ret.add("(declare-variable "+strstr +" String)\n");
					}
					String var = f1.getLeftOp().get(1);
					if(!(var.matches("(-*)[0-9]+"))) {
						String str=filterString(f1.getLeftOp().get(1));
						ret.add("(declare-const "+str +" Int)\n");

					}
					if(f1.getLeftOp().size()==3){
						if(!(f1.getLeftOp().get(2).matches("(-*)[0-9]+"))) {
							String str=filterString(f1.getLeftOp().get(2));
							ret.add("(declare-const "+str +" Int)\n");
						}

					}	
				}

			}	

			break;

		case "strip_tags":


			ret.add("; this function replaces the closing tages only from the $input string\n");
			ret.add("(define-fun strip_tags_main ((str String)) String\n"
					+ "\t(Replace (Replace (Replace (Replace (Replace (Replace str \"</div>\" \"\" ) \"</script>\" \"\") \"</p>\" \"\") \"</span>\" \"\") \"</img>\" \"\") \"</a>\" \"\") )\n");
			ret.add("; we need this function to replace the opening tages e.g <....>\n");
			ret.add("(define-fun strip_tags_next ((a String)) String \n"
					+ "\t(Replace a (Substring a (Indexof a \"<\") (+ (- (Indexof a \">\") (Indexof a \"<\")) 1)) \"\" ))\n");

			ret.addAll(declareTraceHelper(f1));
			break;

		case "intval":

			ret.addAll(declareTraceHelper(f1));
			break;

		case "mktime":


			for(int i=0; i<f1.getLeftOp().size() && f1.getLeftOp().size() >= 1 ; i++){
				if(checkNotConstString(f1.getLeftOp().get(i))){	 
					ret.add("(declare-variable "+filterString(f1.getLeftOp().get(i)) +" String)\n");

				}	
			}
			if(f1.getRightOp() != null){
				ret.add("(declare-variable "+filterString(f1.getRightOp()) +" String)\n");
			}

			break;


		case "strstr":

			if(f1.getLeftOp().size()>=2){
				ret.add("(declare-variable "+left +" String)\n");

				if(f1.getLeftOp().get(1)!= null ){

					//if the left.get1 is constant 
					String var=f1.getLeftOp().get(1);
					if(!(var.startsWith("'") || var.startsWith("\"")) && 
							!(var.endsWith("'") || var.endsWith("\"")) &&
							!(var.startsWith("$") )){
					}
					else 
					{
						String str=filterString(f1.getLeftOp().get(1));
						ret.add("(declare-variable "+str +" String)\n");
					}
				}
				if(f1.getRightOp() != null){
					ret.add("(declare-variable "+filterString(f1.getRightOp()) +" String)\n");
				}

				if(f1.getLeftOp().size()==3){
					//if the left.get1 is constant 
					String var=f1.getLeftOp().get(2);
					if(!(var.startsWith("'") || var.startsWith("\"")) && 
							!(var.endsWith("'") || var.endsWith("\"")) &&
							!(var.startsWith("$") )){
					}
					else 
					{ String str=filterString(f1.getLeftOp().get(2));
					ret.add("(declare-variable "+str +" Bool)\n");
					}
				}

			}

			break;
		case "addslashes":
		case "stripslashes":
		case "mysql_real_escape_string":
		case "strcmp":
		case "explode":
		case "implode":
		case "strpos":
		case "rand": case "mt_rand":
		case "trim": case "rtrim":
		case "nl2br": 
		case "urldecode":
		case "FLAG_BINARY_EQUAL":
		case "LAG_BINARY_NOT_EQUAL":
		case "FLAG_BINARY_IS_IDENTICAL":
		case "FLAG_BINARY_IS_NOT_IDENTICAL":

		case "str_replace":
		case "AST_ISSET":
		case "htmlspecialchars":
		case ".":
		case "escapeshellarg":
		case "escapeshellcmd":
		case "sinkvars":
		case "sink":
			ret.addAll(declareTraceHelper(f1));
			break;
        case "md5":
			ret.add("(define-fun containsNumbers_md5 ((input String)) Bool\n"
					+ "(ite (Contains input \"0\") true\n"
					+ "(ite (Contains input \"1\") true\n"
					+ "(ite (Contains input \"2\") true\n"
					+ "(ite (Contains input \"3\") true\n"
					+ "(ite (Contains input \"4\") true\n"
					+ "(ite (Contains input \"5\") true\n"
					+ "(ite (Contains input \"6\") true\n"
					+ "(ite (Contains input \"7\") true\n"
					+ "(ite (Contains input \"8\") true\n"
					+ "(ite (Contains input \"9\") true false \n"
					+ ")))))))))))\n");

			ret.add("(define-fun containsLetters_md5 ((input String)) Bool\n (ite (Contains input \"a\") true "
					+ "\n (ite (Contains input \"b\") true "
					+ "\n (ite (Contains input \"c\") true "
					+ "\n (ite (Contains input \"d\") true "
					+ "\n (ite (Contains input \"f\") true "
					+ "\n (ite (Contains input \"e\") true "
					+ "\n (ite (Contains input \"E\") true "
					+ "\n (ite (Contains input \"x\") true "
					+ "\n (ite (Contains input \"X\") true "
					+ "\n (ite (Contains input \"A\") true "
					+ "\n (ite (Contains input \"B\") true "
					+ "\n (ite (Contains input \"C\") true "
					+ "\n (ite (Contains input \"D\") true "
					+ "\n (ite (Contains input \"F\") true "
					+ "\n (ite (Contains input \"g\") true "
					+ "\n (ite (Contains input \"h\") true "
					+ "\n (ite (Contains input \"i\") true "
					+ "\n (ite (Contains input \"j\") true "
					+ "\n (ite (Contains input \"k\") true "
					+ "\n (ite (Contains input \"l\") true "
					+ "\n (ite (Contains input \"m\") true "
					+ "\n (ite (Contains input \"n\") true "
					+ "\n (ite (Contains input \"o\") true "
					+ "\n (ite (Contains input \"p\") true "
					+ "\n (ite (Contains input \"q\") true "
					+ "\n (ite (Contains input \"r\") true "
					+ "\n (ite (Contains input \"s\") true "
					+ "\n (ite (Contains input \"t\") true "
					+ "\n (ite (Contains input \"u\") true "
					+ "\n (ite (Contains input \"v\") true "
					+ "\n (ite (Contains input \"w\") true "
					+ "\n (ite (Contains input \"y\") true "
					+ "\n (ite (Contains input \"z\") true "
					+ "\n (ite (Contains input \"G\") true "
					+ "\n (ite (Contains input \"H\") true "
					+ "\n (ite (Contains input \"I\") true "
					+ "\n (ite (Contains input \"J\") true "
					+ "\n (ite (Contains input \"K\") true "
					+ "\n (ite (Contains input \"L\") true "
					+ "\n (ite (Contains input \"M\") true "
					+ "\n (ite (Contains input \"N\") true "
					+ "\n (ite (Contains input \"O\") true "
					+ "\n (ite (Contains input \"P\") true "
					+ "\n (ite (Contains input \"Q\") true "
					+ "\n (ite (Contains input \"R\") true "
					+ "\n (ite (Contains input \"S\") true "
					+ "\n (ite (Contains input \"T\") true "
					+ "\n (ite (Contains input \"U\") true "
					+ "\n (ite (Contains input \"V\") true "
					+ "\n (ite (Contains input \"W\") true "
					+ "\n (ite (Contains input \"Y\") true "
					+ "\n (ite (Contains input \"Z\") true false)))))))))))))))))))))))))))))))))))))))))))))))))))))\n");

			ret.add("(define-fun containsCharacters_md5 ((input String)) Bool "
					+ "(ite (Contains input \";\") true " 
					+ "(ite (Contains input \",\") true " 
					+ "(ite (Contains input \"/\") true " 
					+ "(ite (Contains input \".\") true " 
					+ "(ite (Contains input \"$\") true " 
					+ "(ite (Contains input \"%\") true " 
					+ "(ite (Contains input \"^\") true " 
					+ "(ite (Contains input \"?\") true " 
					+ "(ite (Contains input \"<\") true " 
					+ "(ite (Contains input \">\") true " 
					+ "(ite (Contains input \"\'\") true " 
					+ "(ite (Contains input \"=\") true " 
					+ "(ite (Contains input \"!\") true false ))))))))))))))\n");
			ret.addAll(declareTraceHelper(f1));
			break;

		case "uniqid":

			ret.add("(declare-variable "+left +" String)\n");

			if(f1.getLeftOp().size()==2){
				if((!(f1.getLeftOp().get(1).equalsIgnoreCase("true"))) || (!(f1.getLeftOp().get(1).equalsIgnoreCase("false"))) ){
					ret.add("(declare-variable "+filterString(f1.getLeftOp().get(1)) +" Bool)\n");

				}
			}
			if(f1.getRightOp() != null){
				ret.add("(declare-variable "+filterString(f1.getRightOp()) +" String)\n");
			}


			break;

		case "AST_ASSIGN":

			ret.add("(declare-variable "+left +" String)\n");

			if(!(f1.getRightOp().equals("\"\"")) && checkNotConstString(f1.getRightOp())){
				ret.add("(declare-variable "+filterString(f1.getRightOp()) +" String)\n");

			}
			break;


		case "?":
			if (f1.getLeftOp().size() > 1 ){
				for (String l :f1.getLeftOp()){
					if(!(l.equals("\"\"")) && checkNotConstString(l))
						ret.add("(declare-variable "+filterString(l) +" String)\n");
				}
			}
			if(!(f1.getRightOp().equals("\"\"")) && checkNotConstString(f1.getRightOp())){
				ret.add("(declare-variable "+filterString(f1.getRightOp()) +" String)\n");

			}
			break;
	
			
		}	

		ret.add(	"(define-fun intVal ((str String)) Bool\n"
				+ "(RegexIn str  (RegexStar (RegexUnion (RegexUnion (RegexUnion (RegexUnion (RegexUnion (RegexDigit \"0\") (RegexUnion (RegexDigit \"1\" ) (RegexDigit \"2\"))) "
				+ " (RegexUnion (RegexDigit \"3\" ) (RegexDigit \"4\")))\n "
				+ "(RegexUnion (RegexDigit \"5\" ) (RegexDigit \"6\")))\n"
				+ "(RegexUnion (RegexDigit \"7\" ) (RegexDigit \"8\")))\n"
				+ "(RegexDigit \"9\" ) )"
				+ ") ) )\n");


		return ret;
	}

	private String assignAttackStrings(HashSet<Formula> z3FormulaList, String sinkType){
		String ret = "", tret="", context= null, part;
		String[] str;
		for (Formula p : z3FormulaList){
			if (p.getSource() != "STATIC")
				return ret;
			//  listOfSuper.addAll(p.getSuperGlobals());
			if (p.getOperator().trim() == "sinkvars"){
				//listOfSinkVars.add(filterString(p.getLeftOp().get(0)).trim());
				//listOfSinkVars.add(p);

				context= p.getType().trim(); 
				part= sinkType.toUpperCase()+"_ATTACK_STRINGS_"+context;
				str = AttackStrings.getAttackStrinsList(part);

				if (str != null){
					tret="";
					for (String attString: str)
						tret +=" (= "+filterString(p.getLeftOp().get(0))+" \""+attString+"\" )\n";
					count++;
					ret+="\n(assert (= p1b"+count+" (or "+tret+ ")))\n";
					ret+="(assert p1b"+count+" )\n"; 
				}
			}
			else if (p.getOperator().trim() == "sink"){
				context= p.getType().trim(); 
				part= sinkType.toUpperCase()+"_ATTACK_STRINGS_"+context;
				str = AttackStrings.getAttackStrinsList(part);

				if (str != null){
					tret= "";	
					for (String attString: str)
						tret +=" (Contains "+filterString(p.getLeftOp().get(0))+" \""+attString+"\" )\n";
					count++;
					ret+="\n(assert (= p1b"+count+" (or "+tret+ ")))\n";
					ret+="(assert p1b"+count+" )\n"; 
					for (String sglobal: p.getSuperGlobals()){
						tret="";
						for (String attString: str){
							tret +=" (= "+filterString(sglobal)+" \""+attString+"\" )\n";
							count++;
							ret+="\n(assert (= p1b"+count+" (or "+tret+ ")))\n";
							ret+="(assert p1b"+count+" )\n";
						}
					}  
				}

			}
			else {

				part= sinkType.toUpperCase()+"_ATTACK_STRINGS_NO_QUOTES";
				str = AttackStrings.getAttackStrinsList(part);

				if (str != null){
					for (String sglobal: p.getSuperGlobals()){
						tret="";
						for (String attString: str)
							tret +=" (= "+filterString(sglobal)+" \""+attString+"\" )\n";
						count++;
						ret+="\n(assert (= p1b"+count+" (or "+tret+ ")))\n";
						ret+="(assert p1b"+count+" )\n";

					}  
				}

			}
		} //end for

		return ret;

	}	


	private HashSet<String> declareTraceHelper(Formula f1) {

		HashSet<String> ret = new HashSet<String>();
		if (f1.getLeftOp() != null){
			if (f1.getLeftOp().size()==1 && checkNotConstString(f1.getLeftOp().get(0)) )
				ret.add("(declare-variable "+filterString(f1.getLeftOp().get(0)) +" String)\n");

			else if (f1.getLeftOp().size()==2){
				if(checkNotConstString(f1.getLeftOp().get(1))){
					ret.add("(declare-variable "+filterString(f1.getLeftOp().get(1)) +" String)\n");
				}
			}
			else if (f1.getLeftOp().size()==3){
				if(checkNotConstString(f1.getLeftOp().get(2))){
					ret.add("(declare-variable "+filterString(f1.getLeftOp().get(2)) +" String)\n");
				}
			}
		}

		if (f1.getRightOp() != null && !(f1.getRightOp().equals("\"\"")) && 
				checkNotConstString(f1.getRightOp()))
			ret.add("(declare-variable "+filterString(f1.getRightOp()) +" String)\n");

		return ret;
	}


	private HashSet<String> handleOptionFormula(Formula f1) {
		HashSet<String> ret = new HashSet<>();
		String right = f1.getRightOp();


		if(!right.isEmpty()){
			ret.add("(declare-variable "+filterString(right) +" String)\n");
		}

		return ret;
	}


	private Set<String> handleAssignFormula(Formula f1) {
		HashSet<String> ret = new HashSet<>();
		String left = f1.getLeftOp().get(0);


		if(!left.isEmpty()){
		ret.add("(declare-variable "+filterString(left) +" String)\n");
		
		}
	
		return ret;
	}



	private String FormulaTranslation(HashSet<Formula> z3FormulaList2) {

		String ret="";

		for (Formula f1: z3FormulaList2){
			if (f1.getSource().equals("FORM")){
				count++;
				ret+="\n%"+f1.toString()+"\n";
				if (f1.getOperator().equalsIgnoreCase("=")) 
					ret+=translateAssignFormula(f1);
				else if (f1.getOperator().equalsIgnoreCase("maxlen") || 
						f1.getOperator().equalsIgnoreCase("minlen") )
					ret+=translateMaxLenFormula(f1);
				else if(f1.getOperator().equalsIgnoreCase("or") )
					ret+=translateORFormula(f1);
			}
		if (f1.getSource().equals("TRACE") || f1.getSource() == "STATIC"){
				ret+="\n%"+f1.toString()+"\n";
				switch(f1.getOperator()){
				case "BINARY_IS_EQUAL": case "AST_ASSIGN":
					ret+=translateASTAssignFormula(f1);
					break;
				case "?":
					ret+=translateASTConditional(f1);
					break;
				case "AST_ISSET": 
					ret+=translateIssetFormula(f1);
					break;
				case "htmlspecialchars": case "htmlentities":
					ret+=translateHtmlspecialcharsFormula(f1);
					break;
				case "urldecode":
					ret+=translateUrldecodeFormula(f1);
					break;
				case "strstr":
					ret+=translateStrstrFormula(f1);
					break;
				case "str_replace":
					ret+=translateStr_replaceFormula(f1);
					break;

				case "strip_tags":
					ret+=translateStrip_tagsFormula(f1);
					break;
				case "substr":
					ret+=translateSubstrFormula(f1);
					break;
				case "nl2br":
					ret+=translateNl2brFormula(f1);
					break;

				case "addslashes":
					ret+=translateAddslashesFormula(f1);
					break;
				case "stripslashes":
					ret+=translateStripslashesFormula(f1);
					break;
				case "mysql_real_escape_string": case "mysqli_real_escape_string":
				case "mysql_escape_string": case "mysqli_escape_string": 
				case "dbx_escape_string": case "db2_escape_string":	
					ret+=translateMysql_real_escape_stringFormula(f1);
					break;

				case "intval":
					ret+=translateIntvalFormula(f1);
					break;
				case "explode":
					ret+=translateExplodeFormula(f1);
					break;
				case "rand": case "mt_rand":
					ret+=translateRandFormula(f1);
					break;
				case "md5":
					ret+=translateMd5Formula(f1);
					break;
				case "strcmp":
					ret+=translateStrcmpFormula(f1);
					break;
				case "uniqid":
					ret+=translateUniqidFormula(f1);
					break;
					//boolean functions
				case "is_numeric":
					ret+=translateIs_numericFormula(f1);
					break;
				case "is_int": case "is_integer":
					ret+=translateIs_intFormula(f1);
					break;

				case "strpos":
					ret+=translateStrposFormula(f1);
					break;
				case "empty":
					ret+=translateEmptyFormula(f1);
					break;
					case ".":
					ret+=translateConcat(f1);
					break;
				case "strtr":
					ret+=translateStrtr(f1);
					break;	

				case "escapeshellarg":
					ret+=translateEscapeshellarg(f1);
					break;
				case "escapeshellcmd":
					ret+=translateEscapeshellcmd(f1);
					break;
				}
			}
		}

		return ret;
	}


	private String translateStrtr(Formula f1) {
		ArrayList<String> from= new ArrayList<String>(); 
		ArrayList<String> to = new ArrayList<String>();
		String ret = "";
		if (f1.getLeftOp().size() >= 2 ) {
			String str = filterString(f1.getLeftOp().get(0));
			for (int i = 1; i< f1.getLeftOp().size(); i ++ ) {
				if (i%2 == 0) { 
					if (checkNotConstString(f1.getLeftOp().get(i)))
						to.add(filterString (f1.getLeftOp().get(i))); 
					else 
						to.add (f1.getLeftOp().get(i));
				}
				else {
					if (checkNotConstString(f1.getLeftOp().get(i)))
						from.add(filterString (f1.getLeftOp().get(i))); 
					else 
						from.add (f1.getLeftOp().get(i));
				}
			}

			while (!to.isEmpty() && !from.isEmpty() )
			{   int i = 0 ; 
			ret+="(assert (= p1b"+ (count++)+" (= "+filterString(f1.getRightOp())+" (Replace "+ str+" "+from.get(i) +" "+ to.get(i)+"))))\n";
			if (negate)
				this.assertion.add("(assert p1b"+(count)+")\n");
			else
				ret+="(assert p1b"+(count)+")\n";

			i= i+1;
			}

		}
		return ret;
	}


	/*
	 *PHP manual: Following characters are preceded by a backslash: &#;`|*?~<>^()[]{}$\, \x0A and \xFF. 
	 * ' and " are escaped only if they are not paired
	 * 
	 */
	private String translateEscapeshellcmd(Formula f1) {
		String ret="", left= filterString(f1.getLeftOp().get(0));




		int co=++count;
		ret+="(declare-variable t_cmdescape_"+c+" Int)\n(declare-variable t_cmdescape_"+(c+1)+" Int)\n"
				+ "(declare-variable t_cmdescape_"+(c+2)+" Int)\n(declare-variable t_cmdescape_\"+(c+3)+\" Int)\n"
				+ "(declare-variable t_cmdescape_\"+(c+4)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+5)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+6)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+7)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+8)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+9)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+10)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+11)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+12)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+13)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+14)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+15)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+16)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+17)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+18)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+19)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+20)+\" Int)\\n"
				+ "(declare-variable t_cmdescape_\"+(c+21)+\" Int)\\n";


		//`|*?~<>^()[]{}$\, \x0A and \xFF

		ret+="(assert (= p1b"+count + " (= \"'\" (CharAt "+left +" t_cmdescape_"+(c)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"&\" (CharAt "+left +" t_cmdescape_"+(c+1)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"#\" (CharAt "+left +" t_cmdescape_"+(c+2)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \";\" (CharAt "+left +" t_cmdescape_"+(c+3)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"`\" (CharAt "+left +" t_cmdescape_"+(c+4)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"|\" (CharAt "+left +" t_cmdescape_"+(c+5)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"*\" (CharAt "+left +" t_cmdescape_"+(c+6)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"?\" (CharAt "+left +" t_cmdescape_"+(c+7)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"~\" (CharAt "+left +" t_cmdescape_"+(c+8)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \">\" (CharAt "+left +" t_cmdescape_"+(c+9)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"<\" (CharAt "+left +" t_cmdescape_"+(c+10)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"^\" (CharAt "+left +" t_cmdescape_"+(c+11)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"(\" (CharAt "+left +" t_cmdescape_"+(c+12)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \")\" (CharAt "+left +" t_cmdescape_"+(c+13)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"[\" (CharAt "+left +" t_cmdescape_"+(c+14)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"]\" (CharAt "+left +" t_cmdescape_"+(c+15)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"{\" (CharAt "+left +" t_cmdescape_"+(c+16)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"}\" (CharAt "+left +" t_cmdescape_"+(c+17)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"$\" (CharAt "+left +" t_cmdescape_"+(c+18)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"\\\" (CharAt "+left +" t_cmdescape_"+(c+19)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"\\x0A\" (CharAt "+left +" t_cmdescape_"+(c+20)+") )))\n";
		ret+="(assert (= p1b"+(++count) + " (= \"\\xFF\" (CharAt "+left +" t_cmdescape_"+(c+21)+") )))\n";




		//; \x5C = \
		while(count <= 22 && c <=  22) {
			count = count+1;
			ret+="(assert (= p1b"+(count) + " (= \"\\\" (CharAt "+left+" (- t_cmdescape_"+(c)+" 1 )))))\n";
			c = c+1;
		}

		
		if (negate)

		{  for (int i= count; i< 44; i++)
			this.assertion.add("(assert p1b"+(i)+")\n");

		}
		else {
			for (int i= count; i< 44; i++)
				ret+="(assert p1b"+(i)+")\n";


		}



		ret+="(assert (= p1b"+(++count) + " (= "+filterString(f1.getRightOp())+" "+ left+" )))\n";

		if (negate)
			this.assertion.add("(assert p1b"+(count)+")\n");
		else
			ret+="(assert p1b"+(count)+")\n";

		c=c+1;
		count = count +23;
		return ret;
	}


	/*  PHP manual: "\'" before ' 
         rounds string with single quotes
	 */
	private String translateEscapeshellarg(Formula form) {
		String ret="", left= filterString(form.getLeftOp().get(0));


		int co=++count;
		ret+="(declare-variable t_shellescape_"+c+" String)\n(declare-variable t_shellescape_"+(c+1)+" String)\n";
		ret+="(assert (= p1b"+count + " (= t_shellescape_"+(c)+" (Replace "+left +" \"'\" \"\\\\\\'\"))))\n";

		ret+="(assert (= p1b"+(++count) + " (= t_shellescape_"+(c+1)+" (Concat (Concat \"'\" t_shellescape_"+(c) +") \"'\" ) )))\n";


		ret+="(assert (= p1b"+(++count) + " (= "+filterString(form.getRightOp())+" t_shellescape_"+(c+1) +")))\n";

		if (negate)
			this.assertion.add("(assert p1b"+(count)+")\n");
		else
			ret+="(assert p1b"+(count)+")\n";
		c=c+2; 
		return ret;
	}


	private String translateConcat(Formula formula) {
		String ret="",  left=formula.getLeftOp().get(0), right= formula.getRightOp();

		if(checkNotConstString(left))
			left = filterString(left);
		if (checkNotConstString(right))
			right = filterString(right);

		ret+="(assert (= p1b"+ (++count)+" (= "+filterString(formula.getReturnVar())+" (Concat "+left+" "+ right+"))))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(count)+")\n");
		else
			ret+="(assert p1b"+(count)+")\n"; 

		return ret;
	}


	private String translateStrcmpFormula(Formula form) {
		String ret="";
		int co;
		if(form.getLeftOp().size()>=2){
			co=++count;
			ret+="(declare-variable t_strcmp_"+c+" String)\n(declare-variable t_strcmpBool_"+(c+1)+" Bool)\n";

			String str1=filterString(form.getLeftOp().get(0));
			String str2=filterString(form.getLeftOp().get(1));
			c=c+2;
			ret+="(assert (= t_strcmpBool_"+(c+1)+" (= "+str1+" "+ str2+")))\n";
			ret+= "(assert (ite t_strcmpBool_"+(c+1)+ " (= t_strcmp_"+c+" 0) (= t_strcmp_"+c+" (- (Length "+str1+" ) (Length "+str2+")))) )\n"; 
		}
		return ret;
	}


	private String translateMd5Formula(Formula form) {
		String ret="";
		int co;
		if (form.getLeftOp().size()==1){
			co=++count;
			ret+="(assert (= p1b"+(count) + " (= (Length "+filterString(form.getRightOp())+" ) 32 )) )\n";
			if (negate)
				this.assertion.add("\n(assert p1b"+count+" )\n");
			else 
				ret+="\n(assert p1b"+count+" )\n";

			String str=filterString(form.getRightOp());
			ret+="(assert (= p1b"+(++count)+" (containsNumbers_md5 "+str+")))\n";
			if (negate)
				this.assertion.add("(assert p1b"+(co+1)+")\n");
			else 
				ret+="(assert p1b"+(co+1)+")\n";
			ret+="(assert (= p1b"+(++count)+" (containsLetters_md5 "+str+")))\n";
			if (negate)
				this.assertion.add("(assert p1b"+(co+2)+")\n");
			else
				ret+="(assert p1b"+(co+2)+")\n";
			ret+="(assert (= p1b"+(++count)+" (not (containsCharacters_md5 "+str+"))))\n";
			if (negate)
				this.assertion.add("(assert p1b"+(co+3)+")\n");
			else
				ret+="(assert p1b"+(co+3)+")\n";

		}
		return ret;
	}


	private String translateRandFormula(Formula form) {
		String ret="";
		ret+="(assert (= p1b"+count + " (intVal "+ filterString(form.getRightOp())+ ")) )\n";
		if (negate)
			this.assertion.add("(assert p1b"+(count)+")\n");
		else
			ret+="(assert p1b"+(count)+")\n";

		return ret;
	}


	private String translateUniqidFormula(Formula form) {
		String ret="", clauses;
		int co;
		if (form.getLeftOp().size()==2){
			co=++count;
			ret+="(assert (= p1b"+(count) + " (= (Length "+filterString(form.getRightOp()) + ") 23 )))\n";
			clauses="p1b"+co +" ";
			if (negate)
				this.assertion.add("\n(assert "+clauses+" )\n");
			else
				ret+="\n(assert "+clauses+" )\n";


		}
		else if (form.getLeftOp().size()==1){
			String prefix=form.getLeftOp().get(0);
			co=++count;
			//ret+="(declare-variable t_strpos_"+c+" String)\n";
			ret+="(assert (= p1b"+count + " (= (Length "+filterString(form.getRightOp())+ " ) 13 ) ) )\n";
			ret+="(assert (= p1b"+(++count) + " ( StartsWith "+filterString(form.getRightOp())+ " "+ prefix+" ) ))\n";
			c=c+1;
			clauses="p1b"+co +" ";
			clauses+="p1b"+(1+co) +" ";
			if (negate)
				this.assertion.add("\n(assert (and "+clauses+" ) )\n");
			else
				ret+="\n(assert (and "+clauses+" ) )\n";


		}

		else if (form.getLeftOp().size()==0){
			co=++count;
			ret+="(assert (= p1b"+(count) + " (= (Length "+filterString(form.getRightOp()) + ") 13 )))\n";
			clauses="p1b"+co +" ";
			if (negate)
				this.assertion.add("\n(assert "+clauses+"  )\n");
			else
				ret+="\n(assert "+clauses+"  )\n";


		}
		return ret;
	}


	private String translateExplodeFormula(Formula form) {
		String ret="";
		if(form.getLeftOp().size()==3){
			String retArray=form.getRightOp();
			String l=form.getLeftOp().get(1);
			if (form.getLeftOp().get(1).contains("[") || form.getLeftOp().get(1).contains("]") ){
				l=form.getLeftOp().get(1).replace("[", "_").replace("]", "");
				l=l.trim();
			}
			ret+="(declare-const "+ retArray+" (Array Int String) )\n"; 
			ret+="(assert (= (store (as "+retArray +"(Array Int String) )"+" 0 " +l +" ) (as "+retArray +"(Array Int String)) ))\n";
			count++;
			if (negate)
				this.assertion.add("\n(assert p1b"+count +"  )\n");
			else
				ret+="\n(assert p1b"+count +"  )\n";
		}
		return ret;
	}


	private String translateIntvalFormula(Formula form) {
		String ret="";
		int co=++count;
		ret+="(assert (= p1b"+count + " (intVal "+ filterString(form.getRightOp())+ ")) )\n";
		ret+="(assert (= p1b"+(++count) + " (= "+ filterString(form.getLeftOp().get(0))+" "+ filterString(form.getRightOp())+ ")) )\n";
		if (negate)
		{
			this.assertion.add("\n(assert p1b"+co +" )\n");
			this.assertion.add("\n(assert p1b"+(1+co)+")\n");


		}
		else
		{   ret+="\n(assert p1b"+co +" )\n";

		ret+="\n(assert p1b"+(1+co)+")\n";

		}
		return ret;
	}


	private String translateMysql_real_escape_stringFormula(Formula form) {
		String ret="", left;
		if (form.getLeftOp().size() > 1)
			left= filterString(form.getLeftOp().get(1));
		else 
			left= filterString(form.getLeftOp().get(0));


		int co=++count;
		ret+="(declare-variable t_mescape_"+c+" String)\n(declare-variable t_mescape_"+(c+1)+" String)\n(declare-variable t_mescape_"+(c+2)+" String)\n"
				+ "(declare-variable t_mescape_"+(c+3)+" String)\n(declare-variable t_mescape_"+(c+4)+" String)\n(declare-variable t_mescape_"+(c+5)+" String)\n(declare-variable t_mescape_"+(c+6)+" String)\n";
		ret+="(assert (= p1b"+count + " (= t_mescape_"+(c)+" (Replace "+left +" \"'\" \"\\\\\\'\"))))\n";
		/* if (negate)
	          	this.assertion.add("(assert p1b"+(co)+")\n");
	          else
		         ret+="(assert p1b"+(co)+")\n";
		 */
		ret+="(assert (= p1b"+(++count) + " (= t_mescape_"+(c+1)+" (Replace t_mescape_"+(c)+" \"\\\\\" \"\\\\\\\\\"))))\n";
		/* if (negate)
	          	this.assertion.add("(assert p1b"+(co+1)+")\n");
	          else
		 ret+="(assert p1b"+(co+1)+")\n";
		 */
		ret+="(assert (= p1b"+(++count) + " (= t_mescape_"+(c+2)+" (Replace t_mescape_"+(c+1)+" \"\\x22\" \"\\x5C\\x22\"))))\n";
		/* if (negate)
	          	this.assertion.add("(assert p1b"+(co+2)+")\n");
	          else
		 ret+="(assert p1b"+(co+2)+")\n";
		 */
		// ret+="(assert (= p1b"+(++count) + " (= t_mescape_"+(c+3)+" (Replace t_mescape_"+(c+2)+" \"\\x00\" \"\\\\x00\"))))\n";
		ret+="(assert (= p1b"+(++count) + " (= t_mescape_"+(c+3)+" (Replace t_mescape_"+(c+2)+" \"\\n\" \"\\\\n\"))))\n";
		/*  if (negate)
		          	this.assertion.add("(assert p1b"+(co+3)+")\n");
		          else
		         ret+=";(assert p1b"+(co+3)+")\n";
		 */
		ret+="(assert (= p1b"+(++count) + " (= t_mescape_"+(c+4)+" (Replace t_mescape_"+(c+3)+" \"\\r\" \"\\\\r\"))))\n";
		/* if (negate)
		          	this.assertion.add("(assert p1b"+(co+4)+")\n");
		          else
		     ret+=";(assert p1b"+(co+4)+")\n";
		 */
		ret+="(assert (= p1b"+(++count) + " (= t_mescape_"+(c+5)+" (Replace t_mescape_"+(c+4)+" \"\\x1a\" \"\\\\x1a\"))))\n";
		/* if (negate)
		          	this.assertion.add("(assert p1b"+(co+5)+")\n");
		          else
		     ret+=";(assert p1b"+(co+5)+")\n";
		 */
		ret+="(assert (= p1b"+(++count) + " (= "+filterString(form.getRightOp())+" t_mescape_"+(c+5) +")))\n";
		/* if (negate)
		          	this.assertion.add("(assert p1b"+(co+6)+")\n");
		          else
		     ret+="(assert p1b"+(co+6)+")\n";
		 */
		//		   ret+="(assert (= p1b"+(++count) + " (and (not (Contains "+filterString(form.getRightOp())+ " \"'\")) (not (Contains "+filterString(form.getRightOp())+ " \"\\\"\")) (not (Contains "+filterString(form.getRightOp())+ " \"\\\\\")) )))\n";

		ret+="(assert (= p1b"+(++count) + " (or (Contains "+filterString(form.getRightOp())+ " \"\\\\\\'\") "
				+ "(Contains "+filterString(form.getRightOp())+ " \"\\\\\\\\\") "
				+ " (Contains "+filterString(form.getRightOp())+ " \"\\x5C\\x22\") )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(co+7)+")\n");
		else
			ret+="(assert p1b"+(co+7)+")\n";

		count= count+1;
		ret+="(assert (= p1b"+(count) + "(= "+left +" " +filterString(form.getRightOp())+")))";
		if (negate)
			this.assertion.add("(assert p1b"+(count)+")\n");
		else
			ret+="(assert p1b"+(count)+")\n";

		c=c+7; 

		return ret;
	}


	private String translateStripslashesFormula(Formula form) {
		String ret="";
		ret+="(declare-variable t_stripslash_"+c+" String)\n(declare-variable t_stripslash_"+(c+1)+" String)\n(declare-variable t_stripslash_"+(c+2)+" String)\n"
				+ "(declare-variable t_stripslash_"+(c+3)+" String)\n";
		ret+="(assert (= p1b"+count + " (= t_stripslash_"+(c)+" (Replace "+filterString(form.getLeftOp().get(0))+" \"\\\\\\'\" \"'\" ))))\n";
		/* if (negate)
	          	this.assertion.add("(assert p1b"+(co)+")\n");
	          else
	         ret+="(assert p1b"+(co)+")\n";
		 */   
		ret+="(assert (= p1b"+(++count) + " (= t_stripslash_"+(c+1)+" (Replace t_stripslash_"+(c)+" \"\\\\\\\\\" \"\\\\\" ))))\n";
		/* if (negate)
	          	this.assertion.add("(assert p1b"+(co+1)+")\n");
	          else
	     ret+="(assert p1b"+(co+1)+")\n";
		 */
		ret+="(assert (= p1b"+(++count) + " (= t_stripslash_"+(c+2)+" (Replace t_stripslash_"+(c+1)+" \"\\x5C\\x22\" \"\\x22\"))))\n";
		/* if (negate)
	          	this.assertion.add("(assert p1b"+(co+2)+")\n");
	          else
	     ret+="(assert p1b"+(co+2)+")\n";
		 */
		//ret+="(assert (= p1b"+(++count) + " (= t_stripslash_"+(c+3)+" (Replace t_stripslash_"+(c+2)+" \"\\\\0\" \"\\0\" ))))\n";//\\0" "\0
		//ret+="(assert p1b"+(co+3)+")\n";
		ret+="(assert (= p1b"+(++count) + " (= "+filterString(form.getRightOp())+" t_stripslash_"+(c+2) +")))\n";
		/* if (negate)
	          	this.assertion.add("(assert p1b"+(co+3)+")\n");
	          else
	     ret+="(assert p1b"+(co+3)+")\n";
		 */

		count= ++count;
		ret+="(assert (= p1b"+(count) + " (and (not (Contains "+filterString(form.getRightOp())+ " \"\\x5C\\x22\")) (not (Contains "+filterString(form.getRightOp())+ " \"\\\\\\\\\")) (not (Contains "+filterString(form.getRightOp())+ " \"\\\\\\'\")) )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(count)+")\n");
		else
			ret+="(assert p1b"+(count)+")\n";

		count=count++;
		ret+="(assert (= p1b"+(count) + "(= "+filterString(form.getLeftOp().get(0)) +" " +filterString(form.getRightOp())+")))";
		if (negate)
			this.assertion.add("(assert p1b"+(count)+")\n");
		else
			ret+="(assert p1b"+(count)+")\n";

		c=c+4;
		return ret;
	}


	private String translateAddslashesFormula(Formula form) {

		String ret="";
		int co=++count;
		ret+="(declare-variable t_addslash_"+c+" String)\n(declare-variable t_addslash_"+(c+1)+" String)\n(declare-variable t_addslash_"+(c+2)+" String)\n"
				+ "(declare-variable t_addslash_"+(c+3)+" String)\n";
		ret+="(assert (= p1b"+count + " (= t_addslash_"+(c)+" (Replace "+filterString(form.getLeftOp().get(0)) +" \"'\" \"\\\\\\'\"))))\n";
		//if (negate)
		//   	this.assertion.add("(assert p1b"+(co)+")\n");
		//    else
		// ret+="(assert p1b"+co+")\n";

		ret+="(assert (= p1b"+(++count) + " (= t_addslash_"+(c+1)+" (Replace t_addslash_"+(c)+" \"\\\\\" \"\\\\\\\\\"))))\n"; //\
		//if (negate)
		//   	this.assertion.add("(assert p1b"+(co+1)+")\n");
		// else
		//ret+="(assert p1b"+(co+1)+")\n";
		ret+="(assert (= p1b"+(++count) + " (= t_addslash_"+(c+2)+" (Replace t_addslash_"+(c+1)+" \"\\x22\" \"\\x5C\\x22\"))))\n";// "
		// if (negate)
		//    	this.assertion.add("(assert p1b"+(co+2)+")\n");
		//else
		// ret+="(assert p1b"+(co+2)+")\n";
		//ret+="(assert (= p1b"+(++count) + " (= t_addslash_"+(c+3)+" (Replace t_addslash_"+(c+2)+" \"\\0\" \"\\\\0\"))))\n";
		// ret+="(assert p1b"+(co+3)+")\n";
		ret+="(assert (= p1b"+(++count) + " (= "+filterString(form.getRightOp())+" t_addslash_"+(c+2) +")))\n";
		//if (negate)
		//   	this.assertion.add("(assert p1b"+(co+3)+")\n");
		//    else
		// ret+="(assert p1b"+(co+3)+")\n";
		count= count+1;
		ret+="(assert (= p1b"+(count) + " (and (not (Contains "+filterString(form.getRightOp())+ " \"'\")) (not (Contains "+filterString(form.getRightOp())+ " \"\\\"\")) (not (Contains "+filterString(form.getRightOp())+ " \"\\\\\")) )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(count)+")\n");
		else
			ret+="(assert p1b"+(count)+")\n";  

		count=count++;
		ret+="(assert (= p1b"+(count) + "(= "+filterString(form.getLeftOp().get(0)) +" " +filterString(form.getRightOp())+")))";
		if (negate)
			this.assertion.add("(assert p1b"+(count)+")\n");
		else
			ret+="(assert p1b"+(count)+")\n";
		c=c+4; 


		return ret;
	}


	private String translateEmptyFormula(Formula f1) {
		String ret="", left= filterString(f1.getLeftOp().get(0));
		count++;
		ret+="(assert (= p1b"+count +" (or (= (Length (as "+ left+" String) ) 0) (= (as "+left+ " String) \"0\") (= (as "+left+ " String) \"NULL\" ) ) )) \n";
		if (negate)
			this.assertion.add("\n(assert p1b"+count+"  )\n");
		else
			ret+="\n(assert p1b"+count+"  )\n";

		return ret;
	}


	private String translateStrposFormula(Formula form) {
		String ret="";
		int co=++count;
		//TODO: check this the 3rd argument is not modeled
		if(form.getLeftOp().size()>=2){
			String str=filterString(form.getLeftOp().get(0));
			String str1=form.getLeftOp().get(1);
			if(!checkNotConstString(str1)){
				str1="\""+str1+"\"";
			}
			else 
				str1=filterString(str1);

			ret+="(assert (ite (< (Indexof "+str +" "+ str1+") 0) false true ))\n";
		}

		return ret;
	}


	private String translateIs_intFormula(Formula form) {
		String ret="";
		int co=++count;
		String str=filterString(form.getLeftOp().get(0));
		ret+="(assert (= p1b"+count+" (containsNumbers "+str+")))\n";
		if (negate)
			this.assertion.add("(assert p1b"+co+")\n");
		else
			ret+="(assert p1b"+co+")\n";
		ret+="(assert (= p1b"+(++count)+" (not (containsLetters "+str+"))))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(co+1)+")\n");
		else
			ret+="(assert p1b"+(co+1)+")\n";
		ret+="(assert (= p1b"+(++count)+" (not (containsCharacters "+str+"))))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(co+2)+")\n");
		else
			ret+="(assert p1b"+(co+2)+")\n";

		return ret;
	}


	private String translateIs_numericFormula(Formula form) {
		String ret="";

		int co=++count;
		String str=filterString(form.getLeftOp().get(0));
		ret+="(assert (= p1b"+count+" (not (ContainsDoubles "+str+"))))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(co)+")\n");
		else
			ret+="(assert p1b"+co+")\n";

		ret+="(assert (= p1b"+(++count)+" (ite (or (StartsWith "+str+" \"0b\") (StartsWith "+str+" \"0B\") (StartsWith "+str+" \"0x\") (StartsWith "+str+" \"0X\")) "
				+ "(not (containsLetters2 "+str+") )"
				+ "(and (not (containsLetters2 "+str+") ) (not (containsHexLetters "+str+") ) ) )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(co+1)+")\n");
		else
			ret+="(assert p1b"+(co+1)+")\n";

		ret+="(assert (= p1b"+(++count)+" (ite (or (StartsWith "+str+" \"0b\") (StartsWith "+str+" \"0B\")) (and (ContainsOnlyBinary "+str+") (not (BeyondBinary "+str+"))) true )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(co+2)+")\n");
		else
			ret+="(assert p1b"+(co+2)+")\n";

		ret+="(assert (= p1b"+(++count)+" (ite (and (StartsWith "+str+" \"0\") (not (StartsWith "+str+" \"0x\")) (not (StartsWith "+str+" \"0b\")) (not (StartsWith "+str+" \"0X\")) (not (StartsWith "+str+" \"0B\"))) "
				+ "(and (ContainsOnlyOctals "+str+") (not (containsHexLetters "+str+"))) true )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(co+3)+")\n");
		else
			ret+="(assert p1b"+(co+3)+")\n";

		ret+="(assert (= p1b"+(++count)+" (not (containsCharacters2 "+str+"))))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(co+4)+")\n");
		else
			ret+="(assert p1b"+(co+4)+")\n";

		return ret;
	}


	private String translateNl2brFormula(Formula form) {
		String ret="";
		ret+="(assert (= p1b"+count+" (= "+filterString(form.getLeftOp().get(0)) +" "+filterString(form.getRightOp()) +")))\n";
		if (negate)
			this.assertion.add("(assert p1b"+count+" )\n");
		else
			ret+="(assert p1b"+count+" )\n";

		return ret;
	}


	private String translateSubstrFormula(Formula form) {
		String ret="", left = filterString (form.getLeftOp().get(0).trim());
		int co;
	if(form.getOperator().equals("substr") ){
			co=++count;
			String str=form.getLeftOp().get(1);
			if (form.getSource() == "STATIC"
					&& !checkNotConstString(form.getLeftOp().get(0))
					&& !checkNotConstString(form.getLeftOp().get(1))
					){
				str=filterString (form.getLeftOp().get(1));

			}

			else if(!(form.getLeftOp().get(1).matches("(-*)[0-9]+") )){
				str=filterString (form.getLeftOp().get(1));
			}


			if(form.getLeftOp().size()==3){
				String str2=form.getLeftOp().get(2);

				if (form.getSource() == "STATIC"
						&& !checkNotConstString(form.getLeftOp().get(0))
						&& !checkNotConstString(form.getLeftOp().get(1))
						){

					str2= (form.getLeftOp().get(0));
					left = filterString (form.getLeftOp().get(2));

				}
				else if(!(form.getLeftOp().get(2).matches("(-*)[0-9]+") )){
					str2=filterString (form.getLeftOp().get(2));
				}
				ret+="(assert (= p1b"+(count) + " (= "+filterString (form.getRightOp())+ " (substr "+left+" "+ str+" "+ str2+" ) )))\n";
				if (negate)
					this.assertion.add("(assert p1b"+co+")\n");
				else
					ret+="(assert p1b"+co+")\n";
			}
			else if(form.getLeftOp().size()==2){
				ret+="(declare-variable t_substrLen_"+c+" Int)\n";
				ret+="(assert (= p1b"+count+" (= t_substrLen_"+c+" (- (Length "+left+") "+str+") )))\n";
				if (negate)
					this.assertion.add("(assert p1b"+co+")\n");
				else
					ret+="(assert p1b"+co+")\n";
				ret+="(assert (= p1b"+(++count) + " (= "+filterString (form.getRightOp())+ " (substr "+left+" "+ str+" t_substrLen_"+c+" ) )))\n";
				if (negate)
					this.assertion.add("(assert p1b"+(co+1)+")\n");
				else 
					ret+="(assert p1b"+(co+1)+")\n";
			}

		}
		return ret;
	}


	private String translateStrip_tagsFormula(Formula form) {
		String ret="";
		int co=++count;
		if(form.getLeftOp().size()==1){
			String left=filterString(form.getLeftOp().get(0));
			ret+="(assert (ite (or (Contains "+left+" \">\") (Contains "+left+" \"<\") (Contains "+left+" \"</\"))"
					+ "(= "+filterString(form.getRightOp())+" (strip_tags_next (strip_tags_main "+left+")))"
					+ "(= "+filterString(form.getRightOp())+" "+left+"))) \n";
		}
		else if(form.getLeftOp().size()==2){
			String retString = stripTags(form, c, co);
			ret+=retString;
			c=c+12;
		}
		return ret;
	}


	private String translateStr_replaceFormula(Formula form) {
		String ret="", clauses;

		count++;
		if(checkNotConstString(form.getLeftOp().get(1)) ){
			if(checkNotConstString(form.getLeftOp().get(0)) ){
				String left= filterString(form.getLeftOp().get(0));

				ret+="(assert (= p1b"+count + " (= "+filterString(form.getRightOp())+ " (Replace "+ filterString(form.getLeftOp().get(2))+" "+left+" "+filterString(form.getLeftOp().get(1)) +" ) )))\n";

				clauses="p1b"+count +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else 
					ret+="\n(assert "+clauses+"  )\n";
				count++;
				ret+="(assert (= p1b"+count + " (not (Contains "+filterString(form.getRightOp())+ " "+left+" ))))\n";
				clauses="p1b"+count +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+"  )\n";

			}
			else {
				ret+="(assert (= p1b"+count + " (= "+filterString(form.getRightOp())+ " (Replace "+ filterString(form.getLeftOp().get(2))+" \""+form.getLeftOp().get(0)+"\" "+filterString(form.getLeftOp().get(1)) +" ) )))\n";
				clauses="p1b"+count +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+"  )\n";
				count++;
				ret+="(assert (= p1b"+count + " (not (Contains "+filterString(form.getRightOp())+" \"" +form.getLeftOp().get(0)+ "\" ))))\n";
				clauses="p1b"+count +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+"  )\n";

			}
		}
		else {
			if(checkNotConstString(form.getLeftOp().get(0))  ){
				String left= filterString(form.getLeftOp().get(0));

				ret+="(assert (= p1b"+count + " (= "+filterString(form.getRightOp())+ " (Replace "+ filterString(form.getLeftOp().get(2))+" "+left+" \""+form.getLeftOp().get(1) +"\" ) )))\n";
				clauses="p1b"+count +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+"  )\n";
				count++;
				ret+="(assert (= p1b"+count + " (not (Contains "+filterString(form.getRightOp())+ " "+left+" ))))\n";
				clauses="p1b"+count +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+"  )\n";

			}
			else 
			{
				//if (checkNotConstString(form.getLeftOp().get(1)))
				ret+="(assert (= p1b"+count + " (= "+filterString(form.getRightOp())+ " (Replace "+ filterString(form.getLeftOp().get(2))+" "+form.getLeftOp().get(0)+"  "+form.getLeftOp().get(1) +" ) )))\n";
				//else 
				//  ret+="(assert (= p1b"+count + " (= "+filterString(form.getRightOp())+ " (Replace "+ filterString(form.getLeftOp().get(2))+" "+form.getLeftOp().get(0)+"  \""+form.getLeftOp().get(1) +"\" ) )))\n";

				clauses="p1b"+count +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+"  )\n";
				count++;
				ret+="(assert (= p1b"+count + " (not (Contains "+filterString(form.getRightOp())+ " "+form.getLeftOp().get(0)+" ))))\n";

				clauses="p1b"+count +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+"  )\n";


			}
		}

		return ret;
	}


	private String translateStrstrFormula(Formula form) {
		String ret="", clauses;
		String str1=filterString(form.getLeftOp().get(0));
		String str2=filterString(form.getLeftOp().get(1));
		if(form.getLeftOp().size()==2){
			int co=++count;
			clauses="p1b"+count +" ";	
			ret+="(declare-variable t_strstrStart_"+c+" String)\n(declare-variable t_strstrEnd_"+(1+c)+" String)\n";
			ret+="(assert (= t_strstrStart_"+(c)+" (Indexof "+str1 +" "+str2+")))\n";
			ret+="(assert (= t_strstrEnd_"+(1+c)+" (- (Length "+str1+") t_strstrStart_"+c+")))\n";
			ret+="(assert (= "+clauses+" (= "+ filterString(form.getRightOp())+" (Substring "+str1 +" t_strstrStart_"+c+" t_strstrEnd_"+(1+c)+" ))))\n";
			if (negate)
				this.assertion.add("\n(assert "+clauses+"  )\n");
			else
				ret+="\n(assert "+clauses+"  )\n";
			c=c+2;
		}

		else if(form.getLeftOp().size()==3){
			//co=++count;
			clauses="p1b"+count +" ";	
			ret+="(declare-variable t_strstrStart_"+c+" String)\n(declare-variable t_strstrEnd"+(1+c)+" String )\n"
					+ "(declare-variable t_strstrBool_"+(c+2)+" Bool)";
			ret+="(assert (= t_strstrStart_"+c+" (Indexof "+str1 +" "+str2+")))\n";
			ret+="(assert (= t_strstrEnd_"+(1+c)+" (- (Length "+str1+") t_strstrStart_"+c+")))\n";
			if(form.getLeftOp().get(2).equalsIgnoreCase("true") || form.getLeftOp().get(2).equalsIgnoreCase("false")){

				ret+="(assert (= "+ clauses +" (= t_strstrBool_"+(c+2)+" \""+form.getLeftOp().get(2) +"\")))\n";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="(assert "+clauses +")\n";

			}
			ret+="(assert (ite t_strstrBool_"+(c+2)+" (= "+ filterString(form.getRightOp())+" (Substring "+str1 +"0 t_strstrStart_"+c+" ))"
					+ " (= "+ filterString(form.getRightOp())+" (Substring "+str1 +" t_strstrStart_"+c+" t_strstrEnd_"+(1+c)+" ))))\n";

			c=c+3;
		}

		return ret;
	}


	private String translateUrldecodeFormula(Formula f1) {
		String ret = "";
		int co=++count; String clauses, left=filterString(f1.getLeftOp().get(0));
		ret+="(declare-variable t_url_"+c+" String)\n(declare-variable t_url_"+(c+1)+" String)\n(declare-variable t_url_"+(c+2)+" String)\n"
				+ "(declare-variable t_url_"+(c+3)+" String)\n";

		ret+="(assert (= p1b"+count + " (= t_url_"+(c)+" "+left+")))\n";
		clauses="p1b"+co +" ";
		/* if (negate)
		          	this.assertion.add("\n(assert "+clauses+"  )\n");
		     else
			       ret+="\n(assert "+clauses+")\n";
		 */
		ret+="(assert (= p1b"+(++count) + " (= t_url_"+(c+1)+" (Replace t_url_"+(c)+" \"%20\" \" \"))))\n";
		clauses="p1b"+(1+co) +" ";
		/* if (negate)
		          	this.assertion.add("\n(assert "+clauses+"  )\n");
		      else
				 ret+="\n(assert "+clauses+")\n";
		 */
		count++;
		ret+="(assert (= p1b"+count + " (not (Contains "+left+" \"%20\" ))))\n";
		clauses="p1b"+count +" ";
		if (negate)
			this.assertion.add("\n(assert "+clauses+"  )\n");
		else
			ret+="\n(assert "+clauses+"  )\n";

		ret+="(assert (= p1b"+(++count) + " (= t_url_"+(c+2)+" (Replace t_url_"+(c+1)+" \"%21\" \"!\"))))\n";
		clauses="p1b"+(2+co) +" ";
		/*if (negate)
		          	this.assertion.add("\n(assert "+clauses+"  )\n");
		          else
				 ret+="\n(assert "+clauses+")\n";
		 */

		count++;
		ret+="(assert (= p1b"+count + " (not (Contains "+left+" \"%21\" ))))\n";
		clauses="p1b"+count +" ";
		if (negate)
			this.assertion.add("\n(assert "+clauses+"  )\n");
		else
			ret+="\n(assert "+clauses+"  )\n";


		ret+="(assert (= p1b"+(++count) + " (= t_url_"+(c+3)+" (Replace t_url_"+(c+2)+" \"%25\" \"%\"))))\n";
		clauses="p1b"+(3+co) +" ";
		/*if (negate)
		          	this.assertion.add("\n(assert "+clauses+"  )\n");
		          else
				 ret+="\n(assert "+clauses+")\n";
		 */
		count++;
		ret+="(assert (= p1b"+count + " (not (Contains "+left+" \"%25\" ))))\n";
		clauses="p1b"+count +" ";
		if (negate)
			this.assertion.add("\n(assert "+clauses+"  )\n");
		else
			ret+="\n(assert "+clauses+"  )\n";


		ret+="(assert (= p1b"+(++count) + " (= "+filterString(f1.getRightOp())+" (Replace t_url_"+(c+2)+" \"%22\" \"\\\"\"))))\n";
		clauses="p1b"+(4+co) +" ";
		/* if (negate)
		          	this.assertion.add("\n(assert "+clauses+"  )\n");
		          else
				 ret+="\n(assert "+clauses+")\n";
		 */
		count++;
		ret+="(assert (= p1b"+count + " (not (Contains "+left+" \"%22\" ))))\n";
		clauses="p1b"+count +" ";
		if (negate)
			this.assertion.add("\n(assert "+clauses+"  )\n");
		else
			ret+="\n(assert "+clauses+"  )\n";


		c=c+4;

		ret+=translateASTAssignFormula(left , f1.getRightOp());

		return ret;
	}




	private String translateHtmlspecialcharsFormula(Formula form) {
		String ret= "", clauses, left = filterString(form.getLeftOp().get(0));
		int co=++count;
		if(form.getLeftOp().size()==1){
			ret+="(declare-variable t_htmls_"+c+" String)\n(declare-variable t_htmls_"+(c+1)+" String)\n"
					+ "(declare-variable t_htmls_"+(c+2)+" String)\n";//(declare-variable t_htmls_"+(c+3)+" String)\n";

			ret+="(assert (= p1b"+(count) + " (not (Contains "+left+" \"&\" ))))\n";
			clauses="p1b"+(co) +" ";
			if (negate)
				this.assertion.add("\n(assert "+clauses+"  )\n");
			else
				ret+="\n(assert "+clauses+")\n";

			ret+="(assert (= p1b"+(++count) + " (not (Contains "+left+" \"\\\"\" ))))\n";
			clauses="p1b"+(co+1) +" ";
			if (negate)
				this.assertion.add("\n(assert "+clauses+"  )\n");
			else
				ret+="\n(assert "+clauses+")\n";


			ret+="(assert (= p1b"+(++count) + " (not (Contains "+left+" \"<\" ))))\n";
			clauses="p1b"+(co+2) +" ";
			if (negate)
				this.assertion.add("\n(assert "+clauses+"  )\n");
			else
				ret+="\n(assert "+clauses+")\n";


			ret+="(assert (= p1b"+(++count) + " (not (Contains "+left+" \">\" ))))\n";
			clauses="p1b"+(co+3) +" ";
			if (negate)
				this.assertion.add("\n(assert "+clauses+"  )\n");
			else
				ret+="\n(assert "+clauses+")\n";

			ret+="(assert (= p1b"+(++count) + " (= "+filterString(form.getRightOp())+" "+left+" )))\n";
			clauses="p1b"+(co+4) +" ";
			if (negate)
				this.assertion.add("\n(assert "+clauses+"  )\n");
			else
				ret+="\n(assert "+clauses+")\n";



			c=c+4;
		}
		else if(form.getLeftOp().size()==2){
			if(form.getLeftOp().get(1).equalsIgnoreCase("ENT_QUOTES")) { //ENT_QUOTES	Will convert both double and single quotes.
				ret+="(declare-variable t_htmls_"+c+" String)\n(declare-variable t_htmls_"+(c+1)+" String)\n"
						+ "(declare-variable t_htmls_"+(c+2)+" String)\n(declare-variable t_htmls_"+(c+3)+" String)\n";

				ret+="(assert (= p1b"+(count) + " (not (Contains "+left+" \"&\" ))))\n";
				clauses="p1b"+(co) +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+")\n";


				ret+="(assert (= p1b"+(++count) + " (not (Contains "+left+" \"\\\"\" ))))\n";
				clauses="p1b"+(co+1) +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+")\n";


				ret+="(assert (= p1b"+(++count) + " (not (Contains "+left+" \"<\" ))))\n";
				clauses="p1b"+(co+2) +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+")\n";

				; 
				ret+="(assert (= p1b"+(++count) + " (not (Contains "+left+" \"\\\'\" ))))\n";
				clauses="p1b"+(co+3) +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+")\n";


				ret+="(assert (= p1b"+(++count) + " (not (Contains "+left+" \">\" ))))\n";
				clauses="p1b"+(co+4) +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+")\n";

				ret+="(assert (= p1b"+(++count) + " (= "+ filterString(form.getRightOp())+" "+left+" )))\n";
				clauses="p1b"+(co+5) +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+")\n";

				//

				c=c+5;
			}
			else if(form.getLeftOp().get(1).equalsIgnoreCase("ENT_NOQUOTES")){ //ENT_NOQUOTES	Will leave both double and single quotes unconverted.
				ret+="(declare-variable t_htmls_"+c+" String)\n(declare-variable t_htmls_"+(c+1)+" String)\n";

				ret+="(assert (= p1b"+(count) + " (not (Contains t_htmls_"+(c)+" \"&\" ))))\n";
				clauses="p1b"+(co) +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+")\n";



				ret+="(assert (= p1b"+(++count) + " (not (Contains t_htmls_"+(c+1)+" \"<\" ))))\n";
				clauses="p1b"+(co+1) +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+")\n";


				ret+="(assert (= p1b"+(++count) + " (not (Contains "+left+" \">\" ))))\n";
				clauses="p1b"+(co+2) +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+")\n";

				ret+="(assert (= p1b"+(++count) + " (= "+left+" "+filterString(form.getRightOp()) +")))\n";
				clauses="p1b"+(co+3) +" ";
				if (negate)
					this.assertion.add("\n(assert "+clauses+"  )\n");
				else
					ret+="\n(assert "+clauses+")\n";

				//
				c=c+3;	 
			}
		}

		return ret;
	}


	// e.g. Formula [leftOp=[$_GET[mode]], rightOp=, operator AST_ISSET, returnValue , formula type AST_ISSET, id 58]

	private String translateIssetFormula(Formula f1) {
		String ret="";
		count++;
		ret+="(assert (= p1b"+count +" (> (Length "+ filterString(f1.getLeftOp().get(0))+" ) 0))) \n";
		if (negate)
			this.assertion.add("\n(assert p1b"+count+" )\n");
		else
			ret+="\n(assert p1b"+count+" )\n";
		return ret;
	}

	//formula Formula [leftOp=[$mode], rightOp=$temp_67, operator AST_ASSIGN, returnValue , formula type AST_ASSIGN, id 64]
	private String translateASTAssignFormula(Formula form) {
		String ret="";
		count++;

		if(!(form.getRightOp().isEmpty())){
			if(form.getRightOp().startsWith("'") ||form.getRightOp().startsWith("\"")
					){
				ret+="(assert (= p1b"+count +" (= "+ filterString(form.getLeftOp().get(0))+" "+ form.getRightOp()+" ))) \n";
				if (negate)
					this.assertion.add("\n(assert p1b"+count+" )\n");
				else
					ret+="\n(assert p1b"+count +" )\n";
			}

			else if (form.getRightOp().startsWith("$")){
				ret+="(assert (= p1b"+count +" (= "+ filterString(form.getLeftOp().get(0))+" "+ filterString(form.getRightOp())+" ))) \n";
				if (negate)
					this.assertion.add("\n(assert p1b"+count+" )\n");
				else
					ret+="\n(assert p1b"+count +" )\n";
			}
			else {
				ret+="(assert (= p1b"+count +" (= "+filterString(form.getLeftOp().get(0))+ " \""+  filterString(form.getRightOp())+"\" ))) \n";
				if (negate)
					this.assertion.add("\n(assert p1b"+count+" )\n");
				else
					ret+="\n(assert p1b"+count+"  )\n";
			}



		}
		else if((form.getRightOp().isEmpty())){
			ret+="(assert (= p1b"+count +" (= "+ filterString(form.getLeftOp().get(0))+" "+ "\"\" ))) \n";
			if (negate)
				this.assertion.add("\n(assert p1b"+count+" )\n");
			else
				ret+="\n(assert p1b"+count +" )\n";
		}



		return ret;
	}

	private String translateASTAssignFormula(String left, String right) {
		String ret="";
		count++;

		if(!(right.isEmpty())){
			if(right.startsWith("'") ||right.startsWith("\"")
					){
				//||right.startsWith("$") || right.startsWith("_") 
				ret+="(assert (= p1b"+count +" (= "+ filterString(left)+" "+ right+" ))) \n";
				if (negate)
					this.assertion.add("\n(assert p1b"+count+" )\n");
				else
					ret+="\n(assert p1b"+count +" )\n";
			}

			else if (right.startsWith("$")){
				ret+="(assert (= p1b"+count +" (= "+ filterString(left)+" "+ filterString(right)+" ))) \n";
				if (negate)
					this.assertion.add("\n(assert p1b"+count+" )\n");
				else
					ret+="\n(assert p1b"+count +" )\n";
			}
			else {
				ret+="(assert (= p1b"+count +" (= "+filterString(left)+ " \""+  filterString(right)+"\" ))) \n";
				if (negate)
					this.assertion.add("\n(assert p1b"+count+" )\n");
				else
					ret+="\n(assert p1b"+count+"  )\n";
			}



		}
		else if((right.isEmpty())){
			ret+="(assert (= p1b"+count +" (= "+ filterString(left)+" "+ "\"\" ))) \n";
			if (negate)
				this.assertion.add("\n(assert p1b"+count+" )\n");
			else
				ret+="\n(assert p1b"+count +" )\n";
		}



		return ret;
	}

	/*e.g.: Formula
	 *  [u'left: [$HTTP_POST_VARS[prefix], ""], right: $table_prefix, op: ?, type: AST_ASSIGN, node_id: 11209']]}
      left =  child0 ? child 1: child 2
      we will translate it as left = child1 OR left - child2
	 */
	private String translateASTConditional(Formula form) {
		String ret="", clauses;
		count++;

		String right = filterString(form.getRightOp());

		if(!(form.getLeftOp().isEmpty()) && form.getLeftOp().size() > 1){
			ret+="(assert (= p1b"+count + " (or  ";
			for(String left : form.getLeftOp()){
				if (checkNotConstString(left))
					ret+="(= "+right+" "+ filterString(left)+" )";
				else if (left.startsWith("'") && left.endsWith("'") ||
						(left.startsWith("\"") && left.endsWith("\""))) 
					ret+="(= "+right+" "+ left+" )";
				else 
					ret+="(= "+right+" \""+ left+"\" )";
			}
			ret+=" )) )\n";
			clauses="p1b"+count;

			if (negate)
				this.assertion.add("\n(assert "+clauses+"  )\n");
			else 
				ret+="\n(assert "+clauses+"  )\n";
		}

		return ret;
	}


	//formula for select or radio buttons
	private String translateORFormula(Formula form) {
		String ret="", clauses="";
		String right = filterString(form.getRightOp());

		if(!(form.getLeftOp().isEmpty()) && form.getLeftOp().size() > 1){
			ret+="(assert (= p1b"+count + " (or  ";
			for(String left : form.getLeftOp()){
				ret+="(= "+right+" \""+ left+"\" )";
			}
			ret+=" )) )\n";
			clauses="p1b"+count +" ";
			ret+="\n(assert "+clauses+" )\n";
		}
		//or but has only one option
		else if (form.getLeftOp().size() == 1){
			ret+="(assert (= p1b"+count +  " ";
			for(String left : form.getLeftOp()){
				ret+="(= "+right+" \""+ left+"\" )";
			}
			ret+=" ) )\n";
			clauses="p1b"+count +" ";
			ret+="\n(assert "+clauses+" )\n";
		}

		return ret;
	}


	private String translateAssignFormula(Formula form) {
		String ret="", clauses="";
		String left = filterString(form.getLeftOp().get(0));

		if( !(form.getRightOp().isEmpty())){
			ret+="(assert (= p1b"+count +" (= "+ left+" "+ form.getRightOp()+" ))) \n";
			clauses="p1b"+count +" ";
			ret+="\n(assert "+clauses+" )\n";


		}
		else if( (form.getRightOp().isEmpty())){
			ret+="(assert (= p1b"+count +" (= "+ left+" "+ "\"\" ))) \n";
			clauses="p1b"+count +" ";
			ret+="\n(assert "+clauses+" )\n";


		}

		return ret;
	}

	private String translateMaxLenFormula(Formula form) {
		String ret="", clauses="";
		String left = filterString(form.getLeftOp().get(0));
		String op = form.getOperator();
		if (op.equals("maxlen")){
			if(!(form.getRightOp().isEmpty())){
				ret+="(assert (= p1b"+(count) + " (<= (Length "+left+" ) "+form.getRightOp() +" )) )\n";
				clauses="p1b"+count +" ";
				ret+="\n(assert "+clauses+" )\n";
			}
		}
		else if (op.equals("minlen")){
			if(!(form.getRightOp().isEmpty())){
				String r = form.getRightOp().replace("\"", "");
				ret+="(assert (= p1b"+(count) + " (> (Length "+left+" ) "+r +" )) )\n";
				clauses="p1b"+count +" ";
				ret+="\n(assert "+clauses+" )\n";
			}
		}

		return ret;
	}


	private String stripTags(Formula form, int c, int co) {

		String ret="";
		int count=co;
		String str="";
		if(form.getLeftOp().get(1).contains("<"))
		{
			if(form.getLeftOp().get(1).startsWith("\"") && form.getLeftOp().get(1).endsWith("\"") )
				str=form.getLeftOp().get(1);
			else 
				str="\""+form.getLeftOp().get(1)+"\"";

		}
		else 
			str=filterString(form.getLeftOp().get(1));

		ret+="(declare-variable allowedTags String)\n";
		ret+="(declare-variable t_stripTags_"+c+" String)\n";
		ret+="(declare-variable t_stripTags_"+(c+1)+" String)\n";
		ret+="(declare-variable t_stripTags_"+(c+2)+" String)\n(declare-variable t_stripTags_"+(c+3)+" String)\n(declare-variable t_stripTags_"+(c+4)+" String)\n"
				+ "(declare-variable t_stripTags_"+(c+5)+" String)\n(declare-variable t_stripTags_"+(c+6)+" String)\n(declare-variable t_stripTags_"+(c+7)+" String)\n"
				+ "(declare-variable t_stripTags_"+(c+8)+" String)\n(declare-variable t_stripTags_"+(c+9)+" String)\n(declare-variable t_stripTags_"+(c+10)+" String)\n"
				+ "(declare-variable t_stripTags_"+(c+11)+" String)\n";
		ret+="(declare-variable ret_stripTags_"+c+" String)\n";
		ret+="(declare-variable ret_stripTags_"+(c+1)+" String)\n";
		ret+="(declare-variable ret_stripTags_"+(c+2)+" String)\n(declare-variable ret_stripTags_"+(c+3)+" String)\n(declare-variable ret_stripTags_"+(c+4)+" String)\n"
				+ "(declare-variable ret_stripTags_"+(c+5)+" String)\n(declare-variable ret_stripTags_"+(c+6)+" String)\n(declare-variable ret_stripTags_"+(c+7)+" String)\n"
				+ "(declare-variable ret_stripTags_"+(c+8)+" String)\n(declare-variable ret_stripTags_"+(c+9)+" String)\n(declare-variable ret_stripTags_"+(c+10)+" String)\n"
				+ "(declare-variable ret_stripTags_"+(c+11)+" String)\n";

		ret+="(assert (= p1b"+count+" (= allowedTags "+str +" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+co +") \n");
		else
			ret+="(assert p1b"+co +") \n";
		ret+="(assert (= p1b"+(++count)+" (= t_stripTags_"+c+ " \"<script>\" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(1+co) +") \n");
		else
			ret+="(assert p1b"+(1+co) +") \n";
		ret+="(assert (= p1b"+(++count)+" (= t_stripTags_"+(c+1)+ " \"</script>\" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(2+co) +") \n");
		else
			ret+="(assert p1b"+(2+co) +") \n";
		ret+="(assert (= p1b"+(++count)+" (= t_stripTags_"+(c+2)+ " \"<div>\" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(3+co) +") \n");
		else
			ret+="(assert p1b"+(3+co) +") \n";
		ret+="(assert (= p1b"+(++count)+" (= t_stripTags_"+(c+3)+ " \"</div>\" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(4+co) +") \n");
		else
			ret+="(assert p1b"+(4+co) +") \n";
		ret+="(assert (= p1b"+(++count)+" (= t_stripTags_"+(c+4)+ " \"<span>\" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(5+co) +") \n");
		else
			ret+="(assert p1b"+(5+co) +") \n";
		ret+="(assert (= p1b"+(++count)+" (= t_stripTags_"+(c+5)+ " \"</span>\" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(6+co) +") \n");
		else
			ret+="(assert p1b"+(6+co) +") \n";
		ret+="(assert (= p1b"+(++count)+" (= t_stripTags_"+(c+6)+ " \"<img>\" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(7+co) +") \n");
		else
			ret+="(assert p1b"+(7+co) +") \n";
		ret+="(assert (= p1b"+(++count)+" (= t_stripTags_"+(c+7)+ " \"</img>\" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(8+co) +") \n");
		else
			ret+="(assert p1b"+(8+co) +") \n";
		ret+="(assert (= p1b"+(++count)+" (= t_stripTags_"+(c+8)+ " \"<a>\" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(9+co) +") \n");
		else
			ret+="(assert p1b"+(9+co) +") \n";
		ret+="(assert (= p1b"+(++count)+" (= t_stripTags_"+(c+9)+ " \"</a>\" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(10+co) +") \n");
		else
			ret+="(assert p1b"+(10+co) +") \n";
		ret+="(assert (= p1b"+(++count)+" (= t_stripTags_"+(c+10)+ " \"<p>\" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(11+co) +") \n");
		else
			ret+="(assert p1b"+(11+co) +") \n";
		ret+="(assert (= p1b"+(++count)+" (= t_stripTags_"+(c+11)+ " \"</p>\" )))\n";
		if (negate)
			this.assertion.add("(assert p1b"+(12+co) +") \n");
		else
			ret+="(assert p1b"+(12+co) +") \n";

		ret+="(assert (= p1b"+(++count)+" (Contains allowedTags t_stripTags_"+(c)+ " )))\n";
		ret+="(assert (ite p1b"+(count)+" (= ret_stripTags_"+c+" t_stripTags_"+c+") (= ret_stripTags_"+c+" (Replace "+filterString(form.getLeftOp().get(0))+" t_stripTags_"+c+ " \"\" )) ))\n";

		//}
		ret+="(assert (= p1b"+(++count)+" (Contains allowedTags t_stripTags_"+(c+1)+ " )))\n";
		ret+="(assert (ite p1b"+(count)+" (= ret_stripTags_"+(c+1)+" ret_stripTags_"+c+") (= ret_stripTags_"+(c+1)+" (Replace ret_stripTags_"+c+ " t_stripTags_"+(c+1)+ " \"\" )) ))\n";

		ret+="(assert (= p1b"+(++count)+" (Contains allowedTags t_stripTags_"+(c+2)+ " )))\n";
		ret+="(assert (ite p1b"+(count)+" (= ret_stripTags_"+(c+2)+" ret_stripTags_"+(c+1)+") (= ret_stripTags_"+(c+2)+" (Replace ret_stripTags_"+(c+1)+ " t_stripTags_"+(c+2)+ " \"\" )) ))\n";

		ret+="(assert (= p1b"+(++count)+" (Contains allowedTags t_stripTags_"+(c+3)+ " )))\n";
		ret+="(assert (ite p1b"+(count)+" (= ret_stripTags_"+(c+3)+" ret_stripTags_"+(c+2)+") (= ret_stripTags_"+(c+3)+" (Replace ret_stripTags_"+(c+2)+ " t_stripTags_"+(c+3)+ " \"\" )) ))\n";

		ret+="(assert (= p1b"+(++count)+" (Contains allowedTags t_stripTags_"+(c+4)+ " )))\n";
		ret+="(assert (ite p1b"+(count)+" (= ret_stripTags_"+(c+4)+" ret_stripTags_"+(c+3)+") (= ret_stripTags_"+(c+4)+" (Replace ret_stripTags_"+(c+3)+ " t_stripTags_"+(c+4)+ " \"\" )) ))\n";

		ret+="(assert (= p1b"+(++count)+" (Contains allowedTags t_stripTags_"+(c+5)+ " )))\n";
		ret+="(assert (ite p1b"+(count)+" (= ret_stripTags_"+(c+5)+" ret_stripTags_"+(c+4)+") (= ret_stripTags_"+(c+5)+" (Replace ret_stripTags_"+(c+4)+ " t_stripTags_"+(c+5)+ " \"\" )) ))\n";

		ret+="(assert (= p1b"+(++count)+" (Contains allowedTags t_stripTags_"+(c+6)+ " )))\n";
		ret+="(assert (ite p1b"+(count)+" (= ret_stripTags_"+(c+6)+" ret_stripTags_"+(c+5)+") (= ret_stripTags_"+(c+6)+" (Replace ret_stripTags_"+(c+5)+ " t_stripTags_"+(c+6)+ " \"\" )) ))\n";

		ret+="(assert (= p1b"+(++count)+" (Contains allowedTags t_stripTags_"+(c+7)+ " )))\n";
		ret+="(assert (ite p1b"+(count)+" (= ret_stripTags_"+(c+7)+" ret_stripTags_"+(c+6)+") (= ret_stripTags_"+(c+7)+" (Replace ret_stripTags_"+(c+6)+ " t_stripTags_"+(c+7)+ " \"\" )) ))\n";

		ret+="(assert (= p1b"+(++count)+" (Contains allowedTags t_stripTags_"+(c+8)+ " )))\n";
		ret+="(assert (ite p1b"+(count)+" (= ret_stripTags_"+(c+8)+" ret_stripTags_"+(c+7)+") (= ret_stripTags_"+(c+8)+" (Replace ret_stripTags_"+(c+7)+ " t_stripTags_"+(c+8)+ " \"\" )) ))\n";

		ret+="(assert (= p1b"+(++count)+" (Contains allowedTags t_stripTags_"+(c+9)+ " )))\n";
		ret+="(assert (ite p1b"+(count)+" (= ret_stripTags_"+(c+9)+" ret_stripTags_"+(c+8)+") (= ret_stripTags_"+(c+9)+" (Replace ret_stripTags_"+(c+8)+ " t_stripTags_"+(c+9)+ " \"\" )) ))\n";

		ret+="(assert (= p1b"+(++count)+" (Contains allowedTags t_stripTags_"+(c+10)+ " )))\n";
		ret+="(assert (ite p1b"+(count)+" (= ret_stripTags_"+(c+10)+" ret_stripTags_"+(c+9)+") (= ret_stripTags_"+(c+10)+" (Replace ret_stripTags_"+(c+9)+ " t_stripTags_"+(c+10)+ " \"\" )) ))\n";

		ret+="(assert (= p1b"+(++count)+" (Contains allowedTags t_stripTags_"+(c+11)+ " )))\n";
		ret+="(assert (ite p1b"+(count)+" (= "+ filterString(form.getRightOp())+" ret_stripTags_"+(c+10)+") (= "+filterString(form.getRightOp())+" (Replace ret_stripTags_"+(c+10)+ " t_stripTags_"+(c+11)+ " \"\" )) ))\n";


		return ret;
	}


	private String filterString(String string) {
		string = string.replace("[", "_").replace("]", "").replace(" ", "_").
				replace("{", "").replace("}", "").trim();

		return string;
	}

	private boolean checkNotConstString(String str) {
		// returns true if the string is a variable (starts with $ or _)
		if(str.startsWith("$") || str.startsWith("_") ){
			return true;
		}
		else if (str.startsWith("'") && str.endsWith("'") ||
				(str.startsWith("\"") && str.endsWith("\"")))
			return false ;

		return false;
	}
}