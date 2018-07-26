/**
 * @author Abeer Alhuzali
 * 
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */
package navex.formula;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import org.htmlparser.tags.FormTag;

import navex.HTMLForm;
import navex.solver.Solver;


public class TraceAnalysis {

	
	public static String start(Trace t, HTMLForm form){
		
		HashSet<Formula> newC = preprocessClientFormula(t.getClientFormula(), form);
		t.setNewClientFormula(newC);
		
		HashSet<Formula> combinedFormulas =  new HashSet<Formula>();
		combinedFormulas.addAll(newC);
		combinedFormulas.addAll(t.serverFormula);
		
		
		
		Solver solver = new Solver(combinedFormulas);
		Solver.setNegate(true);
		String spec = solver.prepareSolver();
		Solver.setNegate(false);
		return spec;
		
	}

	/*
	 * 1- all form input tags should be augmented with get or post based on the 
	 * form method.
	 * 2- re-create a new client side formula set
	 */
	private static HashSet<Formula> preprocessClientFormula(HashSet<Formula> clientFormula,
												HTMLForm form) {
		
		FormTag ft = (FormTag)form.getForm();
		
		
		HashSet<Formula> newClientFormula = new HashSet<Formula>();
		
		if (ft.getFormMethod() != null){
			String method = ft.getFormMethod().toUpperCase();
			method = "$_".concat(method)+"[";
			for (Formula cf :clientFormula){
				Formula newF= new Formula (cf);
				if (cf.getOperator().equalsIgnoreCase("=") || 
						cf.getOperator().equalsIgnoreCase("maxlen") ||
						cf.getOperator().equalsIgnoreCase("minlen")){
					//create a new formula from the old one
			
					String newLeft = cf.getLeftOp().get(0);
					newLeft = method+newLeft.concat("]");
					ArrayList<String> leftOp = new ArrayList<String>();
					leftOp.add(newLeft);
					newF.setLeftOp(leftOp);
					newClientFormula.add(newF);
				}
				//we should update the right
				else if (cf.getOperator().equalsIgnoreCase("or")){
					
					String newRight = cf.getRightOp();
					newRight = method+newRight.concat("]");
					
					newF.setRightOp(newRight);
					newClientFormula.add(newF);
				}
			}
		 }
		//we add a formula from the action 
		if (ft.getFormLocation() != null){
			String action = ft.getFormLocation();
			
			if (action.contains("?")){
				HashMap <String, String> varval = new HashMap <String, String>();
				String lastPart = action.substring(action.indexOf("?")+1);
				String[] args = lastPart.split("&");
				for (String part : args){
					String[] p = part.split("=");
					ArrayList<String> temp = new ArrayList<String>();
					temp.add(p[0].trim());
					Formula newF= new Formula (temp,"\""+p[1].trim()+"\"", "=", "FORM",  "FORM");
					newClientFormula.add(newF);
				}
			}
			
		}
		
	  return newClientFormula ;	
	}
}
