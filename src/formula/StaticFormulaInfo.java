/**
 * @author Abeer Alhuzali
 * This class represents the TAC formula 
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */
package navex.formula;

import java.util.HashSet;

public class StaticFormulaInfo {

	HashSet<Formula> formula;
	String file ;
	String lineno ;
	String node_id ;
	private String sinkType;
	private String unique_id;

	public String getSinkType() {
		return sinkType;
	}

	public void setSinkType(String sinkType) {
		this.sinkType = sinkType;
	}

	public HashSet<Formula> getFormula() {
		return formula;
	}

	public void setFormula(HashSet<Formula> formula) {
		this.formula = formula;
	}

	public String getFile() {
		return file;
	}

	public void setFile(String file) {
		this.file = file;
	}

	public String getLineno() {
		return lineno;
	}

	public void setLineno(String lineno) {
		this.lineno = lineno;
	}

	public String getNode_id() {
		return node_id;
	}

	public void setNode_id(String node_id) {
		this.node_id = node_id;
	}

	public StaticFormulaInfo() {
		HashSet<Formula> formula = new HashSet<Formula> ();
	}

	@Override
	public String toString() {
		String str = "StaticFormulaInfo [file=" + file + ", lineno=" + lineno + ", node_id="
				+ node_id + ", sinkType=" + sinkType +", unique_id=" + unique_id+"]";
		str+="\t\t\tformula=" ;
		if (this.getFormula() != null)
			for (Formula f :this.getFormula())
				str+=f.toString();
		return str;
	}

	public String getUnique_id() {
		return unique_id;
	}

	public void setUnique_id(String unique_id) {
		this.unique_id = unique_id;
	}

	public StaticFormulaInfo(String file, String lineno, String node_id, String sinkType, String uniqueid, HashSet<Formula> formula) {
		super();
		this.file = file;
		this.lineno = lineno;
		this.node_id = node_id;
		this.sinkType = sinkType; //e.g: sql or xss
		this.unique_id = uniqueid;
		this.formula = formula;
	}

}
