/**
 * @author Abeer Alhuzali
 * This class represents the TAC formula 
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */
package navex.formula;

import java.util.ArrayList;
import java.util.HashSet;

public class Formula {

	public Formula() {
		this.leftOp=new ArrayList<String>();
		this.rightOp = "";
		this.operator = "";
		this.type="";
		this.returnVar="";
		this.ifCond="";
		this.id="";
		this.source ="";

	}

	ArrayList<String> leftOp;
	String rightOp;
	String operator;
	String type; //if the formula extracted from if-else or built in function , Form or Link
	String id; //used only in traversals
	String source; //to distinguish the source of the extracted formulas. e.g. either FORM or TRACE


	public String getSource() {
		return source;
	}

	public void setSource(String source) {
		this.source = source;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getReturnVar() {
		return returnVar;
	}

	public void setReturnVar(String returnVar) {
		this.returnVar = returnVar;
	}

	String returnVar; 
	String ifCond;

	public String getIfCond() {
		return ifCond;
	}

	public void setIfCond(String ifCond) {
		this.ifCond = ifCond;
	}


	public Formula(ArrayList<String> leftOp, String rightOp, String operator, String type, String source) {

		this.leftOp = leftOp;
		this.rightOp = rightOp;
		this.operator = operator;

		this.source=source;
		this.type=type;
		this.ifCond="";
	}



	public Formula(ArrayList<String> leftOp, String rightOp, String operator, String type) {

		this.leftOp = leftOp;
		this.rightOp = rightOp;
		this.operator = operator;
		this.type=type;
		this.returnVar="";
		this.ifCond="";


	}




	public Formula(Formula fm) {

		this(fm.leftOp, fm.rightOp, fm.operator, fm.type);
		this.id= fm.id;
		this.source=fm.source;
	}

	public ArrayList<String> getLeftOp() {
		return leftOp;
	}

	public void setLeftOp(ArrayList<String> leftOp) {
		this.leftOp = leftOp;
	}

	public String getRightOp() {
		return rightOp;
	}

	public void setRightOp(String rightOp) {
		this.rightOp = rightOp;
	}

	public String getOperator() {
		return operator;
	}

	public void setOperator(String operator) {
		this.operator = operator;
	}


	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = ((leftOp == null) ? 0 : leftOp.hashCode())
				+ ((rightOp == null) ? 0 : rightOp.hashCode())
				+ ((operator == null) ? 0 : operator.hashCode())
				+ ((returnVar == null) ? 0 : returnVar.hashCode())
				+ ((type == null) ? 0 : type.hashCode())
				+ ((source == null) ? 0 : source.hashCode())
				+ ((id == null) ? 0 : id.hashCode());
		return result;
	}

	@Override
	public boolean equals(final Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		final Formula other = (Formula) obj;
		if (leftOp == null) {
			if (other.leftOp != null)
				return false;
		} else if (!leftOp.equals(other.leftOp))
			return false;

		if (rightOp == null) {
			if (other.rightOp != null)
				return false;
		} else if (!rightOp.equals(other.rightOp))
			return false;

		if (operator == null) {
			if (other.operator != null)
				return false;
		} else if (!operator.equals(other.operator))
			return false;

		if (type == null) {
			if (other.type != null)
				return false;
		} else if (!type.equals(other.type))
			return false;

		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
			return false;

		if (returnVar == null) {
			if (other.returnVar != null)
				return false;
		} else if (!returnVar.equals(other.returnVar))
			return false;


		if (source == null) {
			if (other.source != null)
				return false;
		} else if (!source.equals(other.source))
			return false;

		return true;
	}

	@Override
	public String toString() {

		return "Formula [leftOp=" + leftOp + ", rightOp=" + rightOp
				+ ", operator " + operator + ", returnValue " + returnVar + ", formula type " + type +  ", id " + id +"]";
	}
	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String toStringUnary() {

		return "Formula [leftOp=" + leftOp + ", operator " + operator +
				rightOp + "= + rightOp"
				+"]";
	}

	//checks the leftop and rightop to get the super globals
	public HashSet<String> getSuperGlobals() {
		HashSet<String> ret= new HashSet<String>();
		if (this.getRightOp().trim().startsWith("$_GET")
				|| this.getRightOp().trim().startsWith("$_POST")
				|| this.getRightOp().trim().startsWith("$_REQUEST")
				|| this.getRightOp().trim().startsWith("$HTTP_POST_VARS")
				|| this.getRightOp().trim().startsWith("$HTTP_GET_VARS")

				)
			ret.add(this.getRightOp());
		else {
			for (String left : this.getLeftOp()){
				if (left.trim().startsWith("$_GET")
						|| left.trim().startsWith("$_POST")
						|| left.trim().startsWith("$_REQUEST")
						||  left.trim().startsWith("$HTTP_POST_VARS")
						||  left.trim().startsWith("$HTTP_GET_VARS")

						)
					ret.add(left);
			}
		}

		return ret;
	}

}
