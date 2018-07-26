/**
 * @author Abeer Alhuzali
 * This class represents an execution trace 
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */
package navex.formula;

import java.util.HashSet;

public class Trace {
	HashSet<Formula> clientFormula ; //form formula
	HashSet<Formula> serverFormula ; //formula extracted form an execution trace
	
	HashSet<Formula> newClientFormula ; //form formula after modification
	HashSet<Formula> newServerFormula ; //formula extracted form an execution trace
	
	
	
	public Trace() {
		this.clientFormula = new HashSet<Formula>();
		this.serverFormula = new HashSet<Formula>();
		this.newClientFormula = new HashSet<Formula>();
		this.newServerFormula = new HashSet<Formula>();
	}
	
	public Trace(HashSet<Formula> clientFormula, HashSet<Formula> serverFormula) {
		super();
		this.clientFormula = clientFormula;
		this.serverFormula = serverFormula;
		this.newClientFormula = new HashSet<Formula>();
		this.newServerFormula = new HashSet<Formula>();
	}

	public HashSet<Formula> getClientFormula() {
		return clientFormula;
	}

	public void setClientFormula(HashSet<Formula> clientFormula) {
		this.clientFormula = clientFormula;
	}

	public HashSet<Formula> getServerFormula() {
		return serverFormula;
	}

	public void setServerFormula(HashSet<Formula> serverFormula) {
		this.serverFormula = serverFormula;
	}

	public void setNewClientFormula(HashSet<Formula> newC) {
		this.newClientFormula = newC;
		
	}
	
	
}
