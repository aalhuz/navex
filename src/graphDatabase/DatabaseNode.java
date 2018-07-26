/**
 * @author Abeer Alhuzali
 * Navigation Graph Nodes
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */
package navex.graphDatabase;

import java.util.Map;


public abstract class DatabaseNode {

	abstract public void initialize(Object obj);

	abstract public Map<String, Object> createProperties();
	abstract public Map<String, Object> createPropertiesForms();
}
