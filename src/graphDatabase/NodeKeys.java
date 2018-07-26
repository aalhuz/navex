/**
 * @author Abeer Alhuzali
 * Navigation Graph Nodes
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */
package navex.graphDatabase;

import java.util.List;

import org.apache.http.NameValuePair;

public class NodeKeys
{

	public static final String NODE_TYPE = "type";
	public static final String ID = "id";
	
	public static final String URL = "url";
	public static final String PARENT = "parent";
	public static final String DOMAIN = "domain"; //e.g., Domain: 'localhost'
	public static final String PATH =  "path"; 
	public static final String FORMS ="forms";
   //Number of outgoing links
	public static final String LINKS = "links";
	//role of the authenticated user (e.g., admin, normal user, etc.)
	public static final String ROLE = "role"; 
	public static final String PARAMS = "params";
	

	


	

}
