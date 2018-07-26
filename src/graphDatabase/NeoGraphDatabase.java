/**
 * 
 */
package navex.graphDatabase;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import javax.ws.rs.core.MediaType;

import org.apache.http.NameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;

import navex.HTMLForm;
import edu.uci.ics.crawler4j.crawler.Page;
import edu.uci.ics.crawler4j.url.WebURL;


/**
 * @author Abeer Alhuzali
 *  * this is the implementation of creating the navigation graph (a neo4j graph database) using Jason.
 *
 */
public class NeoGraphDatabase {

	protected final static Logger logger = LoggerFactory.getLogger(NeoGraphDatabase.class);
	private static final String SERVER_ROOT_URI = "http://localhost:7474/db/data/";

	HashSet<NavigationDatabaseNode> nodes ;//= new HashSet<URI>();
	HashMap<URI, NavigationDatabaseNode> navNodes ;//= new HashMap<>();
	HashMap<String, URI> urlUriMap ;//= new HashMap<>();



	public NeoGraphDatabase() {
		super();
		nodes = new HashSet<NavigationDatabaseNode>();
		navNodes = new HashMap<>();
		urlUriMap = new HashMap<String, URI>();
	}

	// START SNIPPET: createReltype
	private static enum RelTypes 
	{
		HAS_A_LINK_TO, HAS_A_FORM_TO;
	}
	// END SNIPPET: createReltype

	/**
	 * @param page
	 * @param form 
	 * @param type: either form or link 
	 * @param params : for post request in forms , if it is a link, then it will be null
	 * @param smethod : either get or post
	 */
	public void StartNeoDb(Page page, HTMLForm form, String type, List<NameValuePair> params, String method) 
	{
		checkDatabaseIsRunning();

		if (type == "link"){
			createDbforLink(page);
		}
		else if (type == "form") {
			createDbforForm(page ,form , params, method);
		}


	}


	private void createDbforForm(Page page, HTMLForm form, List<NameValuePair> params, 
			String method) {
		//creating source node
		String url = page.getWebURL().getURL();
		URI nodeUri = null;

		if (this.urlUriMap.containsKey(url) )
		{
			nodeUri = this.urlUriMap.get(url);
		}

		//creating dest node
		NavigationDatabaseNode ndn= new NavigationDatabaseNode (page, form, params, method);
		URI dest = createNode();

		this.nodes.add(ndn);
		this.navNodes.put(dest, ndn);
		this.urlUriMap.put(ndn.getUrl(), dest);

		try {
			addNavigationNodePropertyForm(ndn, dest);
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			addRelationship(nodeUri, dest, "HAS_A_FORM_TO" );
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}



	}


	private void createDbforLink(Page page) {
		NavigationDatabaseNode ndn = NavigationDatabaseNode.findNode(this.nodes, page.getWebURL().getURL());
		URI firstNode ; 
		if ( ndn != null){
			System.out.println("found the navigation node in DB "+ndn.getUrl());
			for (Entry<URI, NavigationDatabaseNode> map : this.navNodes.entrySet()){
				if (map.getValue().equals(ndn))
				{firstNode = map.getKey();
				System.out.println("used an already created node ndn is"+ ndn.toString());
				try {
					addNavigationNodeProperty(ndn, firstNode);
				} catch (URISyntaxException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				}
			}
		}
		else {

			System.out.println("Did Not find the navigation node in DB ");

			ndn= new NavigationDatabaseNode (page);


			ndn.initialize(page);

			// START SNIPPET: nodesAndProps
			firstNode = createNode();

			this.nodes.add(ndn);
			this.navNodes.put(firstNode, ndn);
			this.urlUriMap.put(ndn.getUrl(), firstNode);

			try {
				addNavigationNodeProperty(ndn, firstNode);
			} catch (URISyntaxException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}




	private static URI createNode()
	{
		// START SNIPPET: createNode
		final String nodeEntryPointUri = SERVER_ROOT_URI + "node";
		// http://localhost:7474/db/data/node

		WebResource resource = Client.create()
				.resource( nodeEntryPointUri );
		// POST {} to the node entry point URI
		ClientResponse response = resource.accept( MediaType.APPLICATION_JSON )
				.type( MediaType.APPLICATION_JSON )
				.entity( "{}" )
				.post( ClientResponse.class );

		final URI location = response.getLocation();
		System.out.println( String.format(
				"POST to [%s], status code [%d], location header [%s]",
				nodeEntryPointUri, response.getStatus(), location.toString() ) );
		response.close();

		return location;
		// END SNIPPET: createNode
	}


	public static void addNavigationNodeProperty(NavigationDatabaseNode ndn, URI nodeUri) throws URISyntaxException {


		Map<String, Object> properties = ndn.createProperties();

		for (Entry<String, Object> map :properties.entrySet()){
			if (map.getKey()!= null && map.getValue() != null)
			{ addProperty(nodeUri, map.getKey(), map.getValue().toString());
			}

		}
		addLable(nodeUri);
	}

	private void addNavigationNodePropertyForm(NavigationDatabaseNode ndn, URI dest) throws URISyntaxException {
		Map<String, Object> properties = ndn.createPropertiesForms();

		for (Entry<String, Object> map :properties.entrySet()){
			if (map.getKey()!= null && map.getValue() != null)
			{ addProperty(dest, map.getKey(), map.getValue().toString());
			}

		}
		addLable(dest);
	}

	private static void addLable(URI nodeUri) throws URISyntaxException {

		// START SNIPPET: addlable
		URI Uri = new URI( nodeUri.toString() + "/labels");
		// e.g : http://localhost:7474/db/data/node/59/labels

		WebResource resource = Client.create()
				.resource( Uri );
		ClientResponse response = resource.accept( MediaType.APPLICATION_JSON )
				.type( MediaType.APPLICATION_JSON )
				.entity( "\"Dynamic\"" )
				.post( ClientResponse.class );

		System.out.println( String.format( "PUT to [%s], status code [%d]",
				Uri, response.getStatus() ) );
		response.close();
		// END SNIPPET: addlable

	}


	private static void addProperty( URI nodeUri, String propertyName,
			String propertyValue )
	{
		// START SNIPPET: addProp
		String propertyUri = nodeUri.toString() + "/properties/" + propertyName;
		// http://localhost:7474/db/data/node/{node_id}/properties/{property_name}

		WebResource resource = Client.create()
				.resource( propertyUri );
		ClientResponse response = resource.accept( MediaType.APPLICATION_JSON )
				.type( MediaType.APPLICATION_JSON )
				.entity( "\"" + propertyValue + "\"" )
				.put( ClientResponse.class );

		System.out.println( String.format( "PUT to [%s], status code [%d]",
				propertyUri, response.getStatus() ) );
		response.close();
		// END SNIPPET: addProp
	}




	public void addLinksStart() {
		logger.info("adding links to Neo4j graph database nodes  ");

		for (Entry<URI, NavigationDatabaseNode> map : this.navNodes.entrySet()){
			// System.out.println("nav map uri"+map.getKey()+"---"+map.getValue().getUrl());
			if (map.getValue().getOutLinks() != null ){
				for(WebURL wu :map.getValue().getOutLinks()){
					String u = wu.getURL();
					//System.out.println("Trying to link parent"+map.getValue().getUrl());
					//System.out.println("   with out going url " + u);
					NavigationDatabaseNode tmp = NavigationDatabaseNode.findNode(this.nodes, u);
					if (tmp != null){
						URI childNode = findURI((String)tmp.getUrl());

						if (childNode != null){
							try {
								addRelationship(map.getKey(), childNode, "HAS_A_LINK_TO" );
							} catch (URISyntaxException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
						else 
							logger.debug("Could not link the two nodes because parent could not be found!!!!!!!");
					}
				}
			}
		}
	}	


	private URI findURI(String url) {
		for (Entry<URI, NavigationDatabaseNode> map : this.navNodes.entrySet()){
			//Abeer : casting to string is important, otherwise, the condition will never 
			//be satisfied
			if (((String)map.getValue().getUrl()).equals(url))
				return map.getKey();

		}
		return null;
	}



	// START SNIPPET: insideAddRel
	private  URI addRelationship( URI startNode, URI endNode,
			String relationshipType )
					throws URISyntaxException
	{
		URI fromUri = new URI( startNode.toString() + "/relationships" );
		String relationshipJson = generateJsonRelationship( endNode,
				relationshipType);

		WebResource resource = Client.create()
				.resource( fromUri );
		// POST JSON to the relationships URI
		ClientResponse response = resource.accept( MediaType.APPLICATION_JSON )
				.type( MediaType.APPLICATION_JSON )
				.entity( relationshipJson )
				.post( ClientResponse.class );

		final URI location = response.getLocation();
		System.out.println( String.format(
				"POST to [%s], status code [%d], location header [%s]",
				fromUri, response.getStatus(), location.toString() ) );

		response.close();
		return location;
	}
	// END SNIPPET: insideAddRel

	private  String generateJsonRelationship( URI endNode,
			String relationshipType )
	{
		StringBuilder sb = new StringBuilder();
		sb.append( "{ \"to\" : \"" );
		sb.append( endNode.toString() );
		sb.append( "\", " );

		sb.append( "\"type\" : \"" );
		sb.append( relationshipType );
		sb.append( "\"" );

		sb.append( " }" );
		return sb.toString();
	}




	private static void checkDatabaseIsRunning()
	{
		// START SNIPPET: checkServer
		WebResource resource = Client.create()
				.resource( SERVER_ROOT_URI );
		ClientResponse response = resource.get( ClientResponse.class );

		System.out.println( String.format( "GET on [%s], status code [%d]",
				SERVER_ROOT_URI, response.getStatus() ) );
		response.close();
		// END SNIPPET: checkServer
	}


}
