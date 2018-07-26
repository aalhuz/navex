/**
 * 
 */
package navex.graphDatabase;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.apache.http.NameValuePair;
import org.htmlparser.tags.FormTag;
import org.neo4j.graphdb.Node;

import navex.HTMLForm;
import edu.uci.ics.crawler4j.crawler.CrawlConfig;
import edu.uci.ics.crawler4j.crawler.Page;
import edu.uci.ics.crawler4j.parser.HtmlParseData;
import edu.uci.ics.crawler4j.url.WebURL;
import navex.formula.Formula;

/**
 * @author Abeer Alhuzali
 * Navigation Graph Nodes
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */
public class NavigationDatabaseNode extends DatabaseNode{

	Node neo4jNode;

	public Node getNeo4jNode() {
		return neo4jNode;
	}

	Page node;
	public Page getNode() {
		return node;
	}

	public void setNode(Page node) {
		this.node = node;
	}

	HtmlParseData data;

	public HtmlParseData getData() {
		return data;
	}

	public void setData(HtmlParseData data) {
		this.data = data;
	}

	@Override
	public void initialize(Object n) {
		this.node = (Page) n;
		if (((Page) n).getParseData() instanceof HtmlParseData )
			data = (HtmlParseData) ((Page) n).getParseData();
	}

	String url; 
	String parent; 
	String domain, path;
	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getParent() {
		return parent;
	}

	public void setParent(String parent) {
		this.parent = parent;
	}

	int docid;
	private Set<WebURL> outLinks;

	public Set<WebURL> getOutLinks() {
		return outLinks;
	}

	public void setOutLinks(Set<WebURL> outLinks) {
		this.outLinks = outLinks;
	}

	//Used only in forms
	private String method;
	private HTMLForm form;
	private List<NameValuePair> params;


	public NavigationDatabaseNode (Page n ){
		if (n != null){
			this.node =  n;
			this.url= n.getWebURL().getURL();
			this.domain= n.getWebURL().getDomain();
			this.parent = n.getWebURL().getParentUrl();
			this.path = n.getWebURL().getPath();
			this.docid = n.getWebURL().getDocid();
			if (n.getParseData() instanceof HtmlParseData)
			{this.data= (HtmlParseData) n.getParseData();
			this.outLinks= ((HtmlParseData) n.getParseData()).getOutgoingUrls();

			}
		
		}
	}
	//this constructor is only for form destination nodes
	public NavigationDatabaseNode(Page page, HTMLForm form, List<NameValuePair> params,
			String method) {
		this.parent = page.getWebURL().getURL();
		this.method = method;
		this.form = form; 
		this.params = params; 
		this.docid = page.getWebURL().getDocid();
		this.node = page;
		String t= ((FormTag)form.getForm()).getFormLocation();
		if (t.isEmpty() || t == null)
			this.url=page.getWebURL().getURL();
		else 
			this.url= ((FormTag)form.getForm()).getFormLocation();
	}

	@Override
	public Map<String, Object> createProperties() {
		Map<String, Object> properties = new HashMap<String, Object>();
		if (node != null)
		{
			int docid = this.docid;//node.getWebURL().getDocid();
			properties.put(NodeKeys.ID, docid);

			String url = this.url;//node.getWebURL().getURL();
			if (url != null)
				properties.put(NodeKeys.URL, url);

			String domain = this.domain;//node.get()
			if (domain != null)
				properties.put(NodeKeys.DOMAIN, domain);

			String path = this.path;//node.getWebURL().getPath();
			if (path != null)
				properties.put(NodeKeys.PATH, path);

			String parentUrl = this.parent;//node.getWebURL().getParentUrl();
			if (parentUrl != null)
				properties.put(NodeKeys.PARENT, parentUrl);

			if (data != null){
				int links = data.getOutgoingUrls().size();
				properties.put(NodeKeys.LINKS, links);

				int forms = data.getForms().size();
				properties.put(NodeKeys.FORMS, forms);
			}

			List<NameValuePair> p = this.params;//node.get()
			if (p != null){
				String str="";
				for (NameValuePair pair : p)
				{
					str+=pair.getName()+"="+pair.getValue()+",";
				}

				properties.put(NodeKeys.PARAMS, str);
			}

			if (CrawlConfig.getRole() != null)
				properties.put(NodeKeys.ROLE, CrawlConfig.getRole());


		}

		return properties;
	}


	@Override
	public Map<String, Object> createPropertiesForms() {
		Map<String, Object> properties = new HashMap<String, Object>();
		if (node != null)
		{
			int docid = this.docid;//node.getWebURL().getDocid();
			properties.put(NodeKeys.ID, docid);

			String parentUrl = this.parent;//node.getWebURL().getParentUrl();
			if (parentUrl != null)
				properties.put(NodeKeys.PARENT, parentUrl);

			if (CrawlConfig.getRole() != null)
				properties.put(NodeKeys.ROLE, CrawlConfig.getRole());
		}
		properties.put("method", this.method); 
		properties.put("params", this.params);
		properties.put(NodeKeys.URL, this.url);

		return properties;
	}

	public void setNeo4jNode(Node node2) {
		this.neo4jNode= node2;

	}

	public NavigationDatabaseNode findParent(HashSet<NavigationDatabaseNode> navNodes) {
		File f = new File ("output.txt");
		FileWriter fw = null;
		try {
			fw = new FileWriter (f);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		for (NavigationDatabaseNode n: navNodes){
			if (n != null && n.getNode() != null && n.getNode().getWebURL() != null)

			{   try {
				fw.write("navNodes "+n.toString());
				fw.write("\ncomparing  "+this.getNode().getWebURL().getParentUrl() +"\n\t\t with "+
						n.getNode().getWebURL().getURL());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}


			if (n.getNode().getWebURL().CompareParentToChild
					(this.getNode().getWebURL()))

			{  try {
				fw.write("\nthe matching node is  "+n.toString());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return n;

			}
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return "NavigationDatabaseNode [node=" + node.getWebURL().getURL() +  ", parent=" + node.getWebURL().getParentUrl() + "]";
	}

	
	public static NavigationDatabaseNode findNode(HashSet<NavigationDatabaseNode> nodes, String url) {
		for (NavigationDatabaseNode n :nodes){
			if (((String)url).equals((String)n.getUrl()))
				return n;
		}
		return null;
	}

	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = ((url == null) ? 0 : url.hashCode())
				+ ((parent == null) ? 0 : parent.hashCode())

				;
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
		final NavigationDatabaseNode other = (NavigationDatabaseNode) obj;
		if (url == null) {
			if (other.url != null)
				return false;
		} else if (!url.equals(other.url))
			return false;

		if (parent == null) {
			if (other.parent != null)
				return false;
		} else if (!parent.equals(other.parent))
			return false;



		return true;
	}



}
