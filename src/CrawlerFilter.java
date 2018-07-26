
/*
 * @modified by: Abeer Alhuzali
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */

package navex;


import edu.uci.ics.crawler4j.crawler.*;
import edu.uci.ics.crawler4j.parser.HtmlParseData;
import edu.uci.ics.crawler4j.url.*;

import java.util.regex.Pattern;

import org.apache.http.Header;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;


public class CrawlerFilter extends WebCrawler {

	private static HashSet<Page> allPages = new HashSet<Page>();
	private static HashSet<HTMLForm> allForms = new HashSet<HTMLForm>();


	public static HashSet<HTMLForm> getAllForms() {
		return allForms;
	}


	public static void setAllForms(HashSet<HTMLForm> allForms) {
		CrawlerFilter.allForms = allForms;
	}

	public static void addToAllForms(Set<HTMLForm> forms) {
		CrawlerFilter.allForms.addAll(forms) ;
	}


	public static HashSet<Page> getAllPages() {
		return allPages;
	}


	public static void addPage(Page p) {
		CrawlerFilter.allPages.add(p);
	}

	public static void resetPages(){
		CrawlerFilter.allPages =  new HashSet<Page>();
	}
	private final static Pattern FILTERS = Pattern.compile(".*(\\.(css|js|gif|jpg"
			+ "|png|mp3|zip|gz|com|net|it|org|html|htm)).*$");

	private final static Pattern FILTERS1 = Pattern.compile(".*(\\.(php|inc)).*$");


	//links that logges out should be ignored too
	//Change this as needed.
	@Override
	public boolean shouldVisit(Page referringPage, WebURL url) {
		String href = url.getURL().toLowerCase();
		return (FILTERS1.matcher(href).matches()
				|| href.startsWith("http://localhost/") 
				|| href.startsWith("http://192.168.0.123/") )
				&& !FILTERS.matcher(href).matches()
				&& !href.equals("http://localhost/mybloggie/admin.php?select=logoff");


	}


	/**
	 * This function is called when a page is fetched and ready to be processed
	 * by your program.
	 */
	@Override
	public void visit(Page page) {
		addPage(page);
		int docid = page.getWebURL().getDocid();
		String url = page.getWebURL().getURL();
		String domain = page.getWebURL().getDomain();
		String path = page.getWebURL().getPath();
		String subDomain = page.getWebURL().getSubDomain();
		String parentUrl = page.getWebURL().getParentUrl();
		String anchor = page.getWebURL().getAnchor();

		logger.debug("Docid: {}", docid);
		logger.info("URL: {}", url);
		logger.debug("Domain: '{}'", domain);
		logger.debug("Sub-domain: '{}'", subDomain);
		logger.debug("Path: '{}'", path);
		logger.debug("Parent page: {}", parentUrl);
		logger.debug("Anchor text: {}", anchor);

		if (page.getParseData() instanceof HtmlParseData) {
			HtmlParseData htmlParseData = (HtmlParseData) page.getParseData();
			String text = htmlParseData.getText();
			String html = htmlParseData.getHtml();

			Set<WebURL> links = htmlParseData.getOutgoingUrls();
			Set<HTMLForm> forms = htmlParseData.getForms();
			if (forms != null)
			{System.out.println("Collected forms are "+ forms.size() );
			addToAllForms(forms);
			}

			logger.debug("Text length: {}", text.length());
			logger.debug("Html length: {}", html.length());
			logger.debug("Number of outgoing links: {}"+ links.size());
			System.out.println("outgoing links: "+links.toString());
		}

		Header[] responseHeaders = page.getFetchResponseHeaders();
		if (responseHeaders != null) {
			logger.debug("Response headers:");
			for (Header header : responseHeaders) {
				logger.debug("\t{}: {}", header.getName(), header.getValue());
			}
		}

		logger.debug("=============");
	}


}

