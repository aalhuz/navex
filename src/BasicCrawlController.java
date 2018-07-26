package navex;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.activation.MimeTypeParseException;

import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CookieStore;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicNameValuePair;
import org.htmlparser.tags.FormTag;

/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



import edu.uci.ics.crawler4j.crawler.CrawlConfig;
import edu.uci.ics.crawler4j.crawler.CrawlController;
import edu.uci.ics.crawler4j.crawler.Page;
import edu.uci.ics.crawler4j.crawler.authentication.AuthInfo;
import edu.uci.ics.crawler4j.crawler.authentication.FormAuthInfo;
import edu.uci.ics.crawler4j.fetcher.PageFetcher;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtConfig;
import edu.uci.ics.crawler4j.robotstxt.RobotstxtServer;
import edu.uci.ics.crawler4j.util.IO;
import navex.formula.Trace;
import navex.formula.TraceAnalysis;
import navex.graphDatabase.NavigationDatabaseNode;
import navex.graphDatabase.NeoGraphDatabase;
import opennlp.tools.coref.mention.Parse;
import navex.solver.DynamicSolver;
import navex.solver.Solver;
/**
 * @author Yasser Ganjisaffar
 * @modified by: Abeer Alhuzali
 */
public class BasicCrawlController {
	private static final Logger logger = LoggerFactory.getLogger(BasicCrawlController.class);

	public static CrawlConfig crawlerMain(String[] args, NeoGraphDatabase graph) throws Exception {
		if (args.length < 3) {
			logger.info("Needed parameters: ");
			logger.info("\t rootFolder (it will contain intermediate crawl data)");
			logger.info("\t numberOfCralwers (number of concurrent threads)");
			return null;
		}

		//authentication info is stored in a file 
		String authFile = args[2];

		ArrayList<String[]> authList = IO.readAuthFile(authFile);

		String seed = args[3];



		/*
		 * crawlStorageFolder is a folder where intermediate crawl data is
		 * stored.
		 */
		String crawlStorageFolder = args[0];

		/*
		 * numberOfCrawlers shows the number of concurrent threads that should
		 * be initiated for crawling.
		 */
		int numberOfCrawlers = Integer.parseInt(args[1]);

		int i= 0;CrawlConfig config = null;
		while (i < authList.size()){

			config = startCrawlling(crawlStorageFolder, numberOfCrawlers, authList.get(i), seed, graph );
			i++;
		}


		return  config;

	}




	public static CrawlConfig startCrawlling(String crawlStorageFolder, 
			int numberOfCrawlers, String[] authList, String seed, NeoGraphDatabase graph){

		CrawlConfig config = new CrawlConfig();

		config.setCrawlStorageFolder(crawlStorageFolder);

		/*
		 * Be polite: Make sure that we don't send more than 1 request per
		 * second (1000 milliseconds between requests).
		 */
		// config.setPolitenessDelay(1000);

		/*
		 * You can set the maximum crawl depth here. The default value is -1 for
		 * unlimited depth
		 */
		config.setMaxDepthOfCrawling(20);

		/*
		 * You can set the maximum number of pages to crawl. The default value
		 * is -1 for unlimited number of pages
		 */
		config.setMaxPagesToFetch(1000);

		/**
		 * Do you want crawler4j to crawl also binary data ?
		 * example: the contents of pdf, or the metadata of images etc
		 */
		config.setIncludeBinaryContentInCrawling(false);

		/*
		 * Do you need to set a proxy? If so, you can use:
		 * config.setProxyHost("proxyserver.example.com");
		 * config.setProxyPort(8080);
		 *
		 * If your proxy also needs authentication:
		 * config.setProxyUsername(username); config.getProxyPassword(password);
		 */
		/*
		 * This config parameter can be used to set your crawl to be resumable
		 * (meaning that you can resume the crawl from a previously
		 * interrupted/crashed crawl). Note: if you enable resuming feature and
		 * want to start a fresh crawl, you need to delete the contents of
		 * rootFolder manually.
		 */
		config.setResumableCrawling(false);

		if (authList != null){
			FormAuthInfo auth;
			ArrayList<NameValuePair> nvl = null; 
			try {
				if (authList.length > 5 )
				{
					for (int i = authList.length ; i > 5 ;i=i-2){
						if (nvl == null)
							nvl= new  ArrayList<NameValuePair>();
						NameValuePair nv = new BasicNameValuePair(authList[i-2],authList[i-1]);
						nvl.add(nv);
					}
				}
				auth = new FormAuthInfo 
						(authList[0],authList[1],authList[2],authList[3],authList[4], nvl);

				CrawlConfig.setRole(authList[0]+","+authList[1]);

				HttpClientContext context = HttpClientContext.create();
				BasicCookieStore cookieStore = new BasicCookieStore();
				context.setCookieStore(cookieStore);

				config.addAuthInfo(auth);



			} catch (MalformedURLException e) {
				e.printStackTrace();
			}

		}



		/*
		 * Instantiate the controller for this crawl.
		 */
		PageFetcher pageFetcher = new PageFetcher(config);
		RobotstxtConfig robotstxtConfig = new RobotstxtConfig();
		RobotstxtServer robotstxtServer = new RobotstxtServer(robotstxtConfig, pageFetcher);
		CrawlController controller= null;
		try {

			controller = new CrawlController(config, pageFetcher, robotstxtServer);
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}




		/*
		 * For each crawl, you need to add some seed urls. These are the first
		 * URLs that are fetched and then the crawler starts following links
		 * which are found in these pages
		 */
		controller.addSeed(seed);
		//controller.addSeed("http://www.ics.uci.edu/~lopes/");
		//controller.addSeed("http://www.ics.uci.edu/~welling/");

		/*
		 * Start the crawl. This is a blocking operation, meaning that your code
		 * will reach the line after this only when crawling is finished.
		 */
		controller.start(CrawlerFilter.class, numberOfCrawlers);
		logger.info("Crawler 1 is finished.");



		/*After crawlling the whole application and creating the db graph 
	        from only http links. We will process now the forms (stage 2)
		 */
		startCreatingDB(graph);


		return config;

	}


	public static String getCookieValue(CookieStore cookieStore, String cookieName) {
		String value = null;
		for (Cookie cookie: cookieStore.getCookies()) {
			if (cookie.getName().equals(cookieName)) {
				value = cookie.getValue();
			}
		}
		return value;
	}


	private static void startCreatingDB(NeoGraphDatabase graph) {
		logger.info("Start Building the navigation graph  ......\n");


		for (Page page :CrawlerFilter.getAllPages())
			graph.StartNeoDb(page, null, "link", null, null);


		graph.addLinksStart();
	}


}
