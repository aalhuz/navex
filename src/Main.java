/**
 * @author Abeer Alhuzali
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */
package navex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.htmlparser.tags.FormTag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import edu.uci.ics.crawler4j.crawler.CrawlConfig;
import edu.uci.ics.crawler4j.crawler.Page;
import edu.uci.ics.crawler4j.fetcher.PageFetcher;
import edu.uci.ics.crawler4j.util.IO;
import navex.formula.Trace;
import navex.formula.TraceAnalysis;
import navex.graphDatabase.NeoGraphDatabase;
import navex.solver.DynamicSolver;
import navex.solver.Solver;
import navex.solver.SolverModel;
import edu.uci.ics.crawler4j.parser.HtmlParseData;


public class Main {
	private static final Logger logger = LoggerFactory.getLogger(Main.class);



	public static void main(String[] args) {
		long startTime = System.currentTimeMillis();
		CrawlConfig config = null;

		NeoGraphDatabase graph = new NeoGraphDatabase();

		try {
			config =BasicCrawlController.crawlerMain(args, graph);
		} catch (Exception e) {
			e.printStackTrace();
		}
		//reinitiat the authentication before analyzing forms.
		PageFetcher pageFetcher = new PageFetcher(config);

		startFormAnalyzer(pageFetcher, graph);

		//shutDown the pagefetcher
		pageFetcher.shutDown();
		long analysisEndTime = System.currentTimeMillis();
		long analysisDiffTime = (analysisEndTime - startTime);

		System.out.println("=====TOTAL Crawling+ processing time is====="+analysisDiffTime);

	}


	/*
	 * This method performs the following: 
	 * 1- call solver. The solver generates a model
	 * 2- process model.
	 * 3- generate an http request from the model.
	 * 4- send the http request to the application. The app generates a trace. 
	 * 5- use Joern (enhanced CPG) to analyze the Trace.
	 * 6- traverse the trace to check : 
	 * 			1- failed trace : collect constraints + repeat from (1)
	 * 			2- success trace : add the Http request to seed pool + create Neoj4
	 * 				nodes.
	 * 
	 */
	public static void startFormAnalyzer(PageFetcher pageFetcher, 
			NeoGraphDatabase graph){

		logger.debug("Analyzing Forms");

		if (CrawlerFilter.getAllPages() != null){
			logger.debug("  ....Starting to process Forms in the app....");
			for (Page page : CrawlerFilter.getAllPages()){
				System.out.println("analyzing forms in "+page.getWebURL().getURL());

				int counter = 0;

				if (page.getParseData() instanceof HtmlParseData )
				{ HtmlParseData ff = ((HtmlParseData)page.getParseData());

				for (HTMLForm form:ff.getForms() ){
					List <NameValuePair> params = null;
					String method = ((FormTag)form.getForm()).getFormMethod();
					String action = ((FormTag)form.getForm()).getFormLocation(); 

					System.out.println(" form located in : "+ form.getUrl());
					System.out.println(" form action is:" + action); 
					//if it it a login form --> continue;
					boolean flag = false ;
					for (String p : Options.getLoginFile()){
						if (action.equalsIgnoreCase(p)){
							flag = true;
							break;
						}
					}
					if (flag)
						continue;

					// input: form's solver spec file , form method{get/post}
					//and action i.e. url

					Solver solve = new Solver(form.getZ3FormFormulas());
					String spec = solve.prepareSolver();
					String temp = form.getUrl().replace("http://", "");
					String cFile = "formsSpec/"+temp+"__"+(counter);
					//Z3-str3 does not accept file name that has = ? or &
					cFile= cFile.replace("?", "_").replace("&", "_").replace("=", "_");

					IO.writeToFile(cFile, spec, false);
					//js support 
					String js=  form.getHelperFuncs()
							+ form.domRepresentation + " \n " + form.windowRepresentation
							+ "\n" + form.commonJS + " \n " + form.jsValidation;

					IO.writeToFile(cFile+".scripts", js, false);

					extractJSConstraints(cFile+".scripts");



					invokeSolver(cFile);


					if (action.isEmpty())
						action= form.getUrl();
					if (action.startsWith("./") && !action.equals("./")){
						int start=0;
						String localhost= "localhost";
						//The following is specific to Navex's evaluation. Edit as needed.
						if (cFile.indexOf("localhost/") > 0)
						{
							start = cFile.indexOf("localhost/")+10;

						}
						else if (cFile.indexOf("192.168.0.123/") > 0)
						{
							start = cFile.indexOf("192.168.0.123/")+14;
							localhost = "192.168.0.123";
						}
						//End 

						String appName= cFile.substring(start, cFile.indexOf("/", start)+1);

						action = "http://"+localhost+"/".concat(appName).concat(action.replace("./", ""));
					}
					else if (action.startsWith("./") && action.equals("./")){
						action=form.getUrl();
					}
					else if (!action.startsWith("http://") && (action.startsWith("localhost") || 
							action.startsWith("192.168.0.123")   ))
						action= "http://".concat(action);
					else if (!action.startsWith("http://localhost/")  || !action.startsWith("192.168.0.123") ){

						int start = 0; String localhost = "localhost";

						if (cFile.indexOf("localhost/") > 0)
						{
							start = cFile.indexOf("localhost/")+10;

						}
						else if (cFile.indexOf("192.168.0.123/") > 0)
						{
							start = cFile.indexOf("192.168.0.123/")+14;
							localhost = "192.168.0.123";
						}



						String appName= cFile.substring(start, cFile.indexOf("/", start)+1);

						action = "http://"+localhost+"/".concat(appName).concat(action);
					}
					//update the form action
					((FormTag)form.getForm()).setFormLocation(action);
					;
					String[] mArgs = {cFile+".model", method, action, "form"};
					SolverModel model = new SolverModel();
					try {
						params = model.main(mArgs, pageFetcher);
					} catch (ClientProtocolException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (URISyntaxException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					//we have to invoke the traversal ONLY if its a failed trace
					//Again. This is specific to Navex's evaluation. Please edit as needed.
					if (!IO.IsSuccTrace("/home/user/log/trace.xt")){	
						invokeTraversal();
						//loop until we have a successful trace
						Trace t = new Trace(form.getZ3FormFormulas(),
								DynamicSolver.getServerFormula());
						String combinedSpec = TraceAnalysis.start(t, form);
						String tt = form.getUrl().replace("http://", "");
						String comFile = "CombinedSpec/"+tt+"__"+(counter);
						//Z3-str3 does not accept a file name that has: =, ? , &
						comFile= comFile.replace("?", "_").replace("&", "_").replace("=", "_");

						IO.writeToFile(comFile, combinedSpec, false);

						//invoke the solver again for the combined contraraits Fc+Fs(trace)
						invokeSolver(comFile);

						String[] mArgsTrace = {comFile+".model", method, action, "trace"};
						model = new SolverModel();
						try {
							params = model.main(mArgsTrace, pageFetcher);
						} catch (ClientProtocolException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (URISyntaxException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}


					}
					//successful trace 
					//add nodes to the navigation graph
					else {
						graph.StartNeoDb(page, form ,"form",  params, method);
					}

					counter++;
				}
				}
			}
		}
		else 
			logger.debug("There are NO forms to process ..\n End of the analysis");
	}
	// Edit paths to main.py 
	private static void invokeTraversal() {
		System.out.println( "    --------------------------------------------------------------\n");
		System.out.println( "   Invoking the gremlin Traversal script (main.py) ...\n");
		System.out.println( "    --------------------------------------------------------------\n");

		String cm = "cd /home/user/python-joern/ ;source .env/bin/activate;";
		cm += "python /home/user/python-joern/main.py";
		System.out.println( cm+ "\n");
		String[] cmd = { "/bin/sh", "-c", cm };

		try
		{
			Process p = Runtime.getRuntime().exec( cmd );
			p.waitFor();
		} catch( IOException e )
		{
			System.err.println( "Error invoking the traversal script: " + cm );
		} catch( InterruptedException e )
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


	}
	// Edit paths to Z3-str.py  
	public static void invokeSolver(String cFile) {

		System.out.println( "    --------------------------------------------------------------\n");
		System.out.println( "    Generating Inputs ...\n");
		System.out.println( "    --------------------------------------------------------------\n");

		System.out.println( " Step 1 : Invokign the solver \n  ");
		String cm = "./../../Z3-str2/Z3-str.py -f "+cFile+" > "+cFile+".model";
		System.out.println( cm+ "\n");
		String[] cmd = { "/bin/sh", "-c", cm };

		try
		{   
		Process proc = Runtime.getRuntime().exec( cmd );

		// any error???
		//this is very important
		boolean exitVal = proc.waitFor(5, TimeUnit.SECONDS);
		System.out.println("ExitValue: " + exitVal); 
		proc.destroy();
		} catch (Throwable t)
		{
			t.printStackTrace();
		}
	}

	//Edit path to narcissus engin
	private static void extractJSConstraints(String srcFile) {

		// if the HTML constraints did not have any meaningful JS, do 
		//  not process them.
		//  HTML constraint generator places the DO_NOT_PROCESS_NOTAMPER
		//  flag in the scripts that need not be processed. 
		System.out.println( "--------------------------------------------------------------\n");
		System.out.println( "Extracting JavaScript constraints...\n");
		System.out.println( "--------------------------------------------------------------\n");


		//Edit path to narcissus engin
		String narc="/home/user/repos/navex/js-1.8.5/js/narcissus";


		boolean dontProcess = IO.grep(srcFile, "DO_NOT_PROCESS_NOTAMPER");

		if ( dontProcess ){
			System.out.println( "Processing "+srcFile+"...skipping\n");
		}        
		else{    
			System.out.println( "Processing "+srcFile+"...\n");
			try
			{
				IO.copyFile(srcFile, narc+"/test.js");
			} catch( IOException e )
			{
				System.err.println( "Error invoking cp  : " );
			}
			String newDir= System.getProperty("user.dir") +"/"+narc;
			System.out.println("Executing - "+narc+"/../src/dist/bin/js js.js  > "+srcFile+".log\n");

			String cm= narc+"/../src/dist/bin/js js.js  >  "+srcFile+".log";
			String[] cmd2 = { "/bin/sh", "-c", cm };


			try
			{
				Process p = Runtime.getRuntime().exec( cmd2 );
				p.waitFor();
			} catch( IOException e )
			{
				System.err.println( "Error invoking narc : " + cm );
			} catch( InterruptedException e )
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			String jscFile =srcFile.replace(".scripts.log", ".constraints_JS");

			String toRemove="JavaScript evaluator generated these constraints NTBEGIN";

			IO.copyFile(srcFile, jscFile, toRemove, "");             

			System.out.println( "  Generated JS constraints in "+jscFile+" \n");
		}

		System.out.println( "DONE extracing JS constraints\n");

	}


}
