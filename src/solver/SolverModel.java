/**
 * @author Abeer Alhuzali
 * 
 * This class reads/extracts information from a Z3 model 
 * 
 * e.g of a Z3 model: 
 * SAT (or UNSAT or UNKNOWN)
 * var : value
 * var2 : value2
 * 
 * e.g:
 * * v-ok
************************
>> SAT
------------------------
x : string -> "af"
************************
&0.0188589096069& 
* For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */
package navex.solver;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.uci.ics.crawler4j.fetcher.PageFetcher;
import edu.uci.ics.crawler4j.util.*;

public class SolverModel {
	
	

	private static final Logger logger = LoggerFactory.getLogger(SolverModel.class);
	 
  public enum solTypes{
	  SAT, UNSAT, UNKNOWN;
   }
  
  String url; 
  public String getUrl() {
	return url;
}

public void setUrl(String url) {
	this.url = url;
}

String solution;
  
  
  public String getSolution() {
	return solution;
}

public void setSolution(String solution) {
	this.solution = solution;
}

HashMap <String , String> varValue;
private HashMap<String, String> traceVarValue;
private List<NameValuePair> nvps;

public void setNvps(List<NameValuePair> nvps2) {
	this.nvps = nvps2;
}

public List<NameValuePair> getNvps() {
	return nvps;
}

public HashMap<String, String> getTraceVarValue() {
	return traceVarValue;
}

public HashMap<String, String> getVarValue() {
	return varValue;
}

public void setVarValue(HashMap<String, String> varValue) {
	this.varValue = varValue;
}

public void addVarValue(String var, String value) {
	if (varValue == null)
		varValue = new HashMap <String , String>();
	this.varValue.put(var, value) ;
}


	public SolverModel() {
		this.solution = null;
		this.varValue = new HashMap <String , String>();
		this.traceVarValue = new HashMap <String , String>();
		this.nvps= new ArrayList <NameValuePair>();
		this.getMap = new HashMap<String, String> ();
		this.url = null;
		
	}
	
   public List <NameValuePair> main(String[] args, PageFetcher pageFetcher) throws ClientProtocolException, IOException, URISyntaxException{
	
	String file = args[0];
	String method = args[1];
	String action = args[2];
	String modelType = args[3]; //either trace or form or static
	
	List <NameValuePair> ret = null;
	
	System.out.println("The model for the file "+file);

	this.processSolverModel(file);
	
	if (modelType.equals("trace") || modelType.equals("static") )
		traceModelPreprocessing();
	
	
	ret= this.genHttpRequestFromModel(method, action, modelType, pageFetcher);

	return ret;
   }
   
   @Override
public String toString() {
	return "SolverModel [solution=" + solution + ", varValue=" + varValue + "]";
}

public void processSolverModel(String file){
	logger.debug("Reading the file :"+ file);
   
	 try {
		 FileReader fr = new FileReader(file);
			
		 BufferedReader bis = new BufferedReader(fr);
		 String line = null;//bis.readLine();
		while((line=bis.readLine()) != null)
			  {
		    System.out.println("line is  :"+line);
			line= line.trim();
			if (line.startsWith(">> ")){
				if (line.equals(">> SAT") ||
						line.trim().equals(">> UNKNOWN")  ||
						line.trim().equals(">> UNSAT") )
					{ 
					  this.setSolution(line.split(">>")[1].trim());
			    	System.out.println("the model Solution is  "+this.getSolution());

					}
			}
			
			
			 if (this.getSolution() != null && this.getSolution().equals("SAT")){
				 
				 String[] tuples = line.split(" : ");
                if (tuples.length > 1)
					{
						
						if (tuples[0].startsWith("p1b"))
							continue;
						String value  = tuples[1].split("->")[1].trim();
						if (value.trim().startsWith("\"") && value.trim().endsWith("\""))
						{
							value= value.substring(1,value.length()-1 );
						}
							
						this.addVarValue(tuples[0].trim(), value);
				    	System.out.println("the model var-value pair is <"+tuples[0].trim()+","+ value+">");

					}
			}
		}
		 try{
			  fr.close();
              bis.close();
          }
          catch(Exception e)
          {
              logger.debug( " Exception while closing teh file " + file);
          }
          } catch (IOException e1) {
				e1.printStackTrace();
			}
		
    	System.out.println("the model solution is ::::"+this.getSolution());

     }
  public void traceModelPreprocessing(){
	  for (Entry<String, String> map : this.getVarValue().entrySet()){
		  if (map.getKey().startsWith("$_GET") || map.getKey().startsWith("$_POST")
				  || map.getKey().startsWith("$_SESSION") || map.getKey().startsWith("$_REQUEST") ||
				  map.getKey().startsWith("$HTTP_GET") || map.getKey().startsWith("$HTTP_POST"))
		  {
			  this.addTraceVarValue(map.getKey(), map.getValue());
		  }
	  }
  }

    public void addTraceVarValue(String key, String value) {
    	if (traceVarValue == null)
    		traceVarValue = new HashMap <String , String>();
    	this.traceVarValue.put(key, value) ;
	
}

	public List <NameValuePair> genHttpRequestFromModel(String method, String action, 
					String modelType, PageFetcher pageFetcher) throws ClientProtocolException, IOException, URISyntaxException{
    	if (this.getSolution() == null){
    		System.out.println("The model does not have a solution");
    		return null;
    	}
    	if (!this.getSolution().equals("SAT"))
    	{
    		System.out.println("The model is not SAT");
    		return null;
    	}
    	if (this.getVarValue().isEmpty() ){
    		System.out.println("The model is Empty !!!!");
    		return null;
    	}
    	if (method.equalsIgnoreCase("post")){
    		System.out.println("preparing for a post request to "+action);
    		return postHttpRequest(action, modelType, pageFetcher);
    	}
    	else if (method.equalsIgnoreCase("get")){
    		System.out.println("preparing for a get request to "+action);
    		return getHttpRequest(action, modelType, pageFetcher);
    	}
    	else if (method.equalsIgnoreCase("request")){
    		//requestHttpRequest(action);
    	}
    	else if (modelType == "static" && method == ""){
   		 List <NameValuePair> nvps = new ArrayList <NameValuePair>();

    		 HashMap<String, String> getMap = new HashMap<String, String>();
    		 
    		for (Entry<String, String> map : this.getTraceVarValue().entrySet()){
    		    		  if (map.getKey().contains("$_GET")){
    		    			 String key=  map.getKey().replace("$_GET_", "").replace("]", "");
    		    			  getMap.put(key,map.getValue());
    		    		  }
    		    		  else if (map.getKey().contains("$_POST")){
    			    			 String key=  map.getKey().replace("$_POST_", "").replace("]", "");
    			    			 //postMap.put(key,map.getValue());
    			 	    		 nvps.add(new BasicNameValuePair(key, map.getValue()));

    			    		  }
    		    		  else if (map.getKey().contains("$HTTP_GET_VARS")){
     		    			 String key=  map.getKey().replace("$HTTP_GET_VARS_", "").replace("]", "");
   		    			     getMap.put(key,map.getValue());
   		    		  }
    		    		  else if (map.getKey().contains("$HTTP_POST_VARS")){
 			    			 String key=  map.getKey().replace("$HTTP_POST_VARS_", "").replace("]", "");
 			 	    		 nvps.add(new BasicNameValuePair(key, map.getValue()));

 			    		  }
    		    	}
    	   
    		this.setNvps(nvps);
    		String newUrl = staticGetMap(action, getMap);
    		this.setGetMap(getMap);
    		this.setUrl(newUrl);
    		return nvps;

    	}
		return null;
    		
    	
    	
    }
	HashMap<String, String> getMap;
	public HashMap<String, String> getGetMap() {
		return getMap;
	}

	private void setGetMap(HashMap<String, String> getMap) {
		this.getMap = getMap;	
	}

	private String staticGetMap(String action , HashMap<String, String> getMap) {
		//Augment the action with the get params that we got for the trace
	    	String actionAug = "";
	    	for (Entry<String, String> map : getMap.entrySet()){
	    		try {
					actionAug+=map.getKey()+"="+URLEncoder.encode(map.getValue(), "UTF-8")+"&";
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
	    	}
	    	if(actionAug.lastIndexOf("&") != -1)
	    	   {actionAug= actionAug.substring(0,actionAug.lastIndexOf("&") );
	    	 
	    	    action = action.concat("?").concat(actionAug);
	    	   }
	   
	    
	    	
		return action;
	
	}

	

	private void requestHttpRequest(String action) {
		// TODO Auto-generated method stub
		
	}

	private List <NameValuePair> getHttpRequest(String action, String modelType, PageFetcher pageFetcher) throws ClientProtocolException, IOException, URISyntaxException {
		 List <NameValuePair> nvps = new ArrayList <NameValuePair>();
		 HashMap<String, String> getMap = new HashMap<String, String>();

		 
		 String data="";
		 String responseBody ="";
		 URIBuilder u = new URIBuilder();
				 u.setScheme("http");
		 action= action.replace("http://", "");
				 u.setHost(action);
		if(modelType.equals("form")){ 
	       for (Entry<String, String> map : this.getVarValue().entrySet()){
	    		u.setParameter(map.getKey(), map.getValue());
	    		}
	         }
		else {
			for (Entry<String, String> map : this.getTraceVarValue().entrySet()){
	    		  if (map.getKey().contains("$_GET")){
	    			 String key=  map.getKey().replace("$_GET[", "").replace("]", "");
	    			  getMap.put(key,map.getValue());
	    		  }
	    	}
	    String actionAug = "";
	    	for (Entry<String, String> map : getMap.entrySet()){
	    		u.setParameter(map.getKey(), map.getValue());
	    	}
		}
	    	URI uri = u.build();
	    try{
	    	logger.debug("The uri is  : "+uri.toString());
	    	
	    	//if (uri.startsWith(" http://http//"))
	    		//httpGet.
	    	HttpGet httpGet = new HttpGet(uri);
	    	logger.debug("The uri scheme is  : "+uri.getScheme());
	    	logger.debug("The get request is  : "+httpGet.getURI());
	        CloseableHttpResponse response2 = pageFetcher.httpClient.execute(httpGet, pageFetcher.getConfig().getHttpClientContext());

	        try {
	           logger.debug("Status Code : "+response2.getStatusLine());
	            HttpEntity entity2 = response2.getEntity();
	            // do something useful with the response body
	            // and ensure it is fully consumed
	            responseBody = EntityUtils.toString(entity2);
	            EntityUtils.consume(entity2);
	        } finally {
	            response2.close();
	        }
	    } finally {
	       // httpclient.close();
	    }
		
	    return null;
		
	}

	private List<NameValuePair> postHttpRequest(String action, String modelType, PageFetcher pageFetcher) throws ClientProtocolException, IOException {
		 List <NameValuePair> nvps = new ArrayList <NameValuePair>();
		 HashMap<String, String> postMap = new HashMap<String, String>();
		 HashMap<String, String> getMap = new HashMap<String, String>();
		 
    	 String responseBody="";
	    if(modelType.equals("form"))	
    	 for (Entry<String, String> map : this.getVarValue().entrySet()){
	    		nvps.add(new BasicNameValuePair(map.getKey(), map.getValue()));
	    	}
	    else {
	    	for (Entry<String, String> map : this.getTraceVarValue().entrySet()){
	    		  if (map.getKey().contains("$_GET")){
	    			 String key=  map.getKey().replace("$_GET[", "").replace("]", "");
	    			  getMap.put(key,map.getValue());
	    		  }
	    		  else if (map.getKey().contains("$_POST")){
		    			 String key=  map.getKey().replace("$_POST[", "").replace("]", "");
		    			 postMap.put(key,map.getValue());
		    		  }
	    	}
	    	for (Entry<String, String> map : postMap.entrySet()){
	    		nvps.add(new BasicNameValuePair(map.getKey(), map.getValue()));
	    	}
	    	//Augment the action with the get params we got for the trace
	    	String actionAug = "";
	    	for (Entry<String, String> map : getMap.entrySet()){
	    		actionAug+=map.getKey()+"="+URLEncoder.encode(map.getValue(), "UTF-8")+"&";
	    	}
	    	if (actionAug.lastIndexOf("&") != -1)
	    	   actionAug= actionAug.substring(0,actionAug.lastIndexOf("&") );
	    	if (action.contains("?"))
	    		action = action.concat("&").concat(actionAug);
	    	else 
	    		action = action.concat("?").concat(actionAug);
	    }
	    
	    try{
	    	HttpPost httpPost = new HttpPost(action);
	       
	        httpPost.setEntity(new UrlEncodedFormEntity(nvps));
	       
	        logger.debug("The request is  : "+httpPost.toString());
	        CloseableHttpResponse response2 = pageFetcher.httpClient.execute(httpPost, pageFetcher.getConfig().getHttpClientContext());

	        try {
	           logger.debug("Status Code : "+response2.getStatusLine());
	          HttpEntity entity2 = response2.getEntity();
	            // do something useful with the response body
	            // and ensure it is fully consumed
	          responseBody = EntityUtils.toString(entity2);
	           EntityUtils.consume(entity2);
	        } finally {
	            response2.close();
	        }
	    } finally {
	        //httpclient.close();
	    }
		return nvps;
	}
  
  
 
}
