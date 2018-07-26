package navex;


import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map.Entry;
import javax.activation.MimeTypeParseException;

import org.htmlparser.visitors.TagFindingVisitor;

import navex.formula.Formula;
import navex.formula.InferType;

import org.htmlparser.tags.*;

import org.htmlparser.tags.FormTag;

import org.htmlparser.Node;

/*
 * @author: Abeer Alhuzali and NoTamper.
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */

public class HTMLForm {

	private Node form;

	public int formId;
	public String formName;
	public String fileName;

	private String url; // where we extracted the form from 
	/*
	 * from notamper
	 */
	// document object (DOM) representation of the form
	public String domRepresentation;

	// window object's (top level browser window) representation of the page
	public String windowRepresentation;

	// define helper functions to enable symbolic execution e.g., alert
	private String helperFuns;

	// form specific JavaScript to validate input controls
	public String jsValidation;

	// JavaScript common to all forms, executed when page is loaded
	// this may initialize execution environment for the form validation script
	public String commonJS;
	// set this to true for using new Formula extractor and JS engine 
	// with older (NoTamper) version of solver. 
	public static boolean NEW_FE_JS_OLDER_SOLVER = true; 




	private HashSet<Formula> z3FormFormulas; 
	public Node getForm() {
		return form;
	}

	public void setForm(Node form) {
		this.form = form;
	}

	public int getFormId() {
		return formId;
	}

	public void setFormId(int formId) {
		this.formId = formId;
	}

	public String getFormName() {
		return formName;
	}

	public void setFormName(String formName) {
		this.formName = formName;
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public HashSet<Formula> getZ3FormFormulas() {
		return z3FormFormulas;
	}

	public void setZ3FormFormulas(HashSet<Formula> z3FormFormulas) {
		this.z3FormFormulas = z3FormFormulas;
	}



	private static int formCounter = 1;

	public HTMLForm(Node form, String url,  String commonJS) {
		this.form = form;

		this.formName = ((FormTag) form).getFormName();
		if (this.formName == null)
			this.formName = "form_"+Integer.toString(formCounter);
		this.url = url; 
		this.z3FormFormulas = new HashSet<Formula>();

		this.commonJS = commonJS;
		this.jsValidation = new String("");
		this.domRepresentation = new String();
		this.windowRepresentation = new String();
		this.helperFuns = new String();

	}

	@Override
	public String toString() {
		return "HTMLForm [form=" + ((FormTag)this.form).extractFormLocn() + ", formId=" + formId + ", formName=" + formName + ", url=" + url + ", z3formulas=" + this.getZ3FormFormulas() + "]";
	}



	/*
	 * output HTML constraints in Z3 solver formate
	 * returns any extra copy of the form if there is more than one submit bottons.
	 */

	public HashSet<HTMLForm> processInputsForZ3() throws IOException, MimeTypeParseException{


		Hashtable<String, ArrayList<String>> domains = new Hashtable<String, ArrayList<String>>();

		Hashtable<String, ArrayList<String>> domainsDropDown = new Hashtable<String, ArrayList<String>>();
		Hashtable<String, Integer> arrayCounters = new Hashtable<String, Integer>();
		ArrayList<String> keys = new ArrayList<String>();


		FormTag form2 = (FormTag) form;
		String formName = this.formName;
		domRepresentation = ("// DOM Simulation\n");
		domRepresentation += ("function DOM()\n{\n");
		domRepresentation += ("\tvar " + formName + " = new Object();\n\n");


		String[] tags = { "input", "select", "textarea"};
		TagFindingVisitor tfv = new TagFindingVisitor(tags);
		form.accept(tfv);
		Node[] inputs = tfv.getTags(0);
		Node[] selects = tfv.getTags(1);
		Node[] textareas = tfv.getTags(2);

		System.out.println("form inputs name size  :"+inputs.length);


		HashMap<Node, Formula> submits = new HashMap<Node, Formula>();

		for (Node n : inputs) {
			InputTag input = (InputTag) n;
			String id = input.getAttribute("id");
			String name = input.getAttribute("name");
			String type = input.getAttribute("type");
			String disabled = input.getAttribute("disabled");

			if (name != null && name.contains("[]")) {
				String namePref = name.replace("[]", "");
				Integer counter = arrayCounters.get(namePref);
				if (counter == null)
					counter = new Integer(0);
				else
					counter = new Integer(counter.intValue() + 1);
				name = namePref + "[" + counter.intValue() + "]";
				arrayCounters.put(namePref, counter);
			}

			if (id != null && type != null && !type.equalsIgnoreCase("radio")
					&& !type.equalsIgnoreCase("checkbox")
					&& !type.equalsIgnoreCase("select")
					&& !type.equalsIgnoreCase("file")) {
				domRepresentation += ("\t" + id + " = new Object();\n");
				if(HTMLForm.NEW_FE_JS_OLDER_SOLVER == true){				
					domRepresentation += ("\t" + id + ".value = '?" + name + "_notamper_symbolic';\n");
				} else {				
					domRepresentation += ("\t" + id + ".value = '(post \"" + name + "_notamper_symbolic\")';\n");
				}				
				domRepresentation += ("\t" + formName + "." + id + " = " + id + ";\n\n");
			}


			if (disabled != null && disabled.equalsIgnoreCase("disabled"))
				continue;

			if (type == null){

				String maxLen = input.getAttribute("maxlength");
				String size = input.getAttribute("size");
				String value = input.getAttribute("value");

				ArrayList<String> nameList = new ArrayList<String>();
				nameList.add(name);

				if (maxLen != null && !maxLen.isEmpty()){
					Formula f= new Formula (nameList, maxLen, "maxlen", "form-"+type , "FORM");

					this.z3FormFormulas.add(f);
				}
				else if (size != null && !size.isEmpty()){

					Formula f= new Formula (nameList, size, "maxlen", "form-"+type , "FORM");
					this.z3FormFormulas.add(f);
				}
				else {
					Formula f = new Formula(nameList, "0" , "minlen", "form-"+type, "FORM");
					this.z3FormFormulas.add(f);
				}
				if(value != null && !value.isEmpty()){
					Formula f = new Formula(nameList, "\""+value+"\"" , "=", "form-"+type, "FORM");
					this.z3FormFormulas.add(f);
				}
			}

			else if ( type.equalsIgnoreCase("reset")
					|| type.equalsIgnoreCase("button")) 
				continue;

			else if(type.equalsIgnoreCase("submit")){
				if(name == null)
					continue;
				String value = input.getAttribute("value");

				ArrayList<String> nameList= new ArrayList<String>();
				nameList.add(name);
				Formula f= new Formula (nameList, "\""+value+"\"", "=", "form-"+type, "FORM" );

				submits.put(n, f);
				continue; 
			}

			else if (type.equalsIgnoreCase("hidden")) {
				String value = input.getAttribute("value");

				// TODO: check infer type of value
				//TODO: for now I will consider this as string always.
				String sType = InferType.inferType(value);


				value = (value == null || value.isEmpty()) ? "\"\"" : "\""
						+ value + "\"";

				ArrayList<String> nameList= new ArrayList<String>();
				nameList.add(name);
				Formula f= new Formula (nameList, value, "=", "form-"+type, "FORM" );
				this.z3FormFormulas.add(f);


			} else if (type.equalsIgnoreCase("text")
					|| type.equalsIgnoreCase("password") ) { 
				String maxLen = input.getAttribute("maxlength");
				String size = input.getAttribute("size");
				String value = input.getAttribute("value");

				ArrayList<String> nameList = new ArrayList<String>();
				nameList.add(name);

				if (maxLen != null && !maxLen.isEmpty()){
					Formula f= new Formula (nameList, maxLen, "maxlen", "form-"+type , "FORM");

					this.z3FormFormulas.add(f);
				}
				else if (size != null && !size.isEmpty()){

					Formula f= new Formula (nameList, size, "maxlen", "form-"+type , "FORM");
					this.z3FormFormulas.add(f);
				}
				else {
					Formula f = new Formula(nameList, "0" , "minlen", "form-"+type, "FORM");
					this.z3FormFormulas.add(f);
				}
				if(value != null && !value.isEmpty()){
					Formula f = new Formula(nameList, "\""+value+"\"" , "=", "form-"+type, "FORM");
					this.z3FormFormulas.add(f);
				}



				domRepresentation += ("\tvar " + name + " = new Object();\n");
				if(HTMLForm.NEW_FE_JS_OLDER_SOLVER == true){
					domRepresentation += ("\t" + name + ".value = '?" + name + "_notamper_symbolic';\n");
				} else {
					domRepresentation += ("\t" + name + ".value = '(post \"" + name + "_notamper_symbolic\")';\n");
				}
				domRepresentation += ("\t" + formName + "." + name + " = "
						+ name + ";\n\n");


			} else if (type.equalsIgnoreCase("file")) {

			} else if (type.equalsIgnoreCase("radio")
					|| type.equalsIgnoreCase("checkbox")) {

				String value = input.getAttribute("value");

				if(value != null && name != null){
					ArrayList<String> domain = domains.get(name);
					if (domain == null) {
						domain = new ArrayList<String>();
						keys.add(name);
					}
					domain.add(value);
					domains.put(name, domain);

				}

				if(id != null){
					domRepresentation += ("\tvar " + id + " = new Object();\n");
					if(HTMLForm.NEW_FE_JS_OLDER_SOLVER == true){
						domRepresentation += 
								("\t" + id + ".checked = '?" + name + "_notamper_symbolic';\n");
						domRepresentation += 
								("\t" + id + ".value = '?" + name + "_notamper_symbolic';\n");
					} else {
						domRepresentation += 
								("\t" + id + ".checked = '(post \"" + name + "_notamper_symbolic\")';\n");
						domRepresentation += 
								("\t" + id + ".value = '(post \"" + name + "_notamper_symbolic\")';\n");
					}
					domRepresentation += ("\t" + formName + "." + id + " = " + id + ";\n\n");
				} else if(name != null){
					String s = "\tvar " + name + " = new Object();\n";
					if(domRepresentation.indexOf(s) < 0){
						domRepresentation += s;
						if(HTMLForm.NEW_FE_JS_OLDER_SOLVER == true){
							domRepresentation += 
									("\t" + name + ".checked = '?" + name + "_notamper_symbolic';\n");
							//("\t" + name + ".checked = '\"= (post \"" + name + "_notamper_symbolic\") \"" + 
							//	(value == null ? "on" : value) + "\"';\n");
							domRepresentation += 
									("\t" + name + ".value = '?" + name + "_notamper_symbolic';\n");
							//("\t" + name + ".value = '\"= (post \"" + name + "_notamper_symbolic\") \"" + 
							//	(value == null ? "on" : value) + "\"';\n");
						} else {
							domRepresentation += 
									("\t" + name + ".checked = '(post \"" + name + "_notamper_symbolic\")';\n");
							domRepresentation += 
									("\t" + name + ".value = '(post \"" + name + "_notamper_symbolic\")';\n");
						}
						domRepresentation += ("\t" + formName + "." + name + " = " + name + ";\n\n");					
					}
				}


			}

		} //end for 

		if (!domains.isEmpty()){
			for (Entry<String, ArrayList<String>> map: domains.entrySet()){
				//the formula her is reversed. It should be (key, list<value>, or). 
				Formula f = new Formula(map.getValue(), map.getKey(), "or", "form-radio-checkbox", "FORM");
				this.z3FormFormulas.add(f);
			}
		}


		String[] optionTag = { "option" };
		for (Node n : selects) {
			SelectTag select = (SelectTag) n;
			OptionTag option;
			String name = select.getAttribute("name");
			String id = select.getAttribute("id");


			if (name == null)
				continue;

			ArrayList<String> domain = new ArrayList<String>();
			tfv = new TagFindingVisitor(optionTag);
			n.accept(tfv);
			Node[] options = tfv.getTags(0);
			domRepresentation += ("\tvar options = new Array();\n");

			int i = 0;
			for (Node m : options) {
				option = (OptionTag) m;
				String value = option.getAttribute("value");
				domain.add(value);
				String selected = option.getAttribute("selected");


				if(HTMLForm.NEW_FE_JS_OLDER_SOLVER == true){
					domRepresentation += ("\toptions[" + i + "].selected = '= ?"
							+ name + "_notamper_symbolic \\'" + value + "\\'';\n");
				} else {
					domRepresentation += ("\toptions[" + i + "].selected = '= (post \""
							+ name + "_notamper_symbolic\") \\'" + value + "\\'';\n");
				}

				i++;
			}
			// TODO: check fix#3 -- if id is null use the name in JS
			if (id == null) {
				id = name;
				domRepresentation += ("\tvar " + id + " = new Object();\n");
				domRepresentation += ("\t" + id + ".options = options;\n");
				domRepresentation += ("\t" + formName + "." + id + " = " + id + ";\n\n");
			}

			domainsDropDown.put(name, domain);
		}


		if (!domainsDropDown.isEmpty()){
			for (Entry<String, ArrayList<String>> map: domainsDropDown.entrySet()){
				//the formula her is reversed . it should be (key, list<value>, or). 
				Formula f = new Formula(map.getValue(), map.getKey(), "or", "form-selects", "FORM");
				this.z3FormFormulas.add(f);
			}
		}


		for (Node t : textareas) {
			TextareaTag tat = (TextareaTag) t;
			String id = tat.getAttribute("id");
			String name = tat.getAttribute("name");			
			String rows= tat.getAttribute("rows");
			String max= tat.getAttribute("maxlength");
			ArrayList<String> nameList = new ArrayList<String>();
			nameList.add(name);
			Formula f;
			if(max != null && !max.isEmpty()){
				f = new Formula(nameList, max, "maxlen", "form-textarea", "FORM");
				this.z3FormFormulas.add(f);
			}
			else {
				f = new Formula(nameList, "0" , "minlen", "form-stextarea", "FORM");
				this.z3FormFormulas.add(f);
			}

			if(name != null){
				domRepresentation += ("\tvar " + name + " = new Object();\n");
				if(HTMLForm.NEW_FE_JS_OLDER_SOLVER == true){
					domRepresentation += ("\t" + name + ".value = '?" + name + "_notamper_symbolic';\n");
				} else {
					domRepresentation += ("\t" + name + ".value = '(post \"" + name + "_notamper_symbolic\")';\n");
				}
				domRepresentation += ("\t" + formName + "." + name + " = " + name + ";\n\n");
			}

			if(id != null){
				domRepresentation += ("\t" + id + " = new Object();\n");
				if(HTMLForm.NEW_FE_JS_OLDER_SOLVER == true){
					domRepresentation += ("\t" + id + ".value = '?" + name + "_notamper_symbolic';\n");
				} else {
					domRepresentation += ("\t" + id + ".value = '(post \"" + name + "_notamper_symbolic\")';\n");
				}
				domRepresentation += ("\t" + formName + "." + id + " = " + id + ";\n\n");
			}



		}



		domRepresentation += ("\tvar forms = new Array();\n");
		domRepresentation += ("\tforms[0] = " + formName + ";\n\n");
		domRepresentation += ("\tvar doc = new Object();\n");
		domRepresentation += ("\tdoc.forms = forms;\n");
		domRepresentation += ("\tdoc.") + formName + " = " + formName + ";\n"; 

		domRepresentation += ("\tdoc.getElementsByTagName = NT_gebtn;\n\n");
		domRepresentation += ("\tdoc.write = NT_w;\n\n");

		domRepresentation += ("\tdoc.frames = new Array();\n");
		domRepresentation += ("\tdoc.images = new Array();\n");
		domRepresentation += ("\tdoc.links = new Array();\n");
		domRepresentation += ("\tdoc.plugins = new Array();\n\n");
		domRepresentation += ("\tdoc.cookie = \"\";\n");

		domRepresentation += ("\treturn doc;\n}\n\n");

		domRepresentation += ("function NT_gebtn(elementName){\n");
		domRepresentation += ("    if(elementName == \"form\")\n");
		domRepresentation += ("        return this.forms; \n");
		domRepresentation += ("    else if(elementName == \"frame\")\n");
		domRepresentation += ("        return this.frames;\n");
		domRepresentation += ("    else if(elementName == \"images\")\n");
		domRepresentation += ("        return this.images; \n");
		domRepresentation += ("    else if(elementName == \"link\")\n");
		domRepresentation += ("        return this.links;\n");
		domRepresentation += ("    else if(elementName == \"plugin\")\n");
		domRepresentation += ("        return this.plugins;\n");
		domRepresentation += ("    else\n");
		domRepresentation += ("        return this;\n");
		domRepresentation += ("}\n");
		domRepresentation += ("\n");

		domRepresentation += ("function NT_w(msg){}\n");
		domRepresentation += ("\n");

		domRepresentation += ("\n\nvar document = new DOM();\n\n");

		// create a window object
		windowRepresentation += "function WINDOW(){\n";
		windowRepresentation += "   \n";
		windowRepresentation += "   this.setTimeout = wsto;\n";
		windowRepresentation += "   this.addEventListener = wael;\n";
		windowRepresentation += "   this.attachEvent = wae;\n";
		windowRepresentation += "   this.onload = wol;\n";
		windowRepresentation += "   this.onunload = woul;\n";
		windowRepresentation += "   this.location = new Object();\n";
		windowRepresentation += "   this.location.pathname = \"\";\n";
		windowRepresentation += "}\n";
		windowRepresentation += "\n";
		windowRepresentation += "function wsto(fnToCall, time){\n";
		windowRepresentation += "   // do nothing.\n";
		windowRepresentation += "}\n";
		windowRepresentation += "function wael(eventName, eventHandler, bool){}\n";
		windowRepresentation += "function wae(eventName, eventHandler){}\n";
		windowRepresentation += "function wol(){}\n";
		windowRepresentation += "function woul(){}\n";
		windowRepresentation += "\n";
		windowRepresentation += "var window = new WINDOW();\n\n";

		domRepresentation += "function NAVIGATOR(){\n";
		domRepresentation += "    this.userAgent = 'mozilla';\n"; 
		domRepresentation += "    this.appVersion = '3.0';\n"; 
		domRepresentation += "}\n\n";

		domRepresentation += "var navigator = new NAVIGATOR();\n";
		domRepresentation += 
				"var location = new Object(); \n" +
						"location.href = \"\"; \n " ;



		//finally we analyze the submit buttons

		if (submits.size() > 1){
			HashSet<HTMLForm> ret =new HashSet<HTMLForm>();
			HashSet<Formula> tempFormulas = new HashSet<Formula>();
			tempFormulas.addAll(this.z3FormFormulas);
			int i = 0 ;
			for(Entry<Node, Formula> map: submits.entrySet()) {
				if (i == 0)
					this.z3FormFormulas.add(map.getValue());
				else 
				{
					HTMLForm hf = new HTMLForm (form, url, this.commonJS);
					hf.z3FormFormulas.add(map.getValue());
					hf.z3FormFormulas.addAll(tempFormulas);
					ret.add(hf);
				}
				i++;
			}
			return ret;
		}
		else if (submits.size() == 1) {
			this.z3FormFormulas.add(submits.values().iterator().next());
			return null;
		}
		else 
			return null;


	}

	public void simulateJSValidation() {
		FormTag form2 = (FormTag) form;
		String formName = form2.getFormName() == null ? "form1" : form2
				.getFormName();
		String onSubmit = form2.getAttribute("onSubmit");

		jsValidation = "";
		if (onSubmit != null && onSubmit != "") {
			onSubmit = onSubmit.replaceAll("&amp;", "&");
			onSubmit = onSubmit.replaceAll("&quot;", "\"");
			onSubmit = onSubmit.replaceAll("&lt;", "<");
			onSubmit = onSubmit.replaceAll("&gt;", ">");
			onSubmit = onSubmit.replaceAll("this\\.", "formThis\\.");
			onSubmit = onSubmit.replaceAll(" this ", " formThis ");
			onSubmit = onSubmit.replaceAll("(this)", " formThis");

			// now simulate this reference by initializing the formThis var;
			onSubmit = " var formThis = document.forms[0]; \n " + onSubmit;
			jsValidation += ("\n// Event Simulation\n");
			jsValidation += ("function onSubmit_" + formName + "()\n{\n");
			jsValidation += ("\t" + onSubmit + ";\n}\n\n");
			jsValidation += ("onSubmit_" + formName + "();\n\n");
		}

		if (jsValidation == null || jsValidation.equals("")
				|| jsValidation.trim() == "") {
			jsValidation = " DO_NOT_PROCESS_NOTAMPER";
		} else {
			jsValidation = ("notamper_execution_begins = true;\n\n")
					+ jsValidation;
			jsValidation += ("notamper_execution_ends = true;\n\n");
		}
	}


	public String getHelperFuncs() {
		this.helperFuns += "function alert(msg){}\n";
		this.helperFuns += "function confirm(msg){}\n";
		this.helperFuns += "function prompt(msg){}\n";
		this.helperFuns += "function unescape(s){}\n";
		return this.helperFuns;
	}





}