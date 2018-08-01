#!/usr/bin/perl

use File::Basename;
$mypath = dirname($0);

printf("mypath = $mypath\n");
$mem_min=32;
$mem_max=10240;   

# edit the path of neo4j..../lib to your neo4j installation folder
$classpath="${mypath}/../../neo4j-community-2.1.5/lib/*:${mypath}/lib/*:${classpath_separator}${mypath}/bin";

system("java -XX:+HeapDumpOnOutOfMemoryError -Dnavex.home=\"${mypath}\" -classpath \"${classpath}\" navex.Main  @ARGV");


	

