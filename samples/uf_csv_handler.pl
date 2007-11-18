#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use SnortUnified::Handlers(qw(:ALL));

$file = shift;
$debug = 0;
$UF_Data = {};
$record = {};

# The available handlers for SnortUnified.pm are
# ("unified_opened", $UF);
# ("unified2_event", $UF_Record);
# ("unified2_packet", $UF_Record);
# ("unified2_unhandled", $UF_Record);
# ("unified2_record", $UF_Record); 
# ("unified_record", $UF_Record);
# ("read_data", ($readsize, $buffer));
# ("read_header", $h);

register_handler('unified2_record', \&printrec);

$UF_Data = openSnortUnified($file);
die unless $UF_Data;

print("row");
foreach $field ( @{$record->{'FIELDS'}} ) {
    if ( $field ne 'pkt' ) { 
        print("," . $field);
    }
}

print("\n");

while (read_records()){};

closeSnortUnified();
return 0;

#############################################

sub read_records() {
  while ( $record = readSnortUnifiedRecord() ) {
    
    print($i++ . ",");
  }

  print("Exited while. Deadreads is $UF->{'DEADREADS'}.\n") if $debug;
  
  return 0;
}

sub printrec() {
  $rec = shift;
  print $UNIFIED2_TYPES->{$rec->{'TYPE'}};
  foreach $field ( @{$rec->{'FIELDS'}} ) {
    if ( $field ne 'pkt' ) {
      print("," . $rec->{$field});
    }
  }
  print("\n");

}

