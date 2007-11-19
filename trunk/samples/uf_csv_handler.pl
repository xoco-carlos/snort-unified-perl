#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use SnortUnified::Handlers(qw(:ALL));

$file = shift;
$debug = 0;
$UF_Data = {};
$record = {};

# handlers will be run and regardless of the result processing will continue
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
register_handler('unified_record', \&printrec);
show_handlers();

# Qualifiers will be run, if any return a value < 1 
# then the record will be discarded and processing will continue
# with the next record in the file
# Only one option for unified types
register_qualifier(0,1,402, \&make_noise);
register_qualifier(0,1,402, \&make_noise_fail);
register_qualifier(0,1,402, \&make_noise_never);

# But you can be granular with unified2 types
register_qualifier($UNIFIED2_IDS_EVENT,1,402, \&make_noise);
register_qualifier($UNIFIED2_PACKET,1,402, \&make_noise);
show_qualifiers();

$UF_Data = openSnortUnified($file);
die unless $UF_Data;

while (read_records()){};

closeSnortUnified();
exit 0;

#############################################

sub read_records() {
  while ( $record = readSnortUnifiedRecord() ) {}

  print("Exited while. Deadreads is $UF->{'DEADREADS'}.\n") if $debug;
  
  return 0;
}

sub printrec() {
  $rec = shift;

  # print $UNIFIED2_TYPES->{$rec->{'TYPE'}};
  foreach $field ( @{$rec->{'FIELDS'}} ) {
    if ( $field ne 'pkt' ) {
      print($rec->{$field} . ",");
    }
  }
  print($i++ . "\n");

}

sub make_noise() {
  $rec = shift;

  print("#" x 70 . "\n");
  print("#" x 20 . "\n");
  print("#" x 20 . "\n");
  print("#" x 20 . "\n");
  print("#" x 20 . "\n");
  print("#" x 20 . "\n");
  print("#" x 20 . "\n");
  print("#" x 20 . "\n");
  print("#" x 20 . "\n");
  print("#" x 20 . "\n");
  print("#" x 70 . "\n");

  return 1;
}

sub make_noise_fail() {
  $rec = shift;

  print("#" x 20 . "\n");
  print("#" x 70 . "\n");
  print("#" x 70 . "\n");
  print("#" x 70 . "\n");
  print("#" x 70 . "\n");
  print("#" x 70 . "\n");
  print("#" x 70 . "\n");
  print("#" x 70 . "\n");
  print("#" x 70 . "\n");
  print("#" x 70 . "\n");
  print("#" x 20 . "\n");

  return 0;
}

sub make_noise_never() {
  $rec = shift;

  print("#" x 20 . "\n");
  print("#" x 70 . "\n");
  print("#" x 20 . "\n");
  print("#" x 70 . "\n");
  print("#" x 20 . "\n");
  print("#" x 70 . "\n");
  print("#" x 20 . "\n");
  print("#" x 70 . "\n");
  print("#" x 20 . "\n");
  print("#" x 70 . "\n");
  print("#" x 20 . "\n");

  return 1;
}

