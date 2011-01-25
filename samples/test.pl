#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use Data::Dumper;

$file = shift;
$debug = 0;
$UF_Data = {};
$record = {};

$UF_Data = openSnortUnified($file);
die unless $UF_Data;

while (1) {
    read_records();
}

closeSnortUnified();
return 0;

sub read_records() {
  while ( $record = readSnortUnifiedRecord() ) {

    print "record type " . $record->{'TYPE'} . " is " . $UNIFIED2_TYPES->{$record->{'TYPE'}} . "\n";
    # next unless $record->{'TYPE'} eq $UNIFIED2_EVENT;
    # next unless $record->{'TYPE'} eq $UNIFIED2_IDS_EVENT
    # next unless $record->{'TYPE'} eq $UNIFIED2_IDS_EVENT_VLAN;
    # next unless $record->{'TYPE'} eq $UNIFIED2_IDS_EVENT_IPV6_VLAN;
    next unless $record->{'TYPE'} eq $UNIFIED2_EXTRA_DATA;

    print Dumper($record);
    
    foreach $field ( @{$record->{'FIELDS'}} ) {
        if ( $field ne 'pkt' ) {
            print("," . $record->{$field});
        }
    }
    print("\n");
  }

  print("Exited while. Deadreads is $UF->{'DEADREADS'}.\n") if $debug;
  
  return 0;
}

