#!/usr/bin/perl
use File::Copy;

my @delfiles 	= glob('/home/user/contiki/examples/thesis/node-*.c');
for my $delfile (@delfiles) {
  system("rm", $delfile, "-f");
}

my @conffiles 	= glob('/home/user/contiki/examples/thesis/*.ncfg');
for my $conffile (@conffiles) {
  system("rm", $conffile, "-f");
}

my @files 	= glob('/home/user/GRE*/*.ncfg');
$k 		= 1;

# Config file initial setting
$conffilename 	= '/home/user/contiki/examples/thesis/conf';
$confext 	= '.ncfg';

# C code for each node initial setting
$nodefilename 	= '/home/user/contiki/examples/thesis/node-';
@nodedata 	= ("1-1-1", "2-2-1", "3-2-2", "4-3-1", "5-1-2", "6-3-2", "7-3-3", "8-4-1", "9-5-1", "10-4-2", "11-4-3", "12-5-2", "13-2-3", "14-3-4", "15-3-5");
$nodeext 	= '.c';

for my $file (@files) {
  if($k < 16) {
    $i = 0;
    $j = 0;
    $conffullname 	= $conffilename.$k.$confext;
    $nodefullname 	= $nodefilename.$nodedata[$k-1].$nodeext;
    copy($file, $conffullname) or die "Copy failed: $!";

    open CONF, $conffullname or die "conf$k.ncfg: Open failed: $!";
    open TEMP, "temp_node.c" or die "temp_node.c: Open failed: $!";
    open MOTE, ">$nodefullname";

    while (<CONF>) {
      (/\(new\) groupKey \(hex\): (.*)/)	&& do {$groupKey = $1};
      (/nodeKey: (.*)/) 			&& do {$nodeKey = $1};
      (/nodeID: (.*)/) 				&& do {$nodeID = $1};
      (/subGroupKey \(hex\): (.*)/) 		&& do {$subgKey = $1};
      (/subgroupID: (.*)/) 			&& do {$subgID = $1};
      (/nodeID nodeTokenBackward: (.*) (.*)/) 		&& do {$nodeTknBID[$i] = $1; $nodeTknB[$i++] = $2};
      (/nodeID nodeTokenForward: (.*) (.*)/) 		&& do {$nodeTknBID[$i] = $1; $nodeTknB[$i++] = $2};
      (/subgroupID subgroupTokenBackward: (.*) (.*)/) 	&& do {$subgTknBID[$j] = $1; $subgTknB[$j++] = $2};
      (/subgroupID subgroupTokenForward: (.*) (.*)/) 	&& do {$subgTknBID[$j] = $1; $subgTknB[$j++] = $2};
    }

    $groupKey 	= '0x'.join(', 0x', unpack("(A2)*", $groupKey));
    $nodeKey 	= '0x'.join(', 0x', unpack("(A2)*", $nodeKey));
    $subgKey 	= '0x'.join(', 0x', unpack("(A2)*", $subgKey));
    $nodeTknBSID= join(', ', @nodeTknBID);
    $nodeTknBS 	= '0x'.join(', 0x', unpack("(A2)*", join('', @nodeTknB)));
    $subgTknBSID= join(', ', @subgTknBID);
    $subgTknBS 	= '0x'.join(', 0x', unpack("(A2)*", join('', @subgTknB)));
    $nnodeTknB	= $#nodeTknB + 1;
    $nsubgTknB	= $#subgTknB + 1;

    if($nnodeTknB > 0) {$temp = 'uint8_t tempn['.($nnodeTknB * 32).'] = {'.$nodeTknBS.'};'."\n";}
    for ($i = 0; $i < $nnodeTknB ; $i++) {
      $temp .= 'key_mem_node['.$i.'].ID = '.$nodeTknBID[$i].";\n";
      $temp .= 'memcpy(key_mem_node['.$i.'].Token, tempn + '.($i * 32).', KT_LENGTH * sizeof(uint8_t));'."\n";
    }

    if($nsubgTknB > 0) {$temp .= 'uint8_t temps['.($nsubgTknB * 32).'] = {'.$subgTknBS .'};'."\n";}
    for ($i = 0; $i < $nsubgTknB ; $i++) {
      $temp .= 'key_mem_subg['.$i.'].ID = '.$subgTknBID[$i].";\n";
      $temp .= 'memcpy(key_mem_subg['.$i.'].Token, temps + '.($i * 32).', KT_LENGTH * sizeof(uint8_t));'."\n";
    }

    while (<TEMP>) {
      (/static uint8_t groupKey\[KT_LENGTH\] = \{(.*)\}/) && do {s/$1/$groupKey/};
      (/static uint8_t nodeKey\[KT_LENGTH\] = \{(.*)\}/) && do {s/$1/$nodeKey/};
      (/static uint8_t subgKey\[KT_LENGTH\] = \{(.*)\}/) && do {s/$1/$subgKey/};
      (/static uint32_t nodeID = (.*);/) && do {s/$1/$nodeID/};
      (/static uint32_t subgID = (.*);/) && do {s/$1/$subgID/};
      (/static uint8_t nnode = (.*);/) && do {s/$1/$nnodeTknB/;};
      (/static uint8_t nsubg = (.*);/) && do {s/$1/$nsubgTknB/;};

      (/\/\/here/) && do {s/$1/$temp/;};

      print MOTE
    }
  
    close CONF;
    close TEMP;
    close MOTE;
    $k++;
    undef $temp;
    undef @nodeTknBID;
    undef @nodeTknB;
    undef @subgTknBID;
    undef @subgTknB;
  }
}

