# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-UCP.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 1 };
use Net::UCP;
ok(1); # If we made it this far, we're ok.

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.
#i will add some test...

$ucp = Net::UCP->new(FAKE => 1);
#$ucp->create_fake_smsc(); 

ok 2,
sub { $ucp_string = $ucp->make_01(
                            operation => 1,
                            adc  => '01234567890',
                            oadc => '09876543210',
                            ac   => '',
                            mt   => 3,
                            amsg => 'Short Message'
                           );
if (defined($ucp_string)) {
   print "UCP String OP 01 -> $ucp_string ...";
   return 2;
} else {  
   print "Not defined UCP string ??? ...";
   return 0;
}
};

ok 3,
sub { 
        $smsc_message = "06/00043/R/01/A/01234567890:090196103258/4E";

        $ref_msg = $ucp->parse_message($smsc_message);

        if (ref($ref_msg) eq "HASH") {
          print "TYPE -> " . $ref_msg->{type} . " ";
          print "OT -> " . $ref_msg->{ot} . " ...";
          return 3; 
        } else { 
          print "NOT HASH??? ...";
          return 0; 
        }
};

ok 4,
sub {
    $ucp_string = $ucp->make_02(
                                operation => 1,
                                npl   => '3',
                                rads  => '003932412341/00393291111/00393451231',
                               oadc => '123',
                                ac   => '',
                                mt   => 3,
                                amsg => 'Short Message to 3 subscribers'
                                );
if (defined($ucp_string)) {
   print "UCP String OP 02 -> $ucp_string ...";
   return 4;
} else {  
   print "Not defined UCP string ??? ...";
   return 0;
}
 
};

ok 5,
sub {
    $ucp_string = $ucp->make_message(
                                op => '51',
                                operation => 1,
                                adc   => '00393311212',
                                oadc  => 'ALPHA@NUM',
                                mt   => 3,
                                amsg => 'Short Message for NEMUX',
                                mcls => 1,
                                otoa => 5039,
                                );
if (defined($ucp_string)) {
   print "UCP String OP 51 -> $ucp_string ...";
   return 5;
} else {  
   print "Not defined UCP string ??? ...";
   return 0;
}
 
};
