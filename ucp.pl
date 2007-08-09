#!/usr/bin/perl

use Encode;
use lib 'lib/Net/';
use UCP;

$login = "login";
$password = "password";

#sent one message with send_sms();
###################################
$emi = Net::UCP->new(
		     SMSC_HOST   => '127.0.0.1', # use fake-smsc or nc -l -p 6666 to make some tests
		     SMSC_PORT   => 6666,
		     );

$emi->open_link() or die ($!);

($acknowledge,$error_number,$error_text) = $emi->login(
						       SMSC_ID    => $login,
						       SMSC_PW    => $password,
						       );

($acknowledge,$error_number,$error_text) = $emi->send_sms(
							  RECIPIENT      => '00393001121',
							  MESSAGE_TEXT   => "Test Net::UCP",
							  SENDER_TEXT    => "NEMUX",
							  );
$emi->close_link();


#another message in RAW MODE
###############################

#INIT
$emi = Net::UCP->new(
		     SMSC_HOST   => 'ucp.example.com',
		     SMSC_PORT   => 5555,
		     SRC_HOST   => '10.0.10.1',
		     );

$emi->open_link() or die ($!);

#LOGIN
$ucp_string = $emi->make_message(
				 op => '60',
				 operation => 1,
				 styp => 1,         #open session
				 oadc => $login,
				 pwd  => $password,
				 vers => '0100',
				 );

if ( defined($ucp_string) ) {
    ($acknowledge, $error_number, $error_text) = $emi->transmit_msg( $ucp_string, 5, 1 );
    print $error_text ."\n";
} else {
    die "Error while making UCP String OP 60\n";
}

#SUBMIT MESSAGE

my $oadc_example = encode('gsm0338', 'ALPHA@NUM');
my $amsg_example = encode('gsm0338', 'Short Message for NEMUX by Net::UCP');

#ucp string will be : 01/00154/O/51/00393201001/10412614190438AB4D/////////////////3//53686F7274204D65737361676520666F72204E454D5558206279204E65743A3A554350////1////5039/////C7

$ucp_string = $emi->make_message(
				 op => '51',
				 operation => 1,
				 adc   => '00393201001',
				 oadc  => $oadc_example, 
				 mt   => 3,
				 amsg => $amsg_example, 
				 mcls => 1,
				 otoa => 5039,
				 );
if ( defined($ucp_string) ) {
    ($acknowledge, $error_number, $error_text) = $emi->transmit_msg( $ucp_string, 10, 1 );
    print $error_text ."\n";
} else {
    die "Error while making UCP String OP 51\n";
}

$emi->close_link();
