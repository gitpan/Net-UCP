package Net::UCP;

use strict;
use warnings;
use Carp;
use IO::Socket;
use Time::HiRes qw(setitimer ITIMER_REAL);

require Exporter;

our @ISA = qw(Exporter);

our @EXPORT = qw();
our @EXPORT_OK = ();

our $VERSION = '0.05';

$VERSION = eval $VERSION; 

use constant ACK=>'A';
use constant TRUE=>1;

BEGIN{*logout=*close_link;}

sub new {bless({},shift())->_init(@_);}

# login to SMSC
sub login {
    my$self=shift();
    my %args=(
	      SMSC_ID => '',
	      SMSC_PW => '',
	      SHORT_CODE => undef,
	      ONPI => '',
	      OTON => '',
	      STYP => 1,       #def 1 (open session)
	      VERS => '0100',  #def 0100
	      @_);

    # Conditionally open the socket unless already opened.
    $self->open_link() unless(defined($self->{SOCK}));
    unless(defined($self->{SOCK})) {
        return(defined(wantarray)?wantarray?(undef,0,''):undef:undef);
    }

    defined($args{SMSC_ID})&&length($args{SMSC_ID})||do {
	$self->{WARN}&&warn("Missing mandatory parameter 'SMSC_ID' when trying to login. Login failed");
	return(defined(wantarray)?wantarray?(undef,0,''):undef:undef);
    };
    
    defined($args{SMSC_PW})&&length($args{SMSC_PW})||do {
	$self->{WARN}&&warn("Missing mandatory parameter 'SMSC_PW' when trying to login. Login failed");
	return(defined(wantarray)?wantarray?(undef,0,''):undef:undef);
    };

    my $data=$args{SMSC_ID}.                                  # OAdC
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        $args{OTON}.                                          # OTON (short number alias)
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        $args{ONPI}.                                          # ONPI (private)
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        $args{STYP}.                                          # STYP (open session)
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	$self->{OBJ_EMI_COMMON}->ia5_encode($args{SMSC_PW}).  # PWD
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        ''.                                                   # NPWD
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        $args{VERS}.                                          # VERS (version)
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        ''.                                                   # LAdC
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        ''.                                                   # LTON
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        ''.                                                   # LNPI
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        ''.                                                   # OPID
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        '';                                                   # RES1

    my $header=sprintf("%02d",$self->{TRN_OBJ}->next_trn()).  # Transaction counter.
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        $self->{OBJ_EMI_COMMON}->data_len($data).             # Length.
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        'O'.                                                  # Type (operation).
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        '60';                                                 # OT (Session management).
    
    my $message_string=$header.
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        $data.
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        $self->{OBJ_EMI_COMMON}->checksum($header.
                                          $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
                                          $data.
                                          $self->{OBJ_EMI_COMMON}->UCP_DELIMITER);

    my $timeout = $self->{TIMEOUT_OBJ}->timeout();        
    
    $self->_transmit_msg($message_string,$timeout);
}

# This method will also conditionally be called from the login() method.
sub open_link {
    my$self=shift;
    
    $self->{SOCK}=IO::Socket::INET->new(
                                        PeerAddr  => $self->{SMSC_HOST},
                                        PeerPort  => $self->{SMSC_PORT},
                                        Proto     => 'tcp',
                                        LocalAddr => defined($self->{SRC_HOST}) ? $self->{SRC_HOST} : '',
                                        LocalPort => defined($self->{SRC_PORT}) ? $self->{SRC_PORT} : ''
					);

    defined($self->{SOCK})||do {
	$self->{WARN}&&warn("Failed to establish a socket connection with host $self->{SMSC_HOST} on port $self->{SMSC_PORT} : $!");
        return;
    };
    TRUE;
}

# To avoid keeping the socket open if not used any more.
sub close_link {
    my$self=shift;

    defined($self->{SOCK})||return;

    close($self->{SOCK});
    $self->{SOCK}=undef;
    $self->{TRN_OBJ}->reset_trn();
    TRUE;
}

# send SMS
sub send_sms {
    my$self=shift();
    my%args=(
             RECIPIENT => '',
             MESSAGE_TEXT => '',
             SENDER_TEXT => '',
             UDH => undef,
             MESSAGE_BINARY => undef,
	     FLASH => undef,
             TIMEOUT => undef,
             @_);

    my$timeout;

    if(defined($args{TIMEOUT})) {
        my$tv=TimeoutValue->new(TIMEOUT=>$args{TIMEOUT});
        $timeout=$tv->timeout();
    }
    else {
        $timeout=$self->{TIMEOUT_OBJ}->timeout();
    }

    defined($args{RECIPIENT})&&length($args{RECIPIENT})||do {
        $self->{WARN}&&warn("Missing mandatory parameter 'RECIPIENT' when trying to send message. Transmission failed");
        return(defined(wantarray)?wantarray?(undef,0,''):undef:undef);
    };

    $args{RECIPIENT}=~s/^\+/00/;
    $args{RECIPIENT}=~/^\d+$/||do{
      $self->{WARN}&&warn("The recipient address contains illegal (non-numerical) characters: $args{RECIPIENT}\nMessage not sent ");
        return(defined(wantarray)?wantarray?(undef,0,''):undef:undef);
    };

    # It's OK to send an empty message, but not to use undef.
    defined($args{MESSAGE_TEXT})||($args{MESSAGE_TEXT}=' ');

    my $oadc_tmp = '';
    my $otoa_tmp = '';

    if ((defined($args{SENDER_TEXT}) and length($args{SENDER_TEXT}))) {

	if ($args{SENDER_TEXT} =~ /^([0-9]+)$/) {
	    $otoa_tmp = '';
	    if (length ($args{SENDER_TEXT}) > 22) {substr($args{SENDER_TEXT},22) = ''}
	    $oadc_tmp = $args{SENDER_TEXT};
	} elsif ($args{SENDER_TEXT} =~ /^\+([0-9]+)$/) {
	    $args{SENDER_TEXT} =~ s/^.//;
	    $otoa_tmp = '1139';
	    if (length ($args{SENDER_TEXT}) > 22) {substr($args{SENDER_TEXT},22) = ''}
	    $oadc_tmp = $args{SENDER_TEXT};
	} else {
	    $otoa_tmp = '5039';
	    if (length ($args{SENDER_TEXT}) > 11) {substr($args{SENDER_TEXT},11) = ''}
	    $oadc_tmp = $self->{OBJ_EMI_COMMON}->encode_7bit($args{SENDER_TEXT});
	}

    } else {
	$args{SENDER_TEXT} = "Nemux"; # ;->
	$oadc_tmp = $self->{OBJ_EMI_COMMON}->encode_7bit($args{SENDER_TEXT});
    }

    my $data=$args{RECIPIENT}.                          # AdC (Address Code)
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	$oadc_tmp.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	$self->{SHORT_CODE}.                            # AC. Authentication Code Originator
                                                        # is empty if authentication method is not
                                                        # based on it. (see login() sub.)
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # NRq (Notfication Request 1).
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # NAdC.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # NT (Notification Type 3).
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # NPID.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # LRq.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # LRAd (Last Resort Address).
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # LPID.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # DD.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # DDT.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # VP.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # RPID.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # SCTS.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # Dst.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # Rsn.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	''.                                             # DSCTS.
	$self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	(defined($args{MESSAGE_BINARY}) ?               # MT (message type).
	 '4' :
	 '3').
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 (defined($args{MESSAGE_BINARY}) ?
	  (length($args{MESSAGE_BINARY})/2)*8 :
	  '').                                          # NB. Number of bits
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 (defined($args{MESSAGE_BINARY}) ?
	  $args{MESSAGE_BINARY} :
	  $self->{OBJ_EMI_COMMON}->ia5_encode($args{MESSAGE_TEXT})).
	  $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	  ''.                                           # MMS.
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 ''.                                            # PR.
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 (defined($args{MESSAGE_BINARY}) ?              # DCs. data coding scheme set to 1 if we want to
	  '1':                                          # to send an 8bit message else empty for 7bit default
	  '').
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 ((defined($args{FLASH}) and ($args{FLASH} == 1)) 
	  ?
	  '0' :                                          # FLASH Message
	  '').                                           # MCLs.
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 ''.                                             # RPI.
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 ''.                                             # CPg.
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 ''.                                             # RPLy.
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 $otoa_tmp.                                      # OTOA
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 ''.                                             # HPLMN.
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 (defined($args{MESSAGE_BINARY})&&defined($args{MESSAGE_BINARY}) ?                          # $XSer.
	  make_xser('B',$args{UDH}) :
	  '').
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 ''.                                             # RES4.
	 $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
	 '';                                             # RES5;

    my $header=sprintf("%02d",$self->{TRN_OBJ}->next_trn()). # Transaction counter.
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        $self->{OBJ_EMI_COMMON}->data_len($data).
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        'O'.                                             # Type.
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        '51';                                            # OT (submit message)

    my $message_string=$header.
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        $data.
        $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
        $self->{OBJ_EMI_COMMON}->checksum($header.
                                          $self->{OBJ_EMI_COMMON}->UCP_DELIMITER.
                                          $data.
                                          $self->{OBJ_EMI_COMMON}->UCP_DELIMITER);

    $self->_transmit_msg($message_string,$timeout);
}


#########Development....
#make_xser() subfunction.
#
#Parameters:
#1)Message Type   (it can be "T" -> Text or "B" -> Binary messages)
#2)UserDataHeader (in hexadecimal without octet length)
#
#i make this func. to make some test. But it could be good to implement
#other features
####################################################################
#if udh is undef udh will be to set to 020115 (8bit message)
####################################################################
sub make_xser($$) {
    my $type=shift;
    my $udh=shift;
    my $xser_ret='';

    if (! defined ($udh)) {
	return "020115";
    }

#count octets numbers UDH
    my $udh_len = sprintf("%02X",length($udh)/2);

#counts octets number of DD field
#octets total number
    my $udh_oct = sprintf("%02X",(length($udh)/2)+1);

    $type eq "T" and $xser_ret='020100';

#XSER for binary message with udh
#XSER multipart
#TT 02 -> Xser per DCS
#LL 01 -> ottetti DD
#DD 00 -> set data coding scheme to 8 bit
#TT 01 -> Xser for UDH
#LL $udh_oct -> octets UDH information field
#DD ->  contains UDH field set by user

    $type eq "B" and $xser_ret='01'.$udh_oct.$udh_len.$udh;

####### My Wap Push Test
#$type eq "B" and $xser_ret='01605040B8423F0';
#######

    return $xser_ret;
}

# 'Internal' subs. Don't call these since they may, and will, change without notice.

sub _init {
    my$self=shift();
    $self->{OBJ_EMI_COMMON}=Common->new();
    my%args=(
             SMSC_HOST=>'',
             SMSC_PORT=>$self->{OBJ_EMI_COMMON}->DEF_SMSC_PORT,
             SENDER_TEXT=>'',
             WARN=>0,
             TIMEOUT=>undef,
             SRC_HOST=>undef,
             SRC_PORT=>undef,
             @_);

    $self->{WARN}=defined($args{WARN})?$args{WARN}?1:0:0;
    $self->{TIMEOUT_OBJ}=TimeoutValue->new(TIMEOUT=>$args{TIMEOUT},
                                           WARN=>$self->{WARN});
    $self->{TRN_OBJ}=TranNbr->new();

    defined($args{SMSC_HOST})&&length($args{SMSC_HOST})||do{
        $self->{WARN}&&warn("Mandatory entity 'SMSC_HOST' was missing when creating an object of class ".
                            __PACKAGE__.
                            ". Object not created");
        return;       # Failed to instantiate this object.
    };
    defined($args{SMSC_PORT})&&length($args{SMSC_PORT})||do{
        $self->{WARN}&&warn("Mandatory entity 'SMSC_PORT' was missing when creating an object of class ".
                            __PACKAGE__.
                            ". Object not created");
        return;       # Failed to instantiate this object.
    };
    $args{SMSC_PORT}=~/^\d+$/||do{
        $self->{WARN}&&warn("Non-numerical data found in entity 'SMSC_PORT' when creating an object of class ".
                            __PACKAGE__.
                            ". Object not created");
        return;       # Failed to instantiate this object.
    };

    $self->{SMSC_HOST}=$args{SMSC_HOST};
    $self->{SMSC_PORT}=$args{SMSC_PORT};
    $self->{SENDER_TEXT}=defined($args{SENDER_TEXT})&&length($args{SENDER_TEXT})?$args{SENDER_TEXT}:__PACKAGE__;

    $self->{SRC_HOST}=$args{SRC_HOST};
    $self->{SRC_PORT}=$args{SRC_PORT};

    $self->{SOCK}=undef;

    # Some systems have not implemented alarm().
    # On such systems, calling alarm() will create a run-time error.
    # Determine if we dare calling alarm() or not.

    #I must work on it...

    eval{alarm(0)};
    $self->{CAN_ALARM}=$@?0:1;

    $self;
}


###TEST IT ONLY.... 
#TODO: Add parsing of other OPERATION
#timeout = 0 or < 0 (no timeout)
#file_path (mandatory)
#file path could be a symlynk....!!!
######################################
sub read_mo {
    my ($self, $timeout_second, $file_path) = @_;	

    unless ($file_path) {
	croak "Error in read_mo() set file path please!!";
    }
    
    my ($buffer, $response, $rd);

    if ($timeout_second > 0) {
	$SIG{ALRM} = \&_Sig_Alarm;
	setitimer(ITIMER_REAL, $timeout_second, 0);
    }

    $self->{SOCK}->flush();
    
    do {
	
	$rd = $self->{SOCK}->recv($buffer , 1);
	
	if ($buffer eq $self->{OBJ_EMI_COMMON}->STX) {
	    $response .= $buffer; 
	} else {
	    exit 0;	
	}

    } until($buffer eq $self->{OBJ_EMI_COMMON}->ETX);

    if (! (open (OUTPUT , ">>$file_path"))) {
	croak "Unable to open file $file_path\n";
    }
    
    print OUTPUT "\n MO UCP : $response \n";

    my ($trn, $ack, @mes_txt, $adc, $oadc, $mt, $msg);
    
    my (@ucp_01) = split($self->{OBJ_EMI_COMMON}->UCP_DELIMITER, $response);
    
    $trn = $ucp_01[0];
    
    if($ucp_01[4] eq ACK) { 
	
	print OUTPUT "TRN=$trn OPER=01 SM=$ucp_01[5] ACK=$ucp_01[4]";
	
    } else {
        
	$adc  = $ucp_01[4];
        $oadc = $ucp_01[5];
        $mt   = $ucp_01[7];
        
#To understand read EMI/UCP Specification... operation 01..
	
	if ($mt == 2) { 
            $msg = '';
	    print OUTPUT "MESS: $ucp_01[8]\n";
            $msg = $ucp_01[8];
        }
        elsif ($mt == 3) {
            $msg = '';
            print OUTPUT "MESS: $ucp_01[8]\n";   
            $msg = $self->{OBJ_EMI_COMMON}->ia5_decode($ucp_01[8]);
        }
	
	print OUTPUT "OPER=01 TYPE=$ucp_01[2] AdC=$adc OAdC=$oadc MT=$mt Msg=$msg\n";
        
    }
    
    close OUTPUT;
}


sub _Sig_Alarm {
    print "\n Timeout Reached\n";
    exit 0;
}


#############################
sub _transmit_msg {
    my($self,$message_string,$timeout)=@_;
    my($rd,$buffer,$response,$acknack,$errcode,$errtxt,$ack);

    defined($timeout)||do{$timeout=0};

	open(FILEWRITE ,">>temp.txt");
	print FILEWRITE "\n NOW : $message_string \n";
	close FILEWRITE;

    print {$self->{SOCK}} ($self->{OBJ_EMI_COMMON}->STX.$message_string.$self->{OBJ_EMI_COMMON}->ETX) ||do{
        $errtxt="Failed to print to SMSC socket. Remote end closed?";
        $self->{WARN}&&warn($errtxt);
        return(defined(wantarray)?wantarray?(undef,0,$errtxt):undef:undef);
    };
    
    $self->{SOCK}->flush();

    do  {
        # If this system implements alarm(), we will do a non-blocking read.
        if($self->{CAN_ALARM}) {
            eval {
                $rd=undef;
                local($SIG{ALRM})=sub{die("alarm\n")}; # NB: \n required
                alarm($timeout);
                $rd=read($self->{SOCK},$buffer,1);
                alarm(0);
            };
            # Propagate unexpected errors.
            $@&&$@ne"alarm\n"&&die($@);
        }
        else {
            # No alarm() implemented. Must do a (potentially) blocking call to read().
	    $rd=read($self->{SOCK},$buffer,1);
	}
        defined($rd)||do{ # undef, read error.
            $errtxt="Failed to read from SMSC socket. Never received ETX. Remote end closed?";
            $self->{WARN}&&warn($errtxt);
            return(defined(wantarray)?wantarray?(undef,0,$errtxt):undef:undef);
        };
        $rd||do{ # Zero, end of 'file'.
            $errtxt="Never received ETX from SMSC. Remote end closed?";
            $self->{WARN}&&warn($errtxt);
            return(defined(wantarray)?wantarray?(undef,0,$errtxt):undef:undef);
        };
	$response.=$buffer;
    }   until($buffer eq $self->{OBJ_EMI_COMMON}->ETX);

    (undef,undef,undef,undef,$acknack,$errcode,$errtxt,undef)=split($self->{OBJ_EMI_COMMON}->UCP_DELIMITER,$response);
    if($acknack eq ACK) {
        ($ack,$errcode,$errtxt)=(TRUE,0,'');
    }
    else {
        $ack=0;
        $errtxt=~s/^\s+//;
        $errtxt=~s/\s+$//;
    }
	$errtxt .='\nWe send :'.$message_string.' We Recieve'.$response.'\n';
    defined(wantarray)?wantarray?($ack,$errcode,$errtxt):$ack:undef;
}

package Common;
use strict;

use constant STX=>chr(2);
use constant ETX=>chr(3);
use constant UCP_DELIMITER=>'/';
use constant DEF_SMSC_PORT=>3024;
use constant ACK=>'A';
use constant NACK=>'N';

use constant DEBUG=>0;

use vars qw(%accent_table);

#IA5 by vi
%accent_table = (
                 '05' => '0xe8',
                 '04' => '0xe9',
                 '06' => '0xf9',
                 '07' => '0xec',
                 '08' => '0xf2',
                 '7F' => '0xe0'
                 );

sub new {
    my$self={};
    bless($self,shift())->_init(@_);
}

# Calculate packet checksum
sub checksum {
    my $checksum;
    defined($_[0])||return(0);
    map {$checksum+=ord} (split //,pop @_);
    sprintf("%02X",$checksum%256);
}

# Calculate data length
sub data_len {
    my$len=length(pop @_)+17;
    for(1..(5-length($len))) {
	$len='0'.$len;
    }
    $len;
}

# The first 'octet' in the string returned will contain the length of the remaining user data.
sub encode_7bit {
    my($self,$msg)=@_;
    my($bit_string,$user_data)=('','');
    my($octet,$rest);

    defined($msg)&&length($msg)||return('00');   # Zero length user data.

    for(split(//,$msg)) {
	$bit_string.=unpack('b7',$_);
    }

    print("Bitstring:$bit_string\n") if DEBUG;
	
    while(defined($bit_string)&&(length($bit_string))) {
	$rest=$octet=substr($bit_string,0,8);
	$user_data.=unpack("H2",pack("b8",substr($octet.'0'x7,0,8)));
	$bit_string=(length($bit_string)>8)?substr($bit_string,8):'';
    }

    sprintf("%02X",length($rest)<5?length($user_data)-1:length($user_data)).uc($user_data);
}

sub ia5_decode {
    my ($msg)=@_;
    my $tmp = "";
    my $out = "";
    
    while (length($msg) != "") {
	($tmp,$msg) = ($msg =~ /(..)(.*)/);
	if ($accent_table{$tmp}) {
	    $out .= sprintf("%s", chr(hex($accent_table{$tmp})));
	} else {
	    $out .= sprintf("%s", chr(hex($tmp)));
	}
    }
    
    return ($out);
}

sub ia5_encode { join('',map {sprintf "%02X", ord} split(//,pop(@_))); }

sub _init { shift; }

#Pack.
######################
package TimeoutValue;
use strict;
use Carp;

use constant MIN_TIMEOUT=>0;           # No timeout at all!
use constant DEFAULT_TIMEOUT=>15;
use constant MAX_TIMEOUT=>60;

sub new {bless({},shift())->_init(@_);}

sub timeout {$_[0]->{TIMEOUT};}

sub _init {
    my$self=shift();
   my%args=(
      TIMEOUT=>undef,
      WARN=>0,
	    @_);

    $self->{WARN}=defined($args{WARN})?$args{WARN}?1:0:0;
    $self->{TIMEOUT}=DEFAULT_TIMEOUT;

    if(defined($args{TIMEOUT})) {
	if($args{TIMEOUT}=~/\D/) {
	    $self->{WARN}&&warn("Non-numerical data found in entity 'TIMEOUT' when creating an object of class ".
                             __PACKAGE__.
                             '. '.
                             'Input data: >'.
				$args{TIMEOUT}.
				'< Given TIMEOUT value ignored and default value '.DEFAULT_TIMEOUT.' used instead');
	}

# The commented code will never be executed until we let the MIN_TIMEOUT be greater than zero (since the '-' is non-numeri)
#      elsif($args{TIMEOUT}<MIN_TIMEOUT) {
#         $self->{WARN}&&warn("Entity 'TIMEOUT' contains a value smaller than the smallest value allowed (".
#                             MIN_TIMEOUT.
#                             ") when creating an object of class ".
#                             __PACKAGE__.
#                             '. Given TIMEOUT value ignored and default value '.DEFAULT_TIMEOUT.' used instead');
	elsif($args{TIMEOUT}>MAX_TIMEOUT) {
	    $self->{WARN}&&warn("Entity 'TIMEOUT' contains a value greater than the largest value allowed (".
                             MAX_TIMEOUT.
                             ") when creating an object of class ".
                             __PACKAGE__.
				'. Given TIMEOUT value ignored and default value '.DEFAULT_TIMEOUT.' used instead');
	}
	else {
	    $self->{TIMEOUT}=$args{TIMEOUT};
	}
    }

    $self;
}


#Pack.
##################
package TranNbr;
use strict;
use constant HIGHEST_NBR=>99;

sub new {bless({},shift())->_init(@_);}

sub next_trn {
    my$self=shift;
    ($self->{TRN}>HIGHEST_NBR)&&do{$self->{TRN}=0};
    $self->{TRN}++;
}

sub reset_trn {
    $_[0]->{TRN}=0;
}

sub _init {
    $_[0]->reset_trn();
    $_[0];
}

1;
__END__

=head1 NAME

Net::UCP - Perl extension for EMI - UCP Protocol.

=head1 SYNOPSIS

    use Net::UCP;

    $emi = Net::UCP->new(
	         	 SMSC_HOST   => 'smsc.somedomain.tld', 
		         SMSC_PORT   => 3024, 
		         SENDER_TEXT => 'My Self 123', 
		         SRC_HOST=   => 'my.host.tld', 
		         SRC_PORT    => '1666'
			 );

=head1 DESCRIPTION

This module implements a B<Client> Interface to the B<EMI - UCP Interface> specification,
This Protocol can be used to comunicate with an SMSC (Short Message Service Centre)

Usually the Network connection is based on TCP/IP or X.25.

The EMI/UCP specification can be found online. :) 

This Class can be used to send an SMS message to an SMSC. (Text messages and Binary Messages)

You will of course be required to have a valid login at the SMSC to use their services.
(Unless there is an SMSC which provides their services for free.
Please, let me know about any such service provider. :-)

A Net::UCP object must be created with the new() constructor.
Once this has been done, all commands are accessed via method calls on the object.

=head1 EXAMPLE

    use Net::UCP;
    
    ($recipient,$text,$sender) = @ARGV;
     
    my ($acknowledge,$error_number,$error_text);

    $emi = Net::UCP->new(SMSC_HOST   => 'smsc.somedomain.tld',
			 SMSC_PORT   => 3024,
			 SENDER_TEXT => 'MyApp',
			 SRC_HOST    => '10.10.10.21', #optional see below
			 SRC_PORT    => '1666',        #optional see below
			 WARN        => 1
			 ) or die("Failed to create SMSC object");
    
    $emi->open_link() or die("Failed to connect to SMSC");

    ($acknowledge,$error_number,$error_text) = $emi->login(
							   SMSC_ID    => 'your_account_id',
							   SMSC_PW    => 'your password',
							   SHORT_CODE => 'your Auth Code',
							   OTON       => '5',        #optional
							   ONPI       => '1',        #optional 
							   VERS       => '0100',     #optional
							   );
    
    die ("Login to SMSC failed. Error nbr: $error_number, Error txt: $error_text\n") unless($acknowledge);
    
    ($acknowledge,$error_number,$error_text) = $emi->send_sms(
							      RECIPIENT      => $recipient, #mand.
							      MESSAGE_TEXT   => $text,      #opt
							      SENDER_TEXT    => $sender,    #opt
							      UDH            => $udh,       #opt
							      FLASH          => $flash,     #opt 
							      MESSAGE_BINARY => $b_mess,    #opt
							      );
    
    die("Sending SMS failed. Error nbr: $error_number, Error txt: $error_text\n") unless($acknowledge);
    
    $emi->close_link();

=head1 CONSTRUCTOR

=over 4

=item new() 


The parameters may be given in arbitrary order.

C<SMSC_HOST=E<gt>> B<Mandatory>. The hostname B<or> ip-address of the SMSC.

C<SMSC_PORT=E<gt>> Optional. The TCP/IP port number of your SMSC. If omitted, port number 3024 will be used by default.

C<SMSC_HOST=E<gt>> Optional. Your ip appdress.

C<SRC_PORT=E<gt>> Optional. The TCP/IP source port number. You need to set it if you want to use auth. method based on AC.

C<SENDER_TEXT=E<gt>> Optional. The text that will appear in the receivers mobile phone, identifying you as a sender.
If omitted, the text 'Net::UCP' will be used by default.
You will probably want to provide a more meaningful text than that.

C<TIMEOUT=E<gt>> Optional.
A timeout, given in seconds, to wait for an acknowledgement of an SMS message transmission.
The value must be numeric, positive and within the range of B<0> (zero) to B<60>.
Failing this, or if the parameter is omitted, the default timeout of 15 seconds will be applied.
The value of this parameter will be used in all calls to the send_sms() method.
If the SMSC does not respond with an ACK or a NACK during this period,
the send_sms() method will return a NACK to the caller.
If the value of B<0> (zero) is given, no timeout will occur but the send_sms() method will wait B<indefinitively> for
a response. Note that the value given to the constructor can temporarily be overruled
in the call to the send_sms() method. As a final note, please remember that not all systems have implemented 
the C<alarm()> call, which is used to create a timeout.
On such systems, this module will still do a blocking call when reading data from the SMSC.

C<WARN=E<gt>> Optional. If this parameter is given and if it evaluates to I<true>,
then any warnings and errors will be written to C<STDERR>.
If omitted, or if the parameter evaluates to I<false>, then nothing is written to C<STDERR>.
It is B<strongly> recommended to turn on warnings during the development of an application using the Net::UCP 
module. When development is finished, the developer may chose to not require warnings but to handle all error 
situations completely in the main application by checking the return values from Net::UCP.

The constructor returns I<undef> if mandatory information is missing or invalid parameter values are detected.
In this case, the object is discarded (out of scope) by the Perl interpreter and you cannot call any methods 
on the object handle.

Any errors detected will be printed on C<STDERR> if the C<WARN=E<gt>> parameter evaluates to I<true>.

B<Test> the return value from the constructor!

=back

=head1 METHODS

=over 4

=item open_link()

Open the communication link to the SMSC.
In reality, this opens up a socket to the SMSC.
Be aware that this is B<not> an authenticated login but that the login() method must also be called 
before any SMS messagescan be sent to the SMSC if you will use an Authentication based on Login and Password.

open_link() is useful since the main application can verify that it's at all possible to communicate with the SMSC.
(Think: getting through a firewall.)

This method takes no parameters since it will use the data given in the constructor parameters.

Any errors detected will be printed on C<STDERR> if the C<WARN=E<gt>> parameter in the constructor evaluates to I<true>.

C<open_link()> returns B<true> on success and B<undef> in case something went wrong.

=item login()

You are able to use authentication based on Operation 60 of EMI Protocol.
Authenticates against the SMSC with the given SMSC-id and password.

B<or>

Directly through Operation 51.
Authenticates against the SMSC with the given SHORT_CODE (AC parameter).

If the open_link() method has not explicitly been called by the main application,
the login() method will do it before trying to authenticate with the SMSC.

The parameters may be given in arbitrary order.

C<SHORT_CODE=E<gt>> A valid Authentication Code Mandatory for Auth based on OP 51.

C<SMSC_ID=E<gt>> A string which should be a valid account ID at the SMSC.

C<SMSC_PW=E<gt>> A valid password at the SMSC.

Optional Parameters (Beta):

C<OTON=E<gt>> Originator Type of Number

it could be :
 
              1 = International Number (Starts with the country code) 
              2 = National Number (Default value is omitted)
              6 = Abbreviated Number (short number alias)              
              
C<ONPI=E<gt>> Originator Numbering Plan Id

it could be :

              1 = E.164 address (default value if omitted)
              3 = X.121 address
              5 = Private (TCP/IP address/abbreviated number address)

C<STYP=E<gt>> Subtype of Operation
     
              1 = add item to mo-list
              2 = rmeove item from mo-list
              3 = verify item mo-list
              4 = add item to mt-list
              5 = remove item from mt-list
              6 = verify item mt-list


C<VERS=E<gt>> (...Test...) default value is 0100

Any errors detected will be printed on C<STDERR> if the C<WARN=E<gt>> parameter in the constructor evaluates to I<true>.

B<Return values:>

In void context, login() will always return undef.
login() will return a I<true> value if you will use it only to set Authentication Code.

In scalar context, login() will return I<true> for success, I<false> for transmission failure
and I<undef> for application related errors.
Application related errors may be for instance that a mandatory parameter is missing.
All such errors will be printed on C<STDERR> if the C<WARN=E<gt>> parameter in the constructor evaluates to I<true>.

In array context, login() will return three values: C<($acknowledge, $error_number, $error_text);>
where C<$acknowledge> holds the same value as when the method is called in scalar context
(i.e. I<true>, I<false> or I<undef>),
C<$error_number> contains a numerical error code from the SMSC and
C<$error_text> contains a (relatively) explanatory text about the error.

Be aware that both C<$error_number> and C<$error_text> are provided in a response from the SMSC,
which means that the data quality of these entities depends on how well the SMSC has implemented the protocol.

If C<$acknowledge> is I<undef>, then C<$error_number> will be set to 0 (zero) and C<$error_text> will
contain a zero length string.

It is B<strongly recommended to call login() in an array context>, since this provides for an improved error handling
in the main application.

=item send_sms()

=item EXAMPLE 

    $binary_message  = "024A3A7125CD7DD1A1A5CD7DB1BDD994040045225D04985585D85D84106906985D84984A85585D85D84104D";
    $binary_message .= "04104D85D0690410A24824C49A6289B09D093126986A800";

    $emi->send_sms(
		   RECIPIENT      =>'391232345678', 
		   MESSAGE_TEXT   => 'A Message', 
		   SENDER_TEXT    => 'Marco', 
		   FLASH          => 1,
		   UDH            => '050415811581',
		   MESSAGE_BYNARY => $binary_message,
		   TIMEOUT        => 5 
		   );

Submits the SMS message to the SMSC (Operation 51) and waits for an SMSC acknowledge.

The parameters may be given in arbitrary order.

C<RECIPIENT=E<gt>> B<Mandatory>.

This is the phone number of the recipient in international format with leading a '+' or '00'.

C<MESSAGE_TEXT=E<gt>> Optional. A text message to be transmitted.

It is accepted to transfer an empty message,
so if this parameter is missing, a space character will be sent (0x20).

C<FLASH=E<gt>> Optional. With this parameter you are able to send a Class 0 messages.

    
              1) Set to 1 Flash Message enabled     (Class 0)
              2) Other value Flash Message disabled (No Class)


C<MESSAGE_BINARY=E<gt>> Optional. A binary message to be transmitted.

C<UDH=E<gt>> Optional. User Data Header (you need to set UDH to use MESSAGE_BINARY).

First UDH Octet (length) will be internally calculated for this reason you need to omitted it.

C<SENDER_TEXT=E<gt>> Optional. The text that will appear in the receivers mobile phone, identifying you as a sender.

    In this version you are able to set:

              1) alphanumeric sender  ( Marco81        )
              2) numeric sender       ( 67166155111    )
              3) international format ( +3934112331112 ) 


This text will B<temporarily> replace the text given to the constructor.
If omitted, the text already given to the constructor will be used.

C<TIMEOUT=E<gt>> Optional.

A timeout, given in seconds, to wait for an acknowledgement of this SMS message transmission.
The value must be numeric, positive and within the range of B<0> (zero) to B<60>.
Failing this, or if the parameter is omitted,
the timeout established in the new() constructor will be applied.
If the SMSC does not respond with an ACK or a NACK during this period,
the send_sms() method will return a NACK to the caller.
If the value of B<0> (zero) is given, no timeout will occur but the send_sms() method will wait B<indefinitively> 
for a response. On a system that has not implemented the C<alarm()> call,
which is used to create a timeout,
this module will still do a blocking call when reading data from the SMSC.

Any errors detected will be printed on C<STDERR> if the C<WARN=E<gt>> parameter in the constructor evaluates to I<true>.

B<Return values:>

In void context, send_sms() will always return undef.

In scalar context, send_sms() will return I<true> for success, I<false> for transmission failure
and I<undef> for application related errors.
Application related errors may be for instance that a mandatory parameter is missing.
All such errors will be printed on C<STDERR> if the C<WARN=E<gt>> parameter in the constructor evaluates to I<true>.

In array context, send_sms() will return the three values: C<($acknowledge, $error_number, $error_text);>
where C<$acknowledge> holds the same value as when the method is called in scalar context
(i.e. I<true>, I<false> or I<undef>),
C<$error_number> contains a numerical error code from the SMSC and
C<$error_text> contains a (relatively) explanatory text about the error.

Be aware that both C<$error_number> and C<$error_text> are provided in a response from the SMSC,
which means that the data quality of these entities depends on how well the SMSC has implemented the protocol.

If C<$acknowledge> is I<undef>, then C<$error_number> will be set to 0 (zero) and C<$error_text> will
contain a zero length string.

It is B<strongly recommended to call send_sms() in array context>,
since this provides for an improved error handling in the main application.

B<Note!>
The fact that the message was successfully transmitted to the SMSC does B<not>
guarantee immediate delivery to the recipient or in fact any delivery at all.

B<About the timeout.>
Not all Perl systems are able to provide the timeout.
The timeout is internally implemented with the alarm() call.
If your system has implemented alarm(), then any timeout value provided will be honored.
If not, you may provide any value you wish for the timeout,
it will still be ignored and reading the ACK from the SMSC will block until everything is read.

If the SMSC fails to send you the full response B<your application will freeze>.
If your system B<does> implement alarm() but you do B<not> provide any timeout value,
then the default timeout of 15 seconds will be applied.

You may test this on your own system by executing the following on a command line:

C<perl -e "alarm(0)">

If the response is that alarm() is not implemented, then you're out of luck.
You can still use the module, but in case the SMSC doesn't respond as expected
your application will wait B<indefinitively>.


=item logout()

=item close_link()

logout() is an alias for close_link().
Whichever method name is used, the B<very same code> will be executed.

What goes up, must also come down.
If the main application will continue working on other tasks once the SMS message was sent,
it is possible to explicitly close the communications link to the SMSC with this method.

If the Net::UCP object handle (returned by the new() method) goes out of scope in the main application,
the link will be implicitly closed and in this case it is not necessary to explicitly close the link.

In reality, this method closes the socket established with the SMSC and does some additional house-keeping.
Once the link is closed,
a new call to either open_link() or to login() will try to re-establish the communications link (socket) with the SMSC.

returns nothing (void)

=item read_mo() 

it needs two parameters :

first parameter is timeout in second. It could be 0 or < 0 if you don't want to set timeout.
second parameter is mandatory and it's the path where read_mo() method will store dump of MO messages.
  
With read_mo() method you are able to get back MO messages and store it in a text file.

=item EXAMPLE

    $emi->read_mo(
		  '50',
		  '/path/dump.txt',
		  );


without timeout


    $emi->read_mo(
                  '0',
                  '/NEW/path/dump.txt',
                  );


  
=back

=head1 SEE ALSO

C<IO::Socket>, 

=head1 AUTHOR

Marco Romano, E<lt>nemux@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Marco Romano

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut

sub AUTOLOAD {
    my($method,$class);

    $method = $AUTOLOAD;
    $method =~ s/.*:://;
    $class = ref($_[0]) || $_[0];

    croak "$class Method=$method, object=$object";
}
