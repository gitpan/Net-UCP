use 5.006;
use ExtUtils::MakeMaker;

WriteMakefile(
	      NAME              => 'Net::UCP',
	      VERSION_FROM      => 'lib/Net/UCP.pm', 
	      PREREQ_PM         => { 
		  IO::Socket => 0 
		  }, 
	      ($] >= 5.005 ?     
	       (ABSTRACT_FROM  => 'lib/Net/UCP.pm', 
		AUTHOR         => 'Marco Romano <nemux@cpan.org>') : ()),
	      );
