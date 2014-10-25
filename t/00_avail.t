use Test::More;
use strict; use warnings FATAL => 'all';

use Crypt::ZCert;

my $soname;
eval {; $soname = Crypt::ZCert->new->zmq_soname };
if (my $err = $@) {
  if ($err =~ /search.path|requires.ZeroMQ/) {
    BAIL_OUT "OS unsupported - $err"
  } else {
    die $@
  }
}

ok $soname, "Testing against libzmq: '$soname'";

done_testing
