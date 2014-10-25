use Test::More;
use strict; use warnings FATAL => 'all';

use Crypt::ZCert;

use Path::Tiny;

use Convert::Z85;
use Text::ZPL;

{ # public_file, extant
  my $zpl  = path('t/inc/zcert_secret')->slurp;
  my $data = decode_zpl $zpl;
  my $zcert = Crypt::ZCert->new(
    public_file => 't/inc/zcert'
  );

  cmp_ok $zcert->public_key_z85, 'eq', $data->{curve}->{'public-key'},
    'public_key_z85 from loaded cert ok';
  cmp_ok $zcert->secret_key_z85, 'eq', $data->{curve}->{'secret-key'},
    'secret_key_z85 from loaded cert ok';

  cmp_ok $zcert->public_key, 'eq', decode_z85($zcert->public_key_z85),
    'public_key from loaded cert ok';
  cmp_ok $zcert->secret_key, 'eq', decode_z85($zcert->secret_key_z85),
    'secret_key from loaded cert ok';
}

{ # public_file + secret_file, extant
}

{ # public_file, nonextant
}

{ # public_file + secret_file, neither extant
  # FIXME tempfiles, do cleanup
}

{ # public_file + secret_file, secret_file extant, missing public
}

{ # public_file + secret_file, public_file extant, missing secret
}

{ # no public_file or secret_file (commit dies)
}

{ # only secret file specified
}


done_testing
