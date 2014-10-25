use Test::More;
use strict; use warnings FATAL => 'all';

use Crypt::ZCert;

use Path::Tiny;

use Convert::Z85;
use Text::ZPL;

{ # generate_keypair
  my $keypair = Crypt::ZCert->new->generate_keypair;
  ok $keypair->public && $keypair->secret, 'keypair ok';
}

{ # export_zcert
  my $zcert = Crypt::ZCert->new->export_zcert;
  my $pub_data = decode_zpl $zcert->public;
  my $sec_data = decode_zpl $zcert->secret;
  ok $pub_data->{curve}->{'public-key'}, 'export_zcert public-key ok';
  ok !$pub_data->{curve}->{'secret-key'},
    'export_zcert no secret-key in public ok';
  ok $sec_data->{curve}->{'public-key'} eq $pub_data->{curve}->{'public-key'},
    'export_zcert public-key in secret ok';
  ok $sec_data->{curve}->{'secret-key'}, 'export_zcert secret-key ok';
  ok ref $sec_data->{metadata} eq 'HASH'
    && ref $pub_data->{metadata} eq 'HASH', 'export_zcert metadata ok';
}

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

  cmp_ok $zcert->metadata->get('foo'), 'eq', 'bar', 'metadata ok';
  ok $zcert->metadata->keys->count == 1, '1 key in metadata ok';
}

=pod

=begin comment

FIXME

{ # public_file + secret_file, extant
}

{ # public_file, nonextant
}

{ # public_file + secret_file, neither extant
}

{ # public_file + secret_file, secret_file extant, missing public
}

{ # public_file + secret_file, public_file extant, missing secret
}

{ # no public_file or secret_file (commit dies)
}

{ # only secret file specified
}

=cut

{ # munging metadata
  my $tempdir = Path::Tiny->tempdir(CLEANUP => 1);
  my $zcert = Crypt::ZCert->new(
    public_file => $tempdir ."/zcert",
    metadata    => +{
      foo   => 'baz',
      bar   => 'weeble',
    },
  );
  $zcert->commit;
  # on-disk should override:
  $zcert = Crypt::ZCert->new(
    public_file => $tempdir ."/zcert",
    metadata    => +{
      bar  => 'baz',
      quux => 'fwee',
    },
  );
  is_deeply
    +{ $zcert->metadata->export },
    +{
      foo  => 'baz',
      bar  => 'weeble',
      quux => 'fwee',
    },
    'on-disk metadata overrides object values ok';

  $zcert->metadata->set(bar => 'quux');
  $zcert->commit;
  $zcert = Crypt::ZCert->new(
    public_file => $tempdir ."/zcert",
  );
  is_deeply
    +{ $zcert->metadata->export },
    +{
      foo  => 'baz',
      bar  => 'quux',
      quux => 'fwee',
    },
    'roundtripped metadata changes ok';
}


done_testing
