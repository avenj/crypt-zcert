requires "perl"           => "5.010";
requires "strictures"     => "1";

requires "List::Objects::WithUtils" => "2";
requires "Try::Tiny"      => "0";

requires "Moo"            => "1";
requires "MooX::late"     => "0.014"

requires "Convert::Z85"   => "0";
requires "Text::ZPL"      => "0";

requires "FFI::Raw"       => "0";

requires "List::Objects::Types" => "1";
requires "Types::Path::Tiny"    => "0";
requires "Types::Standard"      => "0";

on 'configure' => sub {};
on 'build'     => sub {};
on 'test'      => sub {};
on 'runtime'   => sub {};
on 'develop'   => sub {};
