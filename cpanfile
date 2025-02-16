# This file is generated by Dist::Zilla::Plugin::CPANFile v6.032
# Do not edit this file directly. To change prereqs, edit the `dist.ini` file.

requires "Alt::Crypt::RSA::BigInt" => "0";
requires "Bytes::Random::Secure" => "0";
requires "Compress::Zlib" => "0";
requires "Crypt::Blowfish" => "0";
requires "Crypt::CAST5_PP" => "0";
requires "Crypt::DES_EDE3" => "0";
requires "Crypt::DSA" => "1.17";
requires "Crypt::IDEA" => "0";
requires "Crypt::RIPEMD160" => "0.05";
requires "Crypt::Rijndael" => "0";
requires "Crypt::Twofish" => "0";
requires "Data::Buffer" => "0.04";
requires "Digest::MD5" => "0";
requires "Digest::SHA" => "0";
requires "Exporter" => "5.57";
requires "File::HomeDir" => "0";
requires "LWP::UserAgent" => "0";
requires "MIME::Base64" => "0";
requires "Math::BigInt" => "0";
requires "URI::Escape" => "0";
requires "parent" => "0";
requires "perl" => "v5.8.1";

on 'test' => sub {
  requires "Test::Exception" => "0";
  requires "Test::More" => "0";
};

on 'configure' => sub {
  requires "ExtUtils::MakeMaker" => "0";
};
