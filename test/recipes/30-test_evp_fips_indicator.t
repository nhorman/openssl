#! /usr/bin/env perl
# Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test::Simple;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir bldtop_dir bldtop_file data_dir/;
use OpenSSL::Test::Utils;
use Cwd qw(abs_path);

BEGIN {
setup("test_evp_fips_indicator");
}

my $no_fips = disabled('fips');
my $config_path = abs_path(srctop_file("test", $no_fips ? "default.cnf"
                                                        : "default-and-fips.cnf"));

plan tests => 1;

ok(run(test(["evp_fipsind_test", "-config", $config_path])),
             "running evp fips indicator presence test");
