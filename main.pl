#!/usr/bin/perl

use strict;
use warnings;
use LWP;
use HTTP::Request::Common qw{ POST };
use HTML::Form;
use Data::Dumper;
use HTTP::Cookies;
use HTML::LinkExtor;
use URI::URL;

sub get_ua
{
    my $ua = new LWP::UserAgent(timeout => 10,
                                max_redirect => 5,
                                requests_redirectable => ['GET', 'HEAD', 'POST']
        );
    my $cookie_jar = HTTP::Cookies->new( file => undef, autosave => 0 );
    $ua->cookie_jar($cookie_jar);
    return $ua;
}


sub debug
{
    my $green = "\e[1;32m";
    my $reset = "\e[0m";
    warn "$green$_[0]$reset \n";
}

sub error
{
    my $red = "\e[1;31m";
    my $reset = "\e[0m";
    warn "$red$_[0]$reset \n";
}

sub is_html($)
{
    return ($_[0] =~ /html/)? 1 : 0;
}

sub compare($$$$$)
{
    my ($normal, $pervert, $val, $name, $action) = @_;
    error("For $name $action value=$val HTTP response code is changed") if ($normal->code != $pervert->code);
    my $normal_content = $normal->decoded_content();
    my $pervert_content = $pervert->decoded_content();
    error("For $name $action value=$val different content size") if (abs(length($normal_content) - length($pervert_content)) > 10);
}

sub get_check($$$)
{
    my ($params_arg, $name, $action) = @_;
    my $uri = URI->new($action);
    $uri->query_form(%$params_arg);
    my $normal = download($uri->as_string());
    my %params = %$params_arg;
    foreach my $val ("'", '"', '`')
    {
        $params{$name} = $val;
        $uri->query_form(%params);
        my $pervert = download($uri->as_string());
        compare($normal, $pervert, $val, $name, $action);
    }
}

sub post_check($$$)
{
    my ($params_arg, $name, $action) = @_;
    my $request = POST( $action, [ %$params_arg ] );
    my $normal = get_ua()->request($request);
    my %params = %$params_arg;
    foreach my $val ("'", '"', '`')
    {
        $params{$name} = $val;
        my $request = POST( $action, [ %params ] );
        my $pervert = get_ua()->request($request);
        compare($normal, $pervert, $val, $name, $action);
    }
}

sub check_parameter($$$$)
{
    my ($action, $method, $params, $name) = @_;
    debug("Check parameter $action $method $name");
    if ($method eq 'GET')
    {
        get_check($params, $name, $action);
    }
    elsif ($method eq 'POST')
    {
        post_check($params, $name, $action);
    }
    else
    {
        debug("Unknown method $method for action: $action");
    }
}

sub extract_links($$)
{
    my ($html_content, $base_url) = @_;
    my @links;

    # Callback to collect href attributes from <a> tags
    my $callback = sub
    {
        my ($tag, %attr) = @_;
        push @links, $attr{href} if $tag eq 'a' && exists $attr{href};
    };

    # Parse HTML content
    my $parser = HTML::LinkExtor->new($callback);
    $parser->parse($html_content);

    # Convert relative URLs to absolute if base_url provided
    @links = map { url($_, $base_url)->abs } @links;
    
    return @links;
}

sub parse($$$$$)
{
    my ($base_url, $content, $charset, $domain, $visited_links) = @_;
    foreach my $form (HTML::Form->parse($content, base=>$base_url, charset=>$charset))
    {
        my %params;
        foreach my $input ($form->inputs)
        {
            next if ($input->type eq 'submit');
            next if (!defined($input->name) or length($input->name) == 0);
            my $value = $input->value || 'value';
            $params{$input->name} = $value;
            check_parameter($form->action, $form->method, \%params, $input->name);
        }
    }
    my @urls = extract_links($content, $base_url);
    foreach my $url (@urls)
    {
        next if (get_domain($url) ne $domain);
        $url =~ s/#[^#]+$//;
        next if exists($visited_links->{$url});
        $visited_links->{$url} = 1;
        check($url, $domain, $visited_links);
    }
}

sub get_domain($)
{
    my $url = $_[0];
    my ($domain) = $url =~ m!^https?://([^/]+)!;
    die "Wrong url: $url" if (length($domain) == 0);
    return $domain;
}

sub check($$$)
{
    my ($url, $domain, $visited_links) = @_;
    debug("Download $url");
    my $r = download($url);
    if (!$r->is_success)
    {
        debug("Download $url error");
        return;
    }
    if (!is_html($r->content_type))
    {
        debug("$url is not html: ".$r->content_type);
        return;
    }
    parse($url, $r->decoded_content, $r->content_charset, $domain, $visited_links);
}

sub download($)
{
    my $url = $_[0];
    my $req = HTTP::Request->new('GET');
    $req->url($url);
    return get_ua()->request($req);
}

die "$0 <url>" if @ARGV != 1;
my %visited_links = ($ARGV[0] => 1);
my $domain = get_domain($ARGV[0]);
check($ARGV[0], $domain, \%visited_links);
