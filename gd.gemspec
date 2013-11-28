# Ensure we require the local version and not one we might have installed already
$: << File.expand_path("../lib", __FILE__)
# $: << File.expand_path(File.dirname(File.realpath(__FILE__)) + '/../lib')
require "gd_version"

spec = Gem::Specification.new do |s| 
  s.name = 'gd'
  s.version = Gd::VERSION
  s.author = 'Tomas Svarovsky'
  s.email = 'svarovsky+tomas@gooddata.com'
  s.homepage = 'http://svarovsky-tomas.com/'
  s.platform = Gem::Platform::RUBY
  s.summary = 'Suite of command line helpers to do the common tasks with gooddata an addition to GoodData gem. Should supersede its command line capabilities'
  s.description = 'CLI interface to GoodData API'
  s.files = %w(
bin/gd
lib/gd_version.rb
lib/gd.rb
lib/mailer.rb
  )
  s.require_paths << 'lib'
  s.has_rdoc = true
  s.extra_rdoc_files = ['README.rdoc','gd.rdoc']
  s.rdoc_options << '--title' << 'gd' << '--main' << 'README.rdoc' << '-ri'
  s.bindir = 'bin'
  s.executables << 'gd'
  s.add_development_dependency('rdoc')
  s.add_dependency('rake')
  s.add_dependency('gooddata')
  s.add_dependency('rainbow')
  s.add_dependency('gli')
  s.add_dependency('highline')
  s.add_dependency('activesupport', '~> 3.0.0')
  s.add_dependency('i18n')
  s.add_dependency('salesforce')
  s.add_dependency('pony')
end
