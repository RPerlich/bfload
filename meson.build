project('bfload', 'c',
    version : '0.6.0',
    license : ['GNU General Public License'],
    meson_version : '>= 0.50.0',
    default_options : [ 'warning_level=3', 'buildtype=debugoptimized', 'prefix=/usr']
)

ssldep = dependency('openssl', version : '>= 0.9.8')
xmldep = dependency('libxml-2.0', version : '>=2.9.10')
curldep = dependency('libcurl', version : '>=7.74.0')

subdir('src')

bfload_bin = executable('bfload', 
  main_source, 
  install:true, 
  dependencies : [ssldep, xmldep, curldep])

