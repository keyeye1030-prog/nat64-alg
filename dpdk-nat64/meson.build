project('dpdk-nat64', 'c', version: '0.1.0', default_options: ['c_std=c11', 'warning_level=2'])

dpdk = dependency('libdpdk', version: ['>=23.11.0', '<24.0.0'], static: true, required: true)
threads = dependency('threads')

src = files(
  'src/compat.c',
  'src/acl.c',
  'src/capture.c',
  'src/config.c',
  'src/jsmn.c',
  'src/main.c',
  'src/monitor.c',
  'src/nat64.c',
  'src/route.c',
)

executable(
  'dpdk-nat64',
  src,
  dependencies: [dpdk, threads],
  include_directories: include_directories('src'),
  install: true,
)
