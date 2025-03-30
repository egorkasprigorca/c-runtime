project('c-runtime', 'c',
        version : '1.0.0',
        default_options : ['warning_level=0', 'c_std=gnu99'])

sources = files('src/main.c')
c_runtime = executable('c_runtime', sources, install : true)

test('test', c_runtime)